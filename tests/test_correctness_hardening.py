"""
Correctness hardening from the production audit.

C1 — a client key is a case-insensitive UUID4, but it is used verbatim as the
tenant identifier and the encryption KDF input; case variants must resolve to the
SAME namespace, not fork into disjoint ones.

C2 — a genuine database failure must not be masked as a legitimate
``{"result": false}``; it must surface (500 / raised) so callers can retry and
the audit records a failure. A missing-role False stays a False.
"""

import uuid
from unittest.mock import patch

import pytest

from auth.database import SessionLocal
from auth.main import create_app
from auth.services.service import AuthorizationService


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# --- C1: case-variant keys are one namespace -------------------------------


def test_case_variant_keys_resolve_to_the_same_namespace(client):
    key = str(uuid.uuid4())  # canonical lowercase
    upper = key.upper()
    assert key != upper

    assert client.post(
        "/api/role/engineers", headers={"Authorization": f"Bearer {key}"}
    ).get_json()["result"] is True

    # The uppercase form of the SAME uuid must see the same data, not a fresh
    # empty namespace.
    roles = client.get(
        "/api/roles", headers={"Authorization": f"Bearer {upper}"}
    ).get_json()["result"]
    assert [r["role"] for r in roles] == ["engineers"]

    # And a permission check written under one case answers under the other.
    client.post(
        "/api/permission/engineers/deploy", headers={"Authorization": f"Bearer {upper}"}
    )
    client.post(
        "/api/membership/alice/engineers", headers={"Authorization": f"Bearer {key}"}
    )
    ans = client.get(
        "/api/has_permission/alice/deploy", headers={"Authorization": f"Bearer {upper}"}
    ).get_json()
    assert ans["data"]["has_permission"] is True


# --- C2: DB errors are not masked; missing-role is still False -------------


def test_db_error_is_not_masked_as_false():
    key = str(uuid.uuid4())
    db = SessionLocal()
    try:
        svc = AuthorizationService(db, key)
        with patch.object(db, "execute", side_effect=RuntimeError("db down")):
            with pytest.raises(RuntimeError):
                svc.add_role("engineers")  # a DB failure must propagate, not be False
    finally:
        db.rollback()
        db.close()


def test_missing_role_write_still_returns_false(client):
    key = str(uuid.uuid4())
    # Adding a membership/permission to a role that does not exist is a
    # legitimate False (200), NOT an error — this must be preserved.
    h = {"Authorization": f"Bearer {key}"}
    assert client.post("/api/membership/alice/ghosts", headers=h).get_json() == {
        "result": False
    }
    assert client.post("/api/permission/ghosts/deploy", headers=h).get_json() == {
        "result": False
    }


def test_deleting_a_role_purges_grants_over_the_api(client):
    """Revoke-by-delete must be durable at the HTTP layer: re-creating a role
    with the same name must not restore former members/permissions."""
    key = str(uuid.uuid4())
    h = {"Authorization": f"Bearer {key}"}

    client.post("/api/role/engineers", headers=h)
    client.post("/api/permission/engineers/deploy", headers=h)
    client.post("/api/membership/alice/engineers", headers=h)
    assert (
        client.get("/api/has_permission/alice/deploy", headers=h).get_json()["data"][
            "has_permission"
        ]
        is True
    )

    assert client.delete("/api/role/engineers", headers=h).status_code == 200

    # re-create the same role name (e.g. a different team reusing it)
    client.post("/api/role/engineers", headers=h)

    assert (
        client.get("/api/has_permission/alice/deploy", headers=h).get_json()["data"][
            "has_permission"
        ]
        is False
    ), "former member regained access after the role name was reused"
    assert client.get("/api/members/engineers", headers=h).get_json()["result"] == []
    assert client.get("/api/role_permissions/engineers", headers=h).get_json()["data"] == []


def test_db_error_surfaces_as_500_through_the_api(client):
    key = str(uuid.uuid4())
    with patch(
        "auth.services.service.AuthorizationService.add_role",
        side_effect=RuntimeError("db down"),
    ):
        resp = client.post(
            "/api/role/engineers", headers={"Authorization": f"Bearer {key}"}
        )
    assert resp.status_code == 500
    # generic, safe body — no stack trace / SQL
    assert "Traceback" not in resp.get_data(as_text=True)
