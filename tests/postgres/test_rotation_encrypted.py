"""
End-to-end API-key rotation against real PostgreSQL with field encryption ON —
the deployment shape the hosted service runs (schema=auth_rbac, encryption=true).

Run via `make test-postgres` (disposable Docker Postgres, separate process).

This is the load-bearing test for rotation's re-encryption: it drives the real
`POST /api/keys/rotate` HTTP route and then checks access **through the API**
under the new key. Because user and permission names are stored encrypted and
bound to the creator (HKDF), `has_permission` under the new key can only return
true if the cells were actually decrypted under the old key and re-encrypted
under the new one inside rotation.
"""

import os
import uuid

import pytest

pytestmark = pytest.mark.postgres

if os.environ.get("AUTH_DATABASE_TYPE") != "postgresql":
    pytest.skip(
        "AUTH_DATABASE_TYPE != postgresql — run via 'make test-postgres'",
        allow_module_level=True,
    )

from sqlalchemy import text  # noqa: E402

from auth.database import create_tables, engine  # noqa: E402
from auth.main import create_app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def test_rotation_reencrypts_and_moves_namespace_over_https_path(client):
    assert os.environ.get("AUTH_ENABLE_ENCRYPTION") == "true"

    old = str(uuid.uuid4())
    user = "alice@example.com"  # exercises the encrypted user column
    assert client.post("/api/role/engineers", headers=_h(old)).get_json()["result"]
    assert client.post(
        "/api/permission/engineers/deploy", headers=_h(old)
    ).get_json()["result"]
    assert client.post(
        f"/api/membership/{user}/engineers", headers=_h(old)
    ).get_json()["result"]

    assert (
        client.get(f"/api/has_permission/{user}/deploy", headers=_h(old))
        .get_json()["data"]["has_permission"]
        is True
    )

    # Rotate.
    resp = client.post("/api/keys/rotate", headers=_h(old))
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    new = data["new_key"]
    assert new != old
    assert data["migrated"] == {
        "roles": 1,
        "memberships": 1,
        "permissions": 1,
        "api_keys": 0,
        "settings": 0,
    }

    # New key: full access preserved — only possible if the encrypted user and
    # permission cells were re-keyed under `new`.
    assert (
        client.get(f"/api/has_permission/{user}/deploy", headers=_h(new))
        .get_json()["data"]["has_permission"]
        is True
    )
    assert [
        r["role"] for r in client.get("/api/roles", headers=_h(new)).get_json()["result"]
    ] == ["engineers"]

    # Old key: empty namespace.
    assert client.get("/api/roles", headers=_h(old)).get_json()["result"] == []
    assert (
        client.get(f"/api/has_permission/{user}/deploy", headers=_h(old))
        .get_json()["data"]["has_permission"]
        is False
    )

    # Forensic (read-only) confirmation that no rows were left behind under the
    # old creator across all three tables.
    schema = os.environ["AUTH_DATABASE_SCHEMA"]
    with engine.connect() as conn:
        for table in ("auth_group", "auth_membership", "auth_permission"):
            leftover = conn.execute(
                text(
                    f'SELECT count(*) FROM "{schema}".{table} '  # noqa: S608
                    "WHERE creator = :old"
                ),
                {"old": old},
            ).scalar()
            assert leftover == 0, f"{table} still has rows under the old key"
