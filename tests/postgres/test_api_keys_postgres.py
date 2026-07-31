"""PostgreSQL end-to-end tests for the per-user API-key lifecycle (SPEC 0004).

Runs in the production shape (schema=auth_rbac, deterministic encryption ON,
advisory locks live) via `make test-postgres`. Exercises the full HTTP
lifecycle and the rotation-preserves-keys guarantee against the real dialect.
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

from auth.database import create_tables  # noqa: E402
from auth.main import create_app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def test_full_lifecycle_on_postgres(client):
    tenant = str(uuid.uuid4())
    created = client.post(
        "/api/apikeys/user/alice@example.com",
        headers=_h(tenant),
        json={"label": "pg key"},
    ).get_json()["data"]
    secret, key_id = created["api_key"], created["key_id"]
    assert secret.startswith("rak_")

    # Green first.
    valid = client.post(
        "/api/apikeys/validate", headers=_h(tenant), json={"api_key": secret}
    ).get_json()["data"]
    assert valid["valid"] is True
    assert valid["user"] == "alice@example.com"
    assert valid["label"] == "pg key"

    listing = client.get(
        "/api/apikeys/user/alice@example.com", headers=_h(tenant)
    ).get_json()["data"]
    assert listing["count"] == 1
    assert listing["keys"][0]["label"] == "pg key"

    # Cross-tenant red while the owner stays green.
    stranger = str(uuid.uuid4())
    assert client.post(
        "/api/apikeys/validate", headers=_h(stranger), json={"api_key": secret}
    ).get_json()["data"] == {"valid": False, "reason": "unknown_key"}

    # Revoke -> red, idempotent repeat.
    assert client.delete(
        f"/api/apikeys/user/alice@example.com/{key_id}", headers=_h(tenant)
    ).get_json()["data"] == {"revoked": True, "already_revoked": False}
    assert client.post(
        "/api/apikeys/validate", headers=_h(tenant), json={"api_key": secret}
    ).get_json()["data"] == {"valid": False, "reason": "revoked"}
    assert client.delete(
        f"/api/apikeys/user/alice@example.com/{key_id}", headers=_h(tenant)
    ).get_json()["data"] == {"revoked": True, "already_revoked": True}


def test_strict_mode_flow_on_postgres(client):
    tenant = str(uuid.uuid4())
    h = _h(tenant)
    client.post("/api/role/ops", headers=h)
    client.post("/api/permission/ops/deploy", headers=h)
    client.post("/api/membership/dana/ops", headers=h)

    # Green baseline before the red means anything.
    assert (
        client.get("/api/has_permission/dana/deploy", headers=h).get_json()["data"][
            "has_permission"
        ]
        is True
    )
    client.put("/api/settings", headers=h, json={"strict_users": True})
    blocked = client.get("/api/has_permission/dana/deploy", headers=h).get_json()[
        "data"
    ]
    assert blocked == {"has_permission": False, "reason": "user_not_key_backed"}

    secret = client.post("/api/apikeys/user/dana", headers=h).get_json()["data"][
        "api_key"
    ]
    assert (
        client.get("/api/has_permission/dana/deploy", headers=h).get_json()["data"][
            "has_permission"
        ]
        is True
    )
    combo = client.post(
        "/api/apikeys/check_permission",
        headers=h,
        json={"api_key": secret, "permission": "deploy"},
    ).get_json()["data"]
    assert combo["valid"] is True and combo["has_permission"] is True

    # Rotation carries the strict setting with the namespace.
    rotated = client.post("/api/keys/rotate", headers=h).get_json()["data"]
    assert rotated["migrated"]["settings"] == 1
    h_new = _h(rotated["new_key"])
    assert client.get("/api/settings", headers=h_new).get_json()["data"] == {
        "strict_users": True
    }


def test_rotation_preserves_keys_on_postgres_with_encryption(client):
    tenant = str(uuid.uuid4())
    secret = client.post(
        "/api/apikeys/user/bob", headers=_h(tenant)
    ).get_json()["data"]["api_key"]
    assert (
        client.post(
            "/api/apikeys/validate", headers=_h(tenant), json={"api_key": secret}
        ).get_json()["data"]["valid"]
        is True
    )

    rotated = client.post("/api/keys/rotate", headers=_h(tenant)).get_json()["data"]
    assert rotated["migrated"]["api_keys"] == 1

    fresh = client.post(
        "/api/apikeys/validate",
        headers=_h(rotated["new_key"]),
        json={"api_key": secret},
    ).get_json()["data"]
    assert fresh["valid"] is True
    assert fresh["user"] == "bob"
    assert client.post(
        "/api/apikeys/validate", headers=_h(tenant), json={"api_key": secret}
    ).get_json()["data"] == {"valid": False, "reason": "unknown_key"}
