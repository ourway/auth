"""
Tests for API-key rotation (`POST /api/keys/rotate`).

Rotation is an atomic *cutover*: the caller's whole namespace moves from the old
key to a fresh server-generated key, and the old key is left owning nothing.
These tests pin that behaviour through the HTTP API (both key states) and, for
the encryption-on path that CI cannot run under Postgres, a focused service-level
test that forces field encryption on and proves each bound cell is re-keyed.
"""

import uuid

import pytest
from sqlalchemy import select

from auth.main import create_app
from auth.models.sql import AuthGroup, AuthMembership, AuthPermission


@pytest.fixture
def app():
    # conftest points the global engine at an isolated temp SQLite DB before
    # `auth` is imported; create_app() creates the tables.
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_namespace(client, key):
    """Create one role + permission + membership under `key` via the API."""
    h = {"Authorization": f"Bearer {key}"}
    assert client.post("/api/role/engineers", headers=h).get_json() == {"result": True}
    assert client.post("/api/permission/engineers/deploy", headers=h).get_json() == {
        "result": True
    }
    assert client.post("/api/membership/alice/engineers", headers=h).get_json() == {
        "result": True
    }


def _has_permission(client, key, user, name):
    h = {"Authorization": f"Bearer {key}"}
    return (
        client.get(f"/api/has_permission/{user}/{name}", headers=h)
        .get_json()["data"]["has_permission"]
    )


def _roles(client, key):
    h = {"Authorization": f"Bearer {key}"}
    return [r["role"] for r in client.get("/api/roles", headers=h).get_json()["result"]]


def test_rotate_moves_the_namespace_to_a_fresh_key(client):
    old = str(uuid.uuid4())
    _seed_namespace(client, old)
    assert _has_permission(client, old, "alice", "deploy") is True

    resp = client.post(
        "/api/keys/rotate", headers={"Authorization": f"Bearer {old}"}
    )
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    new = data["new_key"]

    # a fresh, distinct, valid UUID4
    assert new != old
    assert str(uuid.UUID(new, version=4)) == new
    assert data["migrated"] == {"roles": 1, "memberships": 1, "permissions": 1}


def test_new_key_sees_everything_the_old_key_had(client):
    old = str(uuid.uuid4())
    _seed_namespace(client, old)
    new = client.post(
        "/api/keys/rotate", headers={"Authorization": f"Bearer {old}"}
    ).get_json()["data"]["new_key"]

    assert _roles(client, new) == ["engineers"]
    assert _has_permission(client, new, "alice", "deploy") is True
    members = client.get(
        "/api/members/engineers", headers={"Authorization": f"Bearer {new}"}
    ).get_json()["result"]
    assert any(m["user"] == "alice" for m in members)


def test_old_key_owns_nothing_after_rotation(client):
    old = str(uuid.uuid4())
    _seed_namespace(client, old)
    client.post("/api/keys/rotate", headers={"Authorization": f"Bearer {old}"})

    # The namespace moved, it was not copied.
    assert _roles(client, old) == []
    assert _has_permission(client, old, "alice", "deploy") is False


def test_rotating_twice_yields_a_different_key_each_time(client):
    old = str(uuid.uuid4())
    _seed_namespace(client, old)
    first = client.post(
        "/api/keys/rotate", headers={"Authorization": f"Bearer {old}"}
    ).get_json()["data"]["new_key"]
    second = client.post(
        "/api/keys/rotate", headers={"Authorization": f"Bearer {first}"}
    ).get_json()["data"]["new_key"]
    assert len({old, first, second}) == 3
    assert _has_permission(client, second, "alice", "deploy") is True


def test_rotate_requires_authentication(client):
    # No Authorization header -> the /api/* gate rejects it, nothing rotates.
    assert client.post("/api/keys/rotate").status_code == 401
    # A non-UUID4 token -> 400.
    assert (
        client.post(
            "/api/keys/rotate", headers={"Authorization": "Bearer not-a-uuid"}
        ).status_code
        == 400
    )


def test_rotation_reencrypts_bound_cells_when_encryption_is_on(app, monkeypatch):
    """The critical crypto path, without needing Docker/Postgres.

    Force field encryption on with a test key, seed encrypted cells under the old
    key, rotate, and prove each stored cell is now decryptable under the NEW key
    and no longer authenticates under the OLD one — i.e. it was genuinely
    re-keyed, not merely relabelled.
    """
    from auth.database import SessionLocal
    from auth.encryption import (
        DeterministicEncryption,
        FieldEncryption,
        InvalidCiphertextError,
    )
    from auth.services.service import AuthorizationService

    enc = DeterministicEncryption("unit-test-encryption-key")
    fe = FieldEncryption()
    fe.encryptor = enc
    fe.enabled = True
    # Both the write path (encrypt_sensitive_data) and rotation read this global.
    monkeypatch.setattr("auth.encryption.field_encryption", fe)

    old = str(uuid.uuid4())
    new = str(uuid.uuid4())

    db = SessionLocal()
    try:
        svc = AuthorizationService(db, old)
        assert svc.add_role("engineers", description="secret desc") is True
        assert svc.add_permission("engineers", "deploy") is True
        assert svc.add_membership("alice", "engineers") is True

        # Raw stored user cell is v2 ciphertext bound to the OLD key.
        stored_old = db.execute(
            select(AuthMembership.__table__.c.user).where(
                AuthMembership.__table__.c.creator == old
            )
        ).scalar_one()
        assert stored_old.startswith("v2:")
        assert enc.decrypt(stored_old, old) == "alice"
        with pytest.raises(InvalidCiphertextError):
            enc.decrypt(stored_old, new)  # bound to the old creator

        result = svc.rotate_client_key(new)
        assert result["new_key"] == new
        assert result["migrated"] == {"roles": 1, "memberships": 1, "permissions": 1}

        # Nothing left under the old key.
        assert (
            db.execute(
                select(AuthMembership.__table__.c.id).where(
                    AuthMembership.__table__.c.creator == old
                )
            ).first()
            is None
        )

        # Every encrypted cell now decrypts under NEW, and not under OLD.
        stored_new_user = db.execute(
            select(AuthMembership.__table__.c.user).where(
                AuthMembership.__table__.c.creator == new
            )
        ).scalar_one()
        assert enc.decrypt(stored_new_user, new) == "alice"
        with pytest.raises(InvalidCiphertextError):
            enc.decrypt(stored_new_user, old)

        stored_new_name = db.execute(
            select(AuthPermission.__table__.c.name).where(
                AuthPermission.__table__.c.creator == new
            )
        ).scalar_one()
        assert enc.decrypt(stored_new_name, new) == "deploy"

        stored_new_desc = db.execute(
            select(AuthGroup.__table__.c.description).where(
                AuthGroup.__table__.c.creator == new
            )
        ).scalar_one()
        assert enc.decrypt(stored_new_desc, new) == "secret desc"

        # And the equality-query product path works end to end under the new key.
        assert AuthorizationService(db, new).user_has_permission("alice", "deploy") is True
    finally:
        db.close()
