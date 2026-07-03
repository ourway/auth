"""
Service-layer lifecycle tests on SQLite — the exact Python API surface the
Highway engine consumes. These pin the backward-compat contract: kwarg
names, return shapes, idempotency, tenant isolation, and the (documented)
soft-delete/resurrection semantics.
"""

import uuid

import pytest

from auth import Authorization
from auth.database import SessionLocal, create_tables


@pytest.fixture(scope="module", autouse=True)
def _tables():
    create_tables(raise_on_error=True)


@pytest.fixture
def auth_client():
    # Highway constructs it exactly like this: kwargs client= and db_session=
    session = SessionLocal()
    client = Authorization(client=str(uuid.uuid4()), db_session=session)
    yield client
    session.close()


def test_full_role_lifecycle(auth_client):
    assert auth_client.add_role("admin", description="Administrators") is True
    assert [r["role"] for r in auth_client.roles] == ["admin"]
    assert auth_client.roles[0]["description"] == "Administrators"
    assert auth_client.del_role("admin") is True
    assert auth_client.roles == []


def test_add_role_idempotent_preserves_description(auth_client):
    assert auth_client.add_role("ops", description="Operations") is True
    # Re-add without description must succeed and keep the old description
    assert auth_client.add_role("ops") is True
    assert auth_client.roles[0]["description"] == "Operations"


def test_membership_lifecycle_and_shapes(auth_client):
    auth_client.add_role("editor")
    assert auth_client.add_membership("alice@example.com", "editor") is True
    assert auth_client.has_membership("alice@example.com", "editor") is True
    # Highway consumes these exact shapes
    assert auth_client.get_user_roles("alice@example.com") == [
        {"user": "alice@example.com", "role": "editor"}
    ]
    assert auth_client.get_role_members("editor") == [
        {"user": "alice@example.com", "role": "editor"}
    ]
    assert auth_client.del_membership("alice@example.com", "editor") is True
    assert auth_client.has_membership("alice@example.com", "editor") is False


def test_permission_lifecycle_and_shapes(auth_client):
    auth_client.add_role("editor")
    assert auth_client.add_permission("editor", "edit_content") is True
    assert auth_client.has_permission("editor", "edit_content") is True
    assert auth_client.get_permissions("editor") == [{"name": "edit_content"}]

    auth_client.add_membership("bob@example.com", "editor")
    assert auth_client.user_has_permission("bob@example.com", "edit_content") is True
    assert auth_client.get_user_permissions("bob@example.com") == [
        {"name": "edit_content"}
    ]
    assert auth_client.which_roles_can("edit_content") == [{"role": "editor"}]
    assert auth_client.which_users_can("edit_content") == [
        {"user": "bob@example.com", "role": "editor"}
    ]

    assert auth_client.del_permission("editor", "edit_content") is True
    assert auth_client.has_permission("editor", "edit_content") is False


def test_writes_against_missing_role_return_false(auth_client):
    # Previously an OperationalError/HTTP 500 on SQLite
    assert auth_client.add_membership("alice@example.com", "ghost") is False
    assert auth_client.add_permission("ghost", "anything") is False


def test_delete_semantics_are_idempotent(auth_client):
    auth_client.add_role("temp")
    assert auth_client.del_role("temp") is True
    assert auth_client.del_role("temp") is False  # documented: second delete
    assert auth_client.del_membership("nobody@example.com", "temp") is True
    assert auth_client.del_permission("temp", "nothing") is True


def test_role_resurrection_keeps_members():
    """Documented behavior: del_role soft-deletes; re-adding the same role
    resurrects it with its previous members and permissions. Highway's
    bootstrap relies on add_role being safely repeatable; do not change
    this without a major version."""
    session = SessionLocal()
    client = Authorization(client=str(uuid.uuid4()), db_session=session)
    try:
        client.add_role("phoenix")
        client.add_membership("alice@example.com", "phoenix")
        client.add_permission("phoenix", "rise")
        assert client.del_role("phoenix") is True
        assert client.roles == []
        assert client.add_role("phoenix") is True
        assert client.has_membership("alice@example.com", "phoenix") is True
        assert client.has_permission("phoenix", "rise") is True
    finally:
        session.close()


def test_tenant_isolation():
    session_a, session_b = SessionLocal(), SessionLocal()
    a = Authorization(client=str(uuid.uuid4()), db_session=session_a)
    b = Authorization(client=str(uuid.uuid4()), db_session=session_b)
    try:
        # Both tenants can own a role with the same name (per-creator unique)
        assert a.add_role("admin") is True
        assert b.add_role("admin") is True
        a.add_membership("alice@example.com", "admin")

        assert [r["role"] for r in b.roles] == ["admin"]
        assert b.get_role_members("admin") == []
        assert b.has_membership("alice@example.com", "admin") is False

        # Same user in both tenants stays isolated
        b.add_permission("admin", "nuke")
        assert a.user_has_permission("alice@example.com", "nuke") is False
    finally:
        session_a.close()
        session_b.close()


def test_authorization_wrapper_owns_session_when_not_given():
    client = Authorization(str(uuid.uuid4()))
    assert client.add_role("standalone") is True
    assert [r["role"] for r in client.roles] == ["standalone"]
    client.db.close()
