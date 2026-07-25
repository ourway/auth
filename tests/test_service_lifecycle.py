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


def test_add_role_is_idempotent_for_a_live_role():
    """Re-adding a role that still exists must KEEP its members and permissions.

    Callers bootstrap their roles repeatedly (Highway calls add_role on every
    start), so a repeat add must never wipe grants. This is the half that must
    not change — see test_deleted_role_does_not_resurrect_grants for the half
    that must.
    """
    session = SessionLocal()
    client = Authorization(client=str(uuid.uuid4()), db_session=session)
    try:
        client.add_role("phoenix")
        client.add_membership("alice@example.com", "phoenix")
        client.add_permission("phoenix", "rise")

        assert client.add_role("phoenix") is True  # repeat add, role still live
        assert client.has_membership("alice@example.com", "phoenix") is True
        assert client.has_permission("phoenix", "rise") is True
    finally:
        session.close()


def test_deleted_role_does_not_resurrect_grants():
    """Deleting a role PURGES its grants: re-creating the same name yields an
    empty role.

    Deleting a role is how callers revoke access. Previously the grants were
    only hidden, so reusing the role name silently restored every former member
    and permission (privilege restoration). Deletion must be durable.
    """
    session = SessionLocal()
    client = Authorization(client=str(uuid.uuid4()), db_session=session)
    try:
        client.add_role("phoenix")
        client.add_membership("alice@example.com", "phoenix")
        client.add_permission("phoenix", "rise")
        assert client.user_has_permission("alice@example.com", "rise") is True

        assert client.del_role("phoenix") is True
        assert client.roles == []
        # revocation is effective while deleted
        assert client.user_has_permission("alice@example.com", "rise") is False

        # ...and re-creating the same name does NOT bring the grants back
        assert client.add_role("phoenix") is True
        assert client.has_membership("alice@example.com", "phoenix") is False
        assert client.has_permission("phoenix", "rise") is False
        assert client.user_has_permission("alice@example.com", "rise") is False
        assert client.get_role_members("phoenix") == []
        assert client.get_permissions("phoenix") == []
    finally:
        session.close()


def test_deleting_one_role_leaves_other_roles_intact():
    """The purge is scoped to the deleted role: a user in two roles keeps the
    other role's access, and the user/permission entities survive."""
    session = SessionLocal()
    client = Authorization(client=str(uuid.uuid4()), db_session=session)
    try:
        client.add_role("temp")
        client.add_role("keeper")
        client.add_membership("alice@example.com", "temp")
        client.add_membership("alice@example.com", "keeper")
        client.add_permission("temp", "shared")
        client.add_permission("keeper", "shared")

        assert client.del_role("temp") is True

        assert client.has_membership("alice@example.com", "keeper") is True
        assert client.has_permission("keeper", "shared") is True
        assert client.user_has_permission("alice@example.com", "shared") is True
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
