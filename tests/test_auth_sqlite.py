# CONFTEST
import uuid

import pytest

from auth.dal.authorization_sqlite import Authorization
from auth.models.sqlite import make_test_db_connection

# Generate a valid UUID4 for tests
secret_key = str(uuid.uuid4())


@pytest.fixture
def cas():
    conn = make_test_db_connection()
    # Create Authorization instance with custom connection
    cas_instance = Authorization(secret_key, conn=conn)

    yield cas_instance

    # Cleanup
    conn.close()


# roles
@pytest.fixture(params=["admin", "owner", "group", "other"])
def role(request):
    return request.param


# permissions
@pytest.fixture
def permissions():
    return ["read", "write", "execute"]


# users
@pytest.fixture(params=["sheldon", "leonard", "raj", "howard"])
def member(request):
    return request.param


# AUTHORIZATION TEST


def test_authorization_add_role(cas, role):
    result = cas.add_role(role)
    assert result
    # Check if role is in the list of roles (now includes description)
    roles = cas.roles
    role_dicts = [r for r in roles if r["role"] == role]
    assert len(role_dicts) == 1
    assert role_dicts[0]["role"] == role


def test_authorization_add_permission_to_role(cas, role, permissions):
    # First add the role
    cas.add_role(role)

    if role == "group":
        permissions.remove("write")
    if role == "other":
        permissions.remove("write")
        permissions.remove("execute")

    for permission in permissions:
        cas.add_permission(role, permission)

    for permission in permissions:
        permissions_list = cas.get_permissions(role)
        permission_dicts = [p for p in permissions_list if p["name"] == permission]
        assert len(permission_dicts) == 1

    if role == "admin" or role == "owner":
        assert cas.has_permission(role, "read")
        assert cas.has_permission(role, "write")
        assert cas.has_permission(role, "execute")
    elif role == "group":
        assert cas.has_permission(role, "read")
        assert not cas.has_permission(role, "write")
        assert cas.has_permission(role, "execute")
    else:
        assert cas.has_permission(role, "read")
        assert not cas.has_permission(role, "write")
        assert not cas.has_permission(role, "execute")


def test_authorization_role_can(cas, role):
    # Setup permissions - first add the role
    cas.add_role(role)
    cas.add_permission(role, "read")

    if role in ("admin", "owner", "other"):
        roles_can = cas.which_roles_can("read")
        role_dicts = [r for r in roles_can if r["role"] == role]
        assert len(role_dicts) == 1
    elif role in ("admin", "owner"):
        cas.add_permission(role, "write")
        roles_can = cas.which_roles_can("write")
        role_dicts = [r for r in roles_can if r["role"] == role]
        assert len(role_dicts) == 1
    else:
        roles_can = cas.which_roles_can("write")
        role_dicts = [r for r in roles_can if r["role"] == "other"]
        assert len(role_dicts) == 0


def test_authorization_add_member(cas, member):
    association = {
        "sheldon": "admin",
        "leonard": "owner",
        "raj": "group",
        "howard": "other",
    }

    # Add roles first
    for role_name in set(association.values()):
        cas.add_role(role_name)

    # Add permissions to roles
    cas.add_permission("admin", "read")
    cas.add_permission("admin", "write")
    cas.add_permission("admin", "execute")

    cas.add_permission("owner", "read")
    cas.add_permission("owner", "write")
    cas.add_permission("owner", "execute")

    cas.add_permission("group", "read")
    cas.add_permission("group", "execute")

    cas.add_permission("other", "read")

    cas.add_membership(member, association[member])

    assert cas.has_membership(member, association[member])

    if cas.has_membership(member, "admin") or cas.has_membership(member, "owner"):
        assert cas.user_has_permission(member, "write")
        assert cas.user_has_permission(member, "read")
        assert cas.user_has_permission(member, "execute")
    elif cas.has_membership(member, "group"):
        assert not cas.user_has_permission(member, "write")
        assert cas.user_has_permission(member, "read")
        assert cas.user_has_permission(member, "execute")
    else:
        assert not cas.user_has_permission(member, "write")
        assert cas.user_has_permission(member, "read")
        assert not cas.user_has_permission(member, "execute")

    if member == "howard":
        # Howard should not be able to write
        users_can_write = cas.which_users_can("write")
        howard_can_write = any(user["user"] == "howard" for user in users_can_write)
        assert not howard_can_write
        user_roles = cas.get_user_roles("howard")
        howard_roles = [
            r for r in user_roles if r["user"] == "howard" and r["role"] == "other"
        ]
        assert len(howard_roles) == 1

    if member == "raj":
        user_permissions = cas.get_user_permissions("raj")
        read_perms = [p for p in user_permissions if p["name"] == "read"]
        write_perms = [p for p in user_permissions if p["name"] == "write"]
        assert len(read_perms) == 1
        assert len(write_perms) == 0


def test_authorization_delete_member(cas):
    cas.add_role("other")
    cas.add_membership("josh", "other")
    assert cas.has_membership("josh", "other")

    cas.del_membership("josh", "other")
    assert not cas.has_membership("josh", "other")


def test_authorization_delete_role(cas):
    cas.add_role("intruder")
    roles = cas.roles
    intruder_roles = [r for r in roles if r["role"] == "intruder"]
    assert len(intruder_roles) == 1

    cas.del_role("intruder")
    roles = cas.roles
    intruder_roles = [r for r in roles if r["role"] == "intruder"]
    assert len(intruder_roles) == 0


def test_authorization_delete_permission(cas):
    cas.add_role("admin")
    cas.add_permission("admin", "fake permission")
    permissions = cas.get_permissions("admin")
    fake_perms = [p for p in permissions if p["name"] == "fake permission"]
    assert len(fake_perms) == 1

    cas.del_permission("admin", "fake permission")
    permissions = cas.get_permissions("admin")
    fake_perms = [p for p in permissions if p["name"] == "fake permission"]
    assert len(fake_perms) == 0


def test_authorization_get_role_members(cas):
    cas.add_role("test_role")
    cas.add_membership("user1", "test_role")
    cas.add_membership("user2", "test_role")

    members = cas.get_role_members("test_role")
    user1_members = [m for m in members if m["user"] == "user1"]
    user2_members = [m for m in members if m["user"] == "user2"]
    assert len(user1_members) == 1
    assert len(user2_members) == 1


def test_authorization_which_users_can(cas):
    cas.add_role("role1")
    cas.add_role("role2")
    cas.add_permission("role1", "test_permission")
    cas.add_membership("user1", "role1")
    cas.add_membership("user2", "role2")

    users_can = cas.which_users_can("test_permission")
    user1_can = [u for u in users_can if u["user"] == "user1"]
    user2_can = [u for u in users_can if u["user"] == "user2"]
    assert len(user1_can) == 1
    assert len(user2_can) == 0


def test_authorization_duplicate_role(cas):
    # Adding same role twice should return True for both attempts (for compatibility)
    result1 = cas.add_role("duplicate_role")
    result2 = cas.add_role("duplicate_role")

    assert result1
    assert result2  # Should return True for compatibility


def test_authorization_nonexistent_role(cas):
    # Operations on non-existent roles should handle gracefully
    assert not cas.has_permission("nonexistent", "read")
    # Verify del_permission returns True for non-existent (as the function handles this case)
    result = cas.del_permission("nonexistent", "read")
    assert result  # Should return True for non-existent
    assert not cas.del_role("nonexistent")  # Should return False for non-existent


def test_authorization_empty_results():
    # Create a fresh in-memory database for this test
    from auth.models.sqlite import make_test_db_connection
    conn = make_test_db_connection()

    # Create Authorization instance with custom connection
    cas_instance = Authorization(secret_key, conn=conn)

    # Test empty results for various methods
    assert cas_instance.roles == []
    assert cas_instance.get_permissions("nonexistent") == []
    assert cas_instance.get_user_permissions("nonexistent_user") == []
    assert cas_instance.get_user_roles("nonexistent_user") == []
    assert cas_instance.get_role_members("nonexistent_role") == []
    assert cas_instance.which_roles_can("nonexistent_permission") == []
    assert cas_instance.which_users_can("nonexistent_permission") == []

    # Cleanup
    conn.close()
