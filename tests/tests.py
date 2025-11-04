# CONFTEST
import uuid

import pytest

from auth import Authorization

# Generate a valid UUID4 for tests
secret_key = str(uuid.uuid4())


@pytest.fixture
def cas():
    return Authorization(secret_key)


# roles
@pytest.fixture(params=["admin", "owner", "group", "other"])
def role(request, admin="admin", owner="owner", group="group", other="other"):
    return locals().get(request.param)


# permissions
@pytest.fixture
def permissions():
    return ["read", "write", "execute"]


# users
@pytest.fixture(params=["sheldon", "leonard", "raj", "howard"])
def member(request, sheldon="sheldon", leonard="leonard", raj="raj", howard="howard"):
    return locals().get(request.param)


# AUTHORIZATION TEST


def test_authorization_add_role(cas, role):
    cas.add_role(role)
    assert {"role": role} in cas.roles


def test_authorization_add_permission_to_role(cas, role, permissions):
    if role == "group":
        permissions.remove("write")
    if role == "other":
        permissions.remove("write")
        permissions.remove("execute")

    for permission in permissions:
        cas.add_permission(role, permission)

    for permission in permissions:
        assert {"name": permission} in cas.get_permissions(role)

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
    if role in ("admin", "owner", "other"):
        assert {"role": role} in cas.which_roles_can("read")

    elif role in ("admin", "owner"):
        assert {"role": role} in cas.which_roles_can("write")
    else:
        assert {"role": "other"} not in cas.which_roles_can("write")


def test_authorization_add_member(cas, member):
    association = {
        "sheldon": "admin",
        "leonard": "owner",
        "raj": "group",
        "howard": "other",
    }

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
        assert "howard" not in cas.which_users_can("write")
        assert {"role": "other"} in cas.get_user_roles("howard")

    if member == "raj":
        assert {"name": "read"} in cas.get_user_permissions("raj")
        assert {"name": "write"} not in cas.get_user_permissions("raj")


def test_authorization_delete_member(cas):
    cas.add_membership("josh", "other")
    assert cas.has_membership("josh", "other")

    cas.del_membership("josh", "other")
    assert not cas.has_membership("josh", "other")


def test_authorization_delete_role(cas):
    cas.add_role("intruder")
    assert {"role": "intruder"} in cas.roles
    cas.del_role("intruder")
    assert {"role": "intruder"} not in cas.roles


def test_authorization_delete_permission(cas):
    cas.add_permission("admin", "fake permission")
    assert {"name": "fake permission"} in cas.get_permissions("admin")
    cas.del_permission("admin", "fake permission")
    assert {"name": "fake permission"} not in cas.get_permissions("admin")
