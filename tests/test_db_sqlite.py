import os
import sqlite3
from unittest.mock import patch

from auth.models.sqlite import (
    AuthGroup,
    AuthMembership,
    AuthPermission,
    BaseModel,
    make_db_connection,
    make_test_db_connection,
)


def test_make_db_connection():
    """Test make_db_connection function"""
    # Test with default settings
    conn = make_db_connection()

    assert conn is not None
    assert isinstance(conn, sqlite3.Connection)

    # Test with custom db path via environment variable
    with patch.dict(os.environ, {"AUTH_DB_PATH": ":memory:"}):
        conn2 = make_db_connection()
        assert conn2 is not None
        conn2.close()

    conn.close()


def test_base_model_execute():
    """Test BaseModel execute method"""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row  # Enable row factory for dict-like access
    base_model = BaseModel(conn)

    # Create a simple table for testing
    cursor = base_model._execute(
        "CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)"
    )
    conn.commit()

    # Insert a record
    base_model._execute("INSERT INTO test_table (name) VALUES (?)", ("test",))
    conn.commit()

    # Check if the record was inserted
    cursor = base_model._execute("SELECT * FROM test_table")
    result = cursor.fetchone()

    assert result is not None
    # Using tuple indexing since row_factory might not work with custom cursor
    assert result[1] == "test"  # name column is at index 1

    conn.close()


def test_base_model_fetch_one():
    """Test BaseModel fetch_one method"""
    from auth.models.sqlite import make_test_db_connection

    conn = make_test_db_connection()
    base_model = BaseModel(conn)

    # Create and populate table for testing custom functionality
    base_model._execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
    base_model._execute("INSERT INTO test_table (name) VALUES (?)", ("test1",))
    base_model._execute("INSERT INTO test_table (name) VALUES (?)", ("test2",))
    conn.commit()

    # Fetch one record
    result = base_model._fetch_one(
        "SELECT * FROM test_table WHERE name = ?", ("test1",)
    )

    assert result is not None
    assert result["name"] == "test1"

    # Fetch non-existent record
    result = base_model._fetch_one(
        "SELECT * FROM test_table WHERE name = ?", ("nonexistent",)
    )
    assert result is None

    conn.close()


def test_base_model_fetch_all():
    """Test BaseModel fetch_all method"""
    from auth.models.sqlite import make_test_db_connection

    conn = make_test_db_connection()
    base_model = BaseModel(conn)

    # Create and populate table for testing custom functionality
    base_model._execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
    base_model._execute("INSERT INTO test_table (name) VALUES (?)", ("test1",))
    base_model._execute("INSERT INTO test_table (name) VALUES (?)", ("test2",))
    conn.commit()

    # Fetch all records
    results = base_model._fetch_all("SELECT * FROM test_table ORDER BY id")

    assert len(results) == 2
    assert results[0]["name"] == "test1"
    assert results[1]["name"] == "test2"

    conn.close()


def test_auth_group_create():
    """Test AuthGroup create method"""
    from auth.models.sqlite import make_test_db_connection

    conn = make_test_db_connection()
    auth_group = AuthGroup(conn)

    # Test successful creation
    result = auth_group.create("test_creator", "admin")
    assert result is True

    # Test duplicate creation (should fail due to UNIQUE constraint)
    result = auth_group.create("test_creator", "admin")
    assert result is False

    # Test creation with description
    result = auth_group.create("test_creator", "user", "Regular user role")
    assert result is True

    conn.close()


def test_auth_group_get_by_role():
    """Test AuthGroup get_by_role method"""
    conn = make_test_db_connection()
    auth_group = AuthGroup(conn)

    # Create a group first
    auth_group.create("test_creator", "admin", "Administrator role")

    # Retrieve the group
    result = auth_group.get_by_role("test_creator", "admin")

    assert result is not None
    assert result["creator"] == "test_creator"
    assert result["role"] == "admin"
    assert result["description"] == "Administrator role"

    # Try to get non-existent group
    result = auth_group.get_by_role("test_creator", "nonexistent")
    assert result is None

    conn.close()


def test_auth_group_get_all_by_creator():
    """Test AuthGroup get_all_by_creator method"""
    conn = make_test_db_connection()
    auth_group = AuthGroup(conn)

    # Create multiple groups
    auth_group.create("test_creator", "admin")
    auth_group.create("test_creator", "user")
    auth_group.create("other_creator", "admin")  # Different creator

    # Get groups for specific creator
    results = auth_group.get_all_by_creator("test_creator")

    assert len(results) == 2
    roles = [r["role"] for r in results]
    assert "admin" in roles
    assert "user" in roles

    conn.close()


def test_auth_group_delete():
    """Test AuthGroup delete method (soft delete)"""
    conn = make_test_db_connection()
    auth_group = AuthGroup(conn)

    # Create a group
    auth_group.create("test_creator", "admin")

    # Verify it exists
    result = auth_group.get_by_role("test_creator", "admin")
    assert result is not None

    # Delete the group (soft delete)
    delete_result = auth_group.delete("test_creator", "admin")
    assert delete_result is True

    # Verify it's no longer active
    result = auth_group.get_by_role("test_creator", "admin")
    assert result is None

    conn.close()


def test_auth_membership_create_or_get():
    """Test AuthMembership create_or_get method"""
    conn = make_test_db_connection()
    auth_membership = AuthMembership(conn)

    # Create a membership
    membership_id1 = auth_membership.create_or_get("test_creator", "user1")
    assert membership_id1 is not None

    # Get the same membership (should return the same ID)
    membership_id2 = auth_membership.create_or_get("test_creator", "user1")
    assert membership_id1 == membership_id2

    # Create a different membership
    membership_id3 = auth_membership.create_or_get("test_creator", "user2")
    assert membership_id3 != membership_id1

    conn.close()


def test_auth_membership_add_group():
    """Test AuthMembership add_group method"""
    conn = make_test_db_connection()
    auth_membership = AuthMembership(conn)
    auth_group = AuthGroup(conn)

    # Create a group and a membership
    auth_group.create("test_creator", "admin")
    membership_id = auth_membership.create_or_get("test_creator", "user1")
    group_data = auth_group.get_by_role("test_creator", "admin")
    assert group_data is not None

    # Add group to membership
    result = auth_membership.add_group(membership_id, group_data["id"])
    assert result is True

    # Try to add the same group again (should fail due to UNIQUE constraint)
    result = auth_membership.add_group(membership_id, group_data["id"])
    assert result is False

    conn.close()


def test_auth_membership_get_groups():
    """Test AuthMembership get_groups method"""
    conn = make_test_db_connection()
    auth_membership = AuthMembership(conn)
    auth_group = AuthGroup(conn)

    # Create groups and a membership
    auth_group.create("test_creator", "admin")
    auth_group.create("test_creator", "user")
    membership_id = auth_membership.create_or_get("test_creator", "user1")

    # Get group IDs
    admin_group = auth_group.get_by_role("test_creator", "admin")
    user_group = auth_group.get_by_role("test_creator", "user")
    assert admin_group is not None
    assert user_group is not None

    # Add groups to membership
    auth_membership.add_group(membership_id, admin_group["id"])
    auth_membership.add_group(membership_id, user_group["id"])

    # Get groups for user
    groups = auth_membership.get_groups("test_creator", "user1")

    assert len(groups) == 2
    roles = [g["role"] for g in groups]
    assert "admin" in roles
    assert "user" in roles

    conn.close()


def test_auth_membership_get_by_user():
    """Test AuthMembership get_by_user method"""
    conn = make_test_db_connection()
    auth_membership = AuthMembership(conn)

    # Create a membership
    auth_membership.create_or_get("test_creator", "user1")

    # Get the membership
    result = auth_membership.get_by_user("test_creator", "user1")

    assert result is not None
    assert result["user"] == "user1"
    assert result["creator"] == "test_creator"

    # Try to get non-existent membership
    result = auth_membership.get_by_user("test_creator", "nonexistent")
    assert result is None

    conn.close()


def test_auth_membership_remove_group():
    """Test AuthMembership remove_group method"""
    conn = make_test_db_connection()
    auth_membership = AuthMembership(conn)
    auth_group = AuthGroup(conn)

    # Create a group and a membership
    auth_group.create("test_creator", "admin")
    membership_id = auth_membership.create_or_get("test_creator", "user1")
    group_data = auth_group.get_by_role("test_creator", "admin")
    assert group_data is not None

    # Add group to membership
    auth_membership.add_group(membership_id, group_data["id"])

    # Verify group is added
    groups = auth_membership.get_groups("test_creator", "user1")
    assert len(groups) == 1

    # Remove the group
    result = auth_membership.remove_group(membership_id, group_data["id"])
    assert result is True

    # Verify group is removed
    groups = auth_membership.get_groups("test_creator", "user1")
    assert len(groups) == 0

    conn.close()


def test_auth_permission_create_or_get():
    """Test AuthPermission create_or_get method"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)

    # Create a permission
    perm_id1 = auth_permission.create_or_get("test_creator", "read")
    assert perm_id1 is not None

    # Get the same permission (should return the same ID)
    perm_id2 = auth_permission.create_or_get("test_creator", "read")
    assert perm_id1 == perm_id2

    # Create a different permission
    perm_id3 = auth_permission.create_or_get("test_creator", "write")
    assert perm_id3 != perm_id1

    conn.close()


def test_auth_permission_add_group():
    """Test AuthPermission add_group method"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)
    auth_group = AuthGroup(conn)

    # Create a group and a permission
    auth_group.create("test_creator", "admin")
    permission_id = auth_permission.create_or_get("test_creator", "read")
    group_data = auth_group.get_by_role("test_creator", "admin")
    assert group_data is not None

    # Add group to permission
    result = auth_permission.add_group(permission_id, group_data["id"])
    assert result is True

    # Try to add the same group again (should fail due to UNIQUE constraint)
    result = auth_permission.add_group(permission_id, group_data["id"])
    assert result is False

    conn.close()


def test_auth_permission_get_by_name():
    """Test AuthPermission get_by_name method"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)

    # Create a permission
    auth_permission.create_or_get("test_creator", "read")

    # Get the permission
    result = auth_permission.get_by_name("test_creator", "read")

    assert result is not None
    assert result["name"] == "read"
    assert result["creator"] == "test_creator"

    # Try to get non-existent permission
    result = auth_permission.get_by_name("test_creator", "nonexistent")
    assert result is None

    conn.close()


def test_auth_permission_get_groups():
    """Test AuthPermission get_groups method"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)
    auth_group = AuthGroup(conn)

    # Create groups and a permission
    auth_group.create("test_creator", "admin")
    auth_group.create("test_creator", "user")
    permission_id = auth_permission.create_or_get("test_creator", "read")

    # Get group IDs
    admin_group = auth_group.get_by_role("test_creator", "admin")
    user_group = auth_group.get_by_role("test_creator", "user")
    assert admin_group is not None
    assert user_group is not None

    # Add groups to permission
    auth_permission.add_group(permission_id, admin_group["id"])
    auth_permission.add_group(permission_id, user_group["id"])

    # Get groups for permission
    groups = auth_permission.get_groups("test_creator", "read")

    assert len(groups) == 2
    roles = [g["role"] for g in groups]
    assert "admin" in roles
    assert "user" in roles

    conn.close()


def test_auth_permission_get_all_by_group():
    """Test AuthPermission get_all_by_group method"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)
    auth_group = AuthGroup(conn)

    # Create a group and permissions
    auth_group.create("test_creator", "admin")
    auth_permission.create_or_get("test_creator", "read")
    auth_permission.create_or_get("test_creator", "write")

    # Get IDs
    group_data = auth_group.get_by_role("test_creator", "admin")
    read_perm = auth_permission.get_by_name("test_creator", "read")
    write_perm = auth_permission.get_by_name("test_creator", "write")
    assert group_data is not None
    assert read_perm is not None
    assert write_perm is not None

    # Add group to permissions
    auth_permission.add_group(read_perm["id"], group_data["id"])
    auth_permission.add_group(write_perm["id"], group_data["id"])

    # Get permissions for group
    permissions = auth_permission.get_all_by_group("test_creator", group_data["id"])

    assert len(permissions) == 2
    names = [p["name"] for p in permissions]
    assert "read" in names
    assert "write" in names

    conn.close()


def test_auth_permission_remove_group():
    """Test AuthPermission remove_group method"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)
    auth_group = AuthGroup(conn)

    # Create a group and a permission
    auth_group.create("test_creator", "admin")
    permission_id = auth_permission.create_or_get("test_creator", "read")
    group_data = auth_group.get_by_role("test_creator", "admin")
    assert group_data is not None

    # Add group to permission
    auth_permission.add_group(permission_id, group_data["id"])

    # Verify group is added
    groups = auth_permission.get_groups("test_creator", "read")
    assert len(groups) == 1

    # Remove the group
    result = auth_permission.remove_group(permission_id, group_data["id"])
    assert result is True

    # Verify group is removed
    groups = auth_permission.get_groups("test_creator", "read")
    assert len(groups) == 0

    conn.close()


def test_auth_permission_delete():
    """Test AuthPermission delete method (soft delete)"""
    conn = make_test_db_connection()
    auth_permission = AuthPermission(conn)

    # Create a permission
    auth_permission.create_or_get("test_creator", "read")

    # Verify it exists
    result = auth_permission.get_by_name("test_creator", "read")
    assert result is not None

    # Delete the permission (soft delete)
    delete_result = auth_permission.delete("test_creator", "read")
    assert delete_result is True

    # Verify it's no longer active
    result = auth_permission.get_by_name("test_creator", "read")
    assert result is None

    conn.close()
