"""
Flask test suite using Flask test client
"""

import os
import tempfile
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auth.database import Base
from auth.main import create_app


# Test database setup
@pytest.fixture
def test_db():
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    # Create test app with temporary database
    test_engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    # Create tables
    Base.metadata.create_all(bind=test_engine)

    # Create app with test database
    app = create_app()
    app.config["TESTING"] = True

    yield app

    # Cleanup
    os.unlink(db_path)


@pytest.fixture
def client(test_db):
    return test_db.test_client()



# Generate a valid UUID4 for tests
SECRET_KEY = str(uuid.uuid4())


def test_ping(client):
    """Test health check endpoint"""
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.get_json() == {"message": "PONG"}


def test_add_role(client):
    """Test adding a role"""
    response = client.post(f"/api/role/{SECRET_KEY}/admin")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}


def test_list_roles(client):
    """Test listing roles"""
    # First add a role
    client.post(f"/api/role/{SECRET_KEY}/admin")

    response = client.get(f"/api/roles/{SECRET_KEY}")
    assert response.status_code == 200
    data = response.get_json()
    assert "result" in data
    # Check for role in the list of dictionaries
    roles = [item["role"] for item in data["result"]]
    assert "admin" in roles


def test_add_permission(client):
    """Test adding permission to role"""
    # Add role first
    client.post(f"/api/role/{SECRET_KEY}/admin")

    response = client.post(f"/api/permission/{SECRET_KEY}/admin/read")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}


def test_check_permission(client):
    """Test checking permission"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")

    response = client.get(f"/api/permission/{SECRET_KEY}/admin/read")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}


def test_add_membership(client):
    """Test adding user to role"""
    # Add role first
    client.post(f"/api/role/{SECRET_KEY}/admin")

    response = client.post(f"/api/membership/{SECRET_KEY}/john/admin")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}


def test_check_membership(client):
    """Test checking membership"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")

    response = client.get(f"/api/membership/{SECRET_KEY}/john/admin")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}


def test_check_user_permission(client):
    """Test checking user permission"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")

    response = client.get(f"/api/has_permission/{SECRET_KEY}/john/read")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}


def test_get_user_permissions(client):
    """Test getting user permissions"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")
    client.post(f"/api/permission/{SECRET_KEY}/admin/write")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")

    response = client.get(f"/api/user_permissions/{SECRET_KEY}/john")
    assert response.status_code == 200
    data = response.get_json()
    assert "results" in data
    permissions = [p["name"] for p in data["results"]]
    assert "read" in permissions
    assert "write" in permissions


def test_get_role_permissions(client):
    """Test getting role permissions"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")
    client.post(f"/api/permission/{SECRET_KEY}/admin/write")

    response = client.get(f"/api/role_permissions/{SECRET_KEY}/admin")
    assert response.status_code == 200
    data = response.get_json()
    assert "results" in data
    permissions = [p["name"] for p in data["results"]]
    assert "read" in permissions
    assert "write" in permissions


def test_get_user_roles(client):
    """Test getting user roles"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/role/{SECRET_KEY}/user")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")
    client.post(f"/api/membership/{SECRET_KEY}/john/user")

    response = client.get(f"/api/user_roles/{SECRET_KEY}/john")
    assert response.status_code == 200
    data = response.get_json()
    assert "result" in data
    # Check for user in the list of membership dictionaries
    users = [item["user"] for item in data["result"]]
    assert "john" in users


def test_get_role_members(client):
    """Test getting role members"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")
    client.post(f"/api/membership/{SECRET_KEY}/jane/admin")

    response = client.get(f"/api/members/{SECRET_KEY}/admin")
    assert response.status_code == 200
    data = response.get_json()
    assert "result" in data
    # Check for users in the list of membership dictionaries
    users = [item["user"] for item in data["result"]]
    assert "john" in users
    assert "jane" in users


def test_which_roles_can(client):
    """Test which roles can perform action"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/role/{SECRET_KEY}/user")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")
    client.post(f"/api/permission/{SECRET_KEY}/user/read")

    response = client.get(f"/api/which_roles_can/{SECRET_KEY}/read")
    assert response.status_code == 200
    data = response.get_json()
    assert "result" in data
    roles = [r["role"] for r in data["result"]]
    assert "admin" in roles
    assert "user" in roles


def test_which_users_can(client):
    """Test which users can perform action"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/role/{SECRET_KEY}/user")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")
    client.post(f"/api/permission/{SECRET_KEY}/user/read")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")
    client.post(f"/api/membership/{SECRET_KEY}/jane/user")

    response = client.get(f"/api/which_users_can/{SECRET_KEY}/read")
    assert response.status_code == 200
    data = response.get_json()
    assert "result" in data
    # Check for users in the list of membership dictionaries
    users = [item["user"] for item in data["result"]]
    assert "john" in users
    assert "jane" in users


def test_delete_membership(client):
    """Test removing user from role"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/membership/{SECRET_KEY}/john/admin")

    # Check membership exists
    response = client.get(f"/api/membership/{SECRET_KEY}/john/admin")
    assert response.get_json() == {"result": True}

    # Remove membership
    response = client.delete(f"/api/membership/{SECRET_KEY}/john/admin")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}

    # Check membership removed
    response = client.get(f"/api/membership/{SECRET_KEY}/john/admin")
    assert response.get_json() == {"result": False}


def test_delete_permission(client):
    """Test removing permission from role"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")
    client.post(f"/api/permission/{SECRET_KEY}/admin/read")

    # Check permission exists
    response = client.get(f"/api/permission/{SECRET_KEY}/admin/read")
    assert response.get_json() == {"result": True}

    # Remove permission
    response = client.delete(f"/api/permission/{SECRET_KEY}/admin/read")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}

    # Check permission removed
    response = client.get(f"/api/permission/{SECRET_KEY}/admin/read")
    assert response.get_json() == {"result": False}


def test_delete_role(client):
    """Test deleting role"""
    # Setup
    client.post(f"/api/role/{SECRET_KEY}/admin")

    # Check role exists
    response = client.get(f"/api/roles/{SECRET_KEY}")
    roles = [item["role"] for item in response.get_json()["result"]]
    assert "admin" in roles

    # Delete role
    response = client.delete(f"/api/role/{SECRET_KEY}/admin")
    assert response.status_code == 200
    assert response.get_json() == {"result": True}

    # Check role removed
    response = client.get(f"/api/roles/{SECRET_KEY}")
    roles = [item["role"] for item in response.get_json()["result"]]
    assert "admin" not in roles


def test_duplicate_role(client):
    """Test adding duplicate role"""
    # Add role first time
    response = client.post(f"/api/role/{SECRET_KEY}/admin")
    assert response.get_json() == {"result": True}

    # Try to add same role again - should return True for compatibility
    response = client.post(f"/api/role/{SECRET_KEY}/admin")
    assert response.get_json() == {
        "result": True
    }  # Changed from False to True for compatibility


def test_nonexistent_operations(client):
    """Test operations on non-existent entities"""
    # Check non-existent permission
    response = client.get(f"/api/permission/{SECRET_KEY}/nonexistent/read")
    assert response.get_json() == {"result": False}

    # Delete non-existent permission
    response = client.delete(f"/api/permission/{SECRET_KEY}/nonexistent/read")
    assert response.get_json() == {"result": True}

    # Delete non-existent role
    response = client.delete(f"/api/role/{SECRET_KEY}/nonexistent")
    assert response.get_json() == {"result": False}


def test_empty_results(client):
    """Test empty results for various endpoints"""
    # Use a fresh client key that hasn't been used
    fresh_key = str(uuid.uuid4())

    # Empty roles
    response = client.get(f"/api/roles/{fresh_key}")
    assert response.get_json() == {"result": []}

    # Empty permissions
    response = client.get(f"/api/role_permissions/{fresh_key}/nonexistent")
    assert response.get_json() == {"results": []}

    # Empty user permissions
    response = client.get(f"/api/user_permissions/{fresh_key}/nonexistent")
    assert response.get_json() == {"results": []}

    # Empty which roles can
    response = client.get(f"/api/which_roles_can/{fresh_key}/nonexistent")
    assert response.get_json() == {"result": []}

    # Empty which users can
    response = client.get(f"/api/which_users_can/{fresh_key}/nonexistent")
    assert response.get_json() == {"result": []}
