from unittest.mock import patch

from auth.services.rest_service import app

# Create a test client for the Flask app
client = app.test_client()


def test_ping_endpoint():
    """Test the ping endpoint"""
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.get_json() == {"message": "PONG"}


def test_get_membership():
    """Test getting membership"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.has_membership.return_value = True

        response = client.get("/api/membership/test_client/test_user/test_group")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.has_membership.assert_called_with("test_user", "test_group")


def test_add_membership():
    """Test adding membership"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.add_membership.return_value = True

        response = client.post("/api/membership/test_client/test_user/test_group")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.add_membership.assert_called_with("test_user", "test_group")


def test_delete_membership():
    """Test deleting membership"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.del_membership.return_value = True

        response = client.delete("/api/membership/test_client/test_user/test_group")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.del_membership.assert_called_with("test_user", "test_group")


def test_get_permission():
    """Test getting permission"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.has_permission.return_value = True

        response = client.get("/api/permission/test_client/test_group/test_name")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.has_permission.assert_called_with("test_group", "test_name")


def test_add_permission():
    """Test adding permission"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.add_permission.return_value = True

        response = client.post("/api/permission/test_client/test_group/test_name")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.add_permission.assert_called_with("test_group", "test_name")


def test_delete_permission():
    """Test deleting permission"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.del_permission.return_value = True

        response = client.delete("/api/permission/test_client/test_group/test_name")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.del_permission.assert_called_with("test_group", "test_name")


def test_user_has_permission():
    """Test user has permission"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.user_has_permission.return_value = True

        response = client.get("/api/has_permission/test_client/test_user/test_name")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.user_has_permission.assert_called_with(
            "test_user", "test_name"
        )


def test_get_user_permissions():
    """Test getting user permissions"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.get_user_permissions.return_value = ["perm1", "perm2"]

        response = client.get("/api/user_permissions/test_client/test_user")
        assert response.status_code == 200
        assert response.get_json() == {"results": ["perm1", "perm2"]}

        mock_auth_instance.get_user_permissions.assert_called_with("test_user")


def test_get_role_permissions():
    """Test getting role permissions"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.get_permissions.return_value = ["perm1", "perm2"]

        response = client.get("/api/role_permissions/test_client/test_role")
        assert response.status_code == 200
        assert response.get_json() == {"results": ["perm1", "perm2"]}

        mock_auth_instance.get_permissions.assert_called_with("test_role")


def test_get_user_roles():
    """Test getting user roles"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.get_user_roles.return_value = ["role1", "role2"]

        response = client.get("/api/user_roles/test_client/test_user")
        assert response.status_code == 200
        assert response.get_json() == {"result": ["role1", "role2"]}

        mock_auth_instance.get_user_roles.assert_called_with("test_user")


def test_get_role_members():
    """Test getting role members"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.get_role_members.return_value = ["user1", "user2"]

        response = client.get("/api/members/test_client/test_role")
        assert response.status_code == 200
        assert response.get_json() == {"result": ["user1", "user2"]}

        mock_auth_instance.get_role_members.assert_called_with("test_role")


def test_list_roles():
    """Test listing roles"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.roles = ["role1", "role2"]

        response = client.get("/api/roles/test_client")
        assert response.status_code == 200
        assert response.get_json() == {"result": ["role1", "role2"]}


def test_which_roles_can():
    """Test which roles can"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.which_roles_can.return_value = ["role1", "role2"]

        response = client.get("/api/which_roles_can/test_client/test_name")
        assert response.status_code == 200
        assert response.get_json() == {"result": ["role1", "role2"]}

        mock_auth_instance.which_roles_can.assert_called_with("test_name")


def test_which_users_can():
    """Test which users can"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.which_users_can.return_value = ["user1", "user2"]

        response = client.get("/api/which_users_can/test_client/test_name")
        assert response.status_code == 200
        assert response.get_json() == {"result": ["user1", "user2"]}

        mock_auth_instance.which_users_can.assert_called_with("test_name")


def test_add_role():
    """Test adding role"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.add_role.return_value = True

        response = client.post("/api/role/test_client/test_role")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.add_role.assert_called_with("test_role")


def test_delete_role():
    """Test deleting role"""
    with patch("auth.services.rest_service.Authorization") as mock_auth:
        mock_auth_instance = mock_auth.return_value
        mock_auth_instance.del_role.return_value = True

        response = client.delete("/api/role/test_client/test_group")
        assert response.status_code == 200
        assert response.get_json() == {"result": True}

        mock_auth_instance.del_role.assert_called_with("test_group")
