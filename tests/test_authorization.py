from unittest.mock import Mock, patch

from mongoengine.errors import NotUniqueError

from auth.dal.authorization import Authorization


@patch("auth.dal.authorization.make_db_connection")
def test_authorization_init(mock_make_db_connection):
    """Test Authorization class initialization"""
    auth = Authorization("test_client")

    assert auth.client == "test_client"
    mock_make_db_connection.assert_called_once()


@patch("auth.dal.authorization.make_db_connection")
def test_roles_property(mock_make_db_connection):
    """Test roles property"""

    # Mock the AuthGroup query
    with patch("auth.dal.authorization.AuthGroup") as mock_auth_group:
        mock_query = Mock()
        mock_query.only.return_value = Mock()
        mock_query.only.return_value.to_json.return_value = '[{"role": "admin"}]'
        mock_auth_group.objects.return_value = mock_query

        auth = Authorization("test_client")
        _ = auth.roles  # Ensure roles property is accessed
        mock_auth_group.objects.assert_called_with(creator="test_client")
        mock_query.only.assert_called_with("role")


@patch("auth.dal.authorization.make_db_connection")
def test_get_permissions(mock_make_db_connection):
    """Test get_permissions method"""
    auth = Authorization("test_client")

    with (
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthPermission") as mock_auth_permission,
    ):
        mock_group = Mock()
        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        # Mock permission query
        mock_permission = Mock()
        mock_permission.name = "read"
        mock_permission_query = Mock()
        mock_permission_query.only.return_value = [mock_permission]
        mock_auth_permission.objects.return_value = mock_permission_query

        auth.get_permissions("admin")

        mock_auth_group.objects.assert_called_with(role="admin", creator="test_client")
        mock_group_query.first.assert_called_once()
        mock_auth_permission.objects.assert_called_with(
            groups=mock_group, creator="test_client"
        )


@patch("auth.dal.authorization.make_db_connection")
def test_get_user_permissions(mock_make_db_connection):
    """Test get_user_permissions method"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthMembership") as mock_auth_membership:
        # Mock membership query result
        mock_membership = Mock()
        mock_membership.groups = [Mock(role="admin")]

        mock_membership_query = Mock()
        mock_membership_query.only.return_value = [mock_membership]
        mock_auth_membership.objects.return_value = mock_membership_query

        with patch("auth.dal.authorization.AuthPermission") as mock_auth_permission:
            mock_permission = Mock()
            mock_permission.name = "read"
            mock_permission_query = Mock()
            mock_permission_query.only.return_value = [mock_permission]
            mock_auth_permission.objects.return_value = mock_permission_query

            permissions = auth.get_user_permissions("user1")

            assert len(permissions) == 1
            assert permissions[0]["name"] == "read"


@patch("auth.dal.authorization.make_db_connection")
def test_get_user_roles(mock_make_db_connection):
    """Test get_user_roles method"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthMembership") as mock_auth_membership:
        # Mock membership query result
        mock_membership = Mock()
        mock_membership.groups = [Mock(role="admin")]

        mock_membership_query = Mock()
        mock_membership_query.only.return_value = [mock_membership]
        mock_auth_membership.objects.return_value = mock_membership_query

        roles = auth.get_user_roles("user1")

        assert len(roles) == 1
        assert roles[0]["role"] == "admin"


@patch("auth.dal.authorization.make_db_connection")
def test_get_role_members(mock_make_db_connection):
    """Test get_role_members method"""
    auth = Authorization("test_client")

    with (
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthMembership") as mock_auth_membership,
    ):
        mock_group_query = Mock()
        mock_group_query.only.return_value = [Mock(role="admin", id=1)]
        mock_auth_group.objects.return_value = mock_group_query

        # Mock membership query
        mock_membership = Mock()
        mock_membership.user = "user1"
        mock_membership_query = Mock()
        mock_membership_query.only.return_value = [mock_membership]
        mock_auth_membership.objects.return_value = mock_membership_query

        auth.get_role_members("admin")

        # Verify the calls
        mock_auth_group.objects.assert_called_with(creator="test_client", role="admin")


@patch("auth.dal.authorization.make_db_connection")
def test_which_roles_can(mock_make_db_connection):
    """Test which_roles_can method"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthPermission") as mock_auth_permission:
        mock_permission = Mock()
        mock_permission.groups = [Mock(role="admin")]
        mock_permission_query = Mock()
        mock_permission_query.first.return_value = mock_permission
        mock_auth_permission.objects.return_value = mock_permission_query

        roles = auth.which_roles_can("read")

        assert len(roles) == 1
        assert roles[0]["role"] == "admin"


@patch("auth.dal.authorization.make_db_connection")
def test_which_users_can(mock_make_db_connection):
    """Test which_users_can method"""
    auth = Authorization("test_client")

    with (
        patch.object(auth, "which_roles_can") as mock_which_roles,
        patch.object(auth, "get_role_members") as mock_get_members,
    ):

        mock_which_roles.return_value = [{"role": "admin"}]
        mock_get_members.return_value = [{"user": "user1"}]

        result = auth.which_users_can("read")

        assert result == [[{"user": "user1"}]]
        mock_which_roles.assert_called_with("read")
        mock_get_members.assert_called_with("admin")


@patch("auth.dal.authorization.make_db_connection")
def test_get_role(mock_make_db_connection):
    """Test get_role method"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthGroup") as mock_auth_group:
        mock_group = Mock()
        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        role = auth.get_role("admin")

        assert role == mock_group
        mock_auth_group.objects.assert_called_with(role="admin", creator="test_client")


@patch("auth.dal.authorization.make_db_connection")
def test_add_role_success(mock_make_db_connection):
    """Test add_role method success"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthGroup") as mock_auth_group:
        mock_group_instance = Mock()
        mock_auth_group.return_value = mock_group_instance

        result = auth.add_role("admin")

        assert result is True
        mock_group_instance.save.assert_called_once()


@patch("auth.dal.authorization.make_db_connection")
def test_add_role_duplicate(mock_make_db_connection):
    """Test add_role method with duplicate error"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthGroup") as mock_auth_group:
        mock_group_instance = Mock()
        mock_group_instance.save.side_effect = NotUniqueError()
        mock_auth_group.return_value = mock_group_instance

        result = auth.add_role("admin")

        assert result is False


@patch("auth.dal.authorization.make_db_connection")
def test_del_role_success(mock_make_db_connection):
    """Test del_role method success"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthGroup") as mock_auth_group:
        mock_group = Mock()
        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        result = auth.del_role("admin")

        assert result is True
        mock_group.delete.assert_called_once()


@patch("auth.dal.authorization.make_db_connection")
def test_del_role_not_found(mock_make_db_connection):
    """Test del_role method when role not found"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthGroup") as mock_auth_group:
        mock_group_query = Mock()
        mock_group_query.first.return_value = None
        mock_auth_group.objects.return_value = mock_group_query

        result = auth.del_role("admin")

        assert result is False


@patch("auth.dal.authorization.make_db_connection")
def test_add_membership_new_user(mock_make_db_connection):
    """Test add_membership for a new user"""
    auth = Authorization("test_client")

    with (
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthMembership") as mock_auth_membership,
    ):

        # Mock group exists
        mock_group = Mock()
        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        # Mock user doesn't exist initially, so first() returns None
        mock_membership_query = Mock()
        mock_membership_query.first.return_value = None
        mock_auth_membership.objects.return_value = mock_membership_query

        # Set up new membership instance
        new_membership = Mock()
        mock_auth_membership.return_value = new_membership

        result = auth.add_membership("user1", "admin")

        assert result is True
        # Check that a new membership was created with the user
        mock_auth_membership.assert_called()
        new_membership.save.assert_called()


@patch("auth.dal.authorization.make_db_connection")
def test_add_membership_existing_user(mock_make_db_connection):
    """Test add_membership for an existing user"""
    auth = Authorization("test_client")

    with (
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthMembership") as mock_auth_membership,
    ):

        # Mock group exists
        mock_group = Mock()
        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        # Mock user exists
        existing_membership = Mock()
        existing_membership.groups = []  # Empty initially
        mock_membership_query = Mock()
        mock_membership_query.first.return_value = existing_membership
        mock_auth_membership.objects.return_value = mock_membership_query

        result = auth.add_membership("user1", "admin")

        assert result is True


@patch("auth.dal.authorization.make_db_connection")
def test_del_membership_success(mock_make_db_connection):
    """Test del_membership method success"""
    auth = Authorization("test_client")

    with (
        patch.object(auth, "has_membership") as mock_has_membership,
        patch("auth.dal.authorization.AuthMembership") as mock_auth_membership,
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
    ):

        mock_has_membership.return_value = True
        mock_group = Mock()
        mock_membership = Mock()
        mock_membership.groups = [mock_group]
        mock_group.role = "admin"

        mock_membership_query = Mock()
        mock_membership_query.first.return_value = mock_membership
        mock_auth_membership.objects.return_value = mock_membership_query

        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        result = auth.del_membership("user1", "admin")

        assert result is True


@patch("auth.dal.authorization.make_db_connection")
def test_del_membership_not_exists(mock_make_db_connection):
    """Test del_membership method when membership doesn't exist"""
    auth = Authorization("test_client")

    with patch.object(auth, "has_membership") as mock_has_membership:
        mock_has_membership.return_value = False

        result = auth.del_membership("user1", "admin")

        assert result is True  # Returns True if doesn't exist


@patch("auth.dal.authorization.make_db_connection")
def test_has_membership_success(mock_make_db_connection):
    """Test has_membership method success"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthMembership") as mock_auth_membership:
        mock_membership = Mock()
        mock_membership.groups = [Mock(role="admin")]
        mock_membership_query = Mock()
        mock_membership_query.first.return_value = mock_membership
        mock_auth_membership.objects.return_value = mock_membership_query

        result = auth.has_membership("user1", "admin")

        assert result is True


@patch("auth.dal.authorization.make_db_connection")
def test_has_membership_not_found(mock_make_db_connection):
    """Test has_membership method not found"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthMembership") as mock_auth_membership:
        mock_membership_query = Mock()
        mock_membership_query.first.return_value = None
        mock_auth_membership.objects.return_value = mock_membership_query

        result = auth.has_membership("user1", "admin")

        assert result is False


@patch("auth.dal.authorization.make_db_connection")
def test_add_permission_success(mock_make_db_connection):
    """Test add_permission method success"""
    auth = Authorization("test_client")

    with (
        patch.object(auth, "has_permission") as mock_has_permission,
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthPermission") as mock_auth_permission,
    ):

        mock_has_permission.return_value = False  # Permission doesn't exist yet
        mock_group = Mock()

        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        mock_auth_permission.objects.return_value = Mock()
        mock_auth_permission.objects.return_value.update.return_value = 1

        result = auth.add_permission("admin", "read")

        assert result is True


@patch("auth.dal.authorization.make_db_connection")
def test_add_permission_already_exists(mock_make_db_connection):
    """Test add_permission method when permission already exists"""
    auth = Authorization("test_client")

    with patch.object(auth, "has_permission") as mock_has_permission:
        mock_has_permission.return_value = True  # Permission already exists

        result = auth.add_permission("admin", "read")

        assert result is True


@patch("auth.dal.authorization.make_db_connection")
def test_del_permission_success(mock_make_db_connection):
    """Test del_permission method success"""
    auth = Authorization("test_client")

    with (
        patch.object(auth, "has_permission") as mock_has_permission,
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthPermission") as mock_auth_permission,
    ):

        mock_has_permission.return_value = True
        mock_group = Mock()
        mock_permission = Mock()

        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        mock_permission_query = Mock()
        mock_permission_query.first.return_value = mock_permission
        mock_auth_permission.objects.return_value = mock_permission_query

        result = auth.del_permission("admin", "read")

        assert result is True
        mock_permission.delete.assert_called_once()


@patch("auth.dal.authorization.make_db_connection")
def test_has_permission_success(mock_make_db_connection):
    """Test has_permission method success"""
    auth = Authorization("test_client")

    with (
        patch("auth.dal.authorization.AuthGroup") as mock_auth_group,
        patch("auth.dal.authorization.AuthPermission") as mock_auth_permission,
    ):

        mock_group = Mock()
        mock_group_query = Mock()
        mock_group_query.first.return_value = mock_group
        mock_auth_group.objects.return_value = mock_group_query

        mock_permission = Mock()
        mock_permission_query = Mock()
        mock_permission_query.first.return_value = mock_permission
        mock_auth_permission.objects.return_value = mock_permission_query

        result = auth.has_permission("admin", "read")

        assert result is True


@patch("auth.dal.authorization.make_db_connection")
def test_user_has_permission_success(mock_make_db_connection):
    """Test user_has_permission method success"""
    auth = Authorization("test_client")

    with patch("auth.dal.authorization.AuthMembership") as mock_auth_membership:
        mock_membership = Mock()
        mock_membership.groups = [Mock(role="admin")]
        mock_membership_query = Mock()
        mock_membership_query.first.return_value = mock_membership
        mock_auth_membership.objects.return_value = mock_membership_query

        with patch.object(auth, "has_permission") as mock_has_permission:
            mock_has_permission.return_value = True

            result = auth.user_has_permission("user1", "read")

            assert result is True
