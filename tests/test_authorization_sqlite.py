from unittest.mock import Mock, patch

from auth.dal.authorization_sqlite import Authorization


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_authorization_init(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test Authorization class initialization"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    assert auth.client == "test_client"
    assert auth.conn == mock_conn
    mock_make_db_connection.assert_called_once()

    # Check that the models were initialized with the connection
    mock_group.assert_called_once_with(mock_conn)
    mock_membership.assert_called_once_with(mock_conn)
    mock_permission.assert_called_once_with(mock_conn)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_roles_property(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test roles property"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_all_by_creator.return_value = [
        {"role": "admin"},
        {"role": "user"},
    ]

    roles = auth.roles

    assert roles == [{"role": "admin"}, {"role": "user"}]
    mock_group_instance.get_all_by_creator.assert_called_with("test_client")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_permissions(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_permissions method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

    # Set up mock permission object
    mock_permission_instance = Mock()
    auth.permission_model = mock_permission_instance
    mock_permission_instance.get_all_by_group.return_value = [
        {"name": "read"},
        {"name": "write"},
    ]

    permissions = auth.get_permissions("admin")

    assert permissions == [{"name": "read"}, {"name": "write"}]
    mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
    mock_permission_instance.get_all_by_group.assert_called_with("test_client", 1)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_permissions_role_not_found(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_permissions method when role is not found"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object to return None (role not found)
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = None

    permissions = auth.get_permissions("nonexistent")

    assert permissions == []


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_user_permissions(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_user_permissions method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock membership model
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.get_groups.return_value = [{"id": 1, "role": "admin"}]

    # Set up mock permission model
    mock_permission_instance = Mock()
    auth.permission_model = mock_permission_instance
    mock_permission_instance.get_all_by_group.return_value = [
        {"name": "read"},
        {"name": "write"},
    ]

    permissions = auth.get_user_permissions("user1")

    assert permissions == [{"name": "read"}, {"name": "write"}]
    mock_membership_instance.get_groups.assert_called_with("test_client", "user1")
    mock_permission_instance.get_all_by_group.assert_called_with("test_client", 1)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_user_roles(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_user_roles method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock membership model
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.get_groups.return_value = [
        {"id": 1, "role": "admin"},
        {"id": 2, "role": "user"},
    ]

    roles = auth.get_user_roles("user1")

    assert roles == [{"user": "user1", "role": "admin"}, {"user": "user1", "role": "user"}]
    mock_membership_instance.get_groups.assert_called_with("test_client", "user1")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_role_members(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_role_members method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group model
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

    # Set up mock membership model
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance._fetch_all.return_value = [
        {"user": "user1"},
        {"user": "user2"},
    ]

    members = auth.get_role_members("admin")

    assert members == [{"user": "user1", "role": "admin"}, {"user": "user2", "role": "admin"}]
    mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
    # The call will be made to the raw SQL method, but testing the logic
    assert mock_membership_instance._fetch_all.called


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_role_members_role_not_found(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_role_members method when role is not found"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group model to return None
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = None

    members = auth.get_role_members("nonexistent")

    assert members == []


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_which_roles_can(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test which_roles_can method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock permission model
    mock_permission_instance = Mock()
    auth.permission_model = mock_permission_instance
    mock_permission_instance.get_groups.return_value = [
        {"id": 1, "role": "admin"},
        {"id": 2, "role": "editor"},
    ]

    roles = auth.which_roles_can("read")

    assert roles == [{"role": "admin"}, {"role": "editor"}]
    mock_permission_instance.get_groups.assert_called_with("test_client", "read")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_which_users_can(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test which_users_can method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    with patch.object(auth, "which_roles_can") as mock_which_roles, \
         patch.object(auth, "get_role_members") as mock_get_members:

        mock_which_roles.return_value = [{"role": "admin"}, {"role": "editor"}]
        mock_get_members.side_effect = [
            [{"user": "user1"}, {"user": "user2"}],  # For admin role
            [{"user": "user3"}],  # For editor role
        ]

        result = auth.which_users_can("read")

        # which_users_can now flattens the list instead of returning nested lists
        assert result == [{"user": "user1"}, {"user": "user2"}, {"user": "user3"}]
        mock_which_roles.assert_called_with("read")
        mock_get_members.assert_any_call("admin")
        mock_get_members.assert_any_call("editor")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_get_role(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test get_role method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    expected_role = {"id": 1, "role": "admin"}
    mock_group_instance.get_by_role.return_value = expected_role

    role = auth.get_role("admin")

    assert role == expected_role
    mock_group_instance.get_by_role.assert_called_with("test_client", "admin")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_add_role(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test add_role method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.create.return_value = True

    result = auth.add_role("admin")

    assert result is True
    mock_group_instance.create.assert_called_with("test_client", "admin", None)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_add_role_with_description(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test add_role method with description"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.create.return_value = True

    result = auth.add_role("admin", "Administrator role")

    assert result is True
    mock_group_instance.create.assert_called_with(
        "test_client", "admin", "Administrator role"
    )


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_del_role(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test del_role method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.delete.return_value = True

    result = auth.del_role("admin")

    assert result is True
    mock_group_instance.delete.assert_called_with("test_client", "admin")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_add_membership(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test add_membership method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object (role exists)
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

    # Set up mock membership object
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.create_or_get.return_value = 100  # membership ID
    mock_membership_instance.add_group.return_value = True

    result = auth.add_membership("user1", "admin")

    assert result is True
    mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
    mock_membership_instance.create_or_get.assert_called_with("test_client", "user1")
    mock_membership_instance.add_group.assert_called_with(100, 1)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_add_membership_role_not_found(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test add_membership method when role doesn't exist"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object (role doesn't exist)
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = None

    result = auth.add_membership("user1", "nonexistent")

    assert result is False
    mock_group_instance.get_by_role.assert_called_with("test_client", "nonexistent")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_del_membership(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test del_membership method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    with patch.object(auth, "has_membership") as mock_has_membership:
        mock_has_membership.return_value = True  # Membership exists

        # Set up mock group object
        mock_group_instance = Mock()
        auth.group_model = mock_group_instance
        mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

        # Set up mock membership object
        mock_membership_instance = Mock()
        auth.membership_model = mock_membership_instance
        mock_membership_instance.get_by_user.return_value = {"id": 100, "user": "user1"}
        mock_membership_instance.remove_group.return_value = True

        result = auth.del_membership("user1", "admin")

        assert result is True
        mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
        mock_membership_instance.get_by_user.assert_called_with("test_client", "user1")
        mock_membership_instance.remove_group.assert_called_with(100, 1)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_del_membership_not_exists(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test del_membership method when membership doesn't exist"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    with patch.object(auth, "has_membership") as mock_has_membership:
        mock_has_membership.return_value = False  # Membership doesn't exist

        result = auth.del_membership("user1", "admin")

        assert result is True  # Returns True if doesn't exist


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_has_membership(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test has_membership method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock membership object
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.get_groups.return_value = [{"id": 1, "role": "admin"}]

    result = auth.has_membership("user1", "admin")

    assert result is True
    mock_membership_instance.get_groups.assert_called_with("test_client", "user1")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_has_membership_false(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test has_membership method returning False"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock membership object
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.get_groups.return_value = [
        {"id": 1, "role": "admin"}  # different role
    ]

    result = auth.has_membership("user1", "editor")

    assert result is False


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_add_permission(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test add_permission method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    with patch.object(auth, "has_permission") as mock_has_permission:
        mock_has_permission.return_value = False  # Permission doesn't exist yet

        # Set up mock group object
        mock_group_instance = Mock()
        auth.group_model = mock_group_instance
        mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

        # Set up mock permission object
        mock_permission_instance = Mock()
        auth.permission_model = mock_permission_instance
        mock_permission_instance.create_or_get.return_value = 100  # permission ID
        mock_permission_instance.add_group.return_value = True

        result = auth.add_permission("admin", "read")

        assert result is True
        mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
        mock_permission_instance.create_or_get.assert_called_with("test_client", "read")
        mock_permission_instance.add_group.assert_called_with(100, 1)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_add_permission_already_exists(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test add_permission method when permission already exists"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    with patch.object(auth, "has_permission") as mock_has_permission:
        mock_has_permission.return_value = True  # Permission already exists

        result = auth.add_permission("admin", "read")

        assert result is True


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_del_permission(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test del_permission method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    with patch.object(auth, "has_permission") as mock_has_permission:
        mock_has_permission.return_value = True  # Permission exists

        # Set up mock group object
        mock_group_instance = Mock()
        auth.group_model = mock_group_instance
        mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

        # Set up mock permission object
        mock_permission_instance = Mock()
        auth.permission_model = mock_permission_instance
        mock_permission_instance.get_by_name.return_value = {"id": 100, "name": "read"}
        mock_permission_instance.remove_group.return_value = True

        result = auth.del_permission("admin", "read")

        assert result is True
        mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
        mock_permission_instance.get_by_name.assert_called_with("test_client", "read")
        mock_permission_instance.remove_group.assert_called_with(100, 1)


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_has_permission(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test has_permission method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

    # Set up mock permission object
    mock_permission_instance = Mock()
    auth.permission_model = mock_permission_instance
    mock_permission_instance.get_groups.return_value = [{"id": 1, "role": "admin"}]

    result = auth.has_permission("admin", "read")

    assert result is True
    mock_group_instance.get_by_role.assert_called_with("test_client", "admin")
    mock_permission_instance.get_groups.assert_called_with("test_client", "read")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_has_permission_false(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test has_permission method returning False"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock group object
    mock_group_instance = Mock()
    auth.group_model = mock_group_instance
    mock_group_instance.get_by_role.return_value = {"id": 1, "role": "admin"}

    # Set up mock permission object - different group
    mock_permission_instance = Mock()
    auth.permission_model = mock_permission_instance
    mock_permission_instance.get_groups.return_value = [
        {"id": 2, "role": "editor"}  # different group
    ]

    result = auth.has_permission("admin", "read")

    assert result is False


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_user_has_permission(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test user_has_permission method"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock membership object
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.get_groups.return_value = [{"id": 1, "role": "admin"}]

    with patch.object(auth, "has_permission") as mock_has_permission:
        mock_has_permission.return_value = True

        result = auth.user_has_permission("user1", "read")

        assert result is True
        mock_membership_instance.get_groups.assert_called_with("test_client", "user1")
        mock_has_permission.assert_called_with("admin", "read")


@patch("auth.dal.authorization_sqlite.make_db_connection")
@patch("auth.dal.authorization_sqlite.AuthGroup")
@patch("auth.dal.authorization_sqlite.AuthMembership")
@patch("auth.dal.authorization_sqlite.AuthPermission")
def test_user_has_permission_false(
    mock_permission, mock_membership, mock_group, mock_make_db_connection
):
    """Test user_has_permission method returning False"""
    mock_conn = Mock()
    mock_make_db_connection.return_value = mock_conn

    auth = Authorization("test_client")

    # Set up mock membership object
    mock_membership_instance = Mock()
    auth.membership_model = mock_membership_instance
    mock_membership_instance.get_groups.return_value = [{"id": 1, "role": "admin"}]

    with patch.object(auth, "has_permission") as mock_has_permission:
        mock_has_permission.return_value = False

        result = auth.user_has_permission("user1", "read")

        assert result is False
