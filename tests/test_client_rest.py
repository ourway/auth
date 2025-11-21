from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError

from auth.core.REST.client import (
    Client,
    connect,
    connection_factory,
)


def test_connect_get():
    """Test connect function with GET method"""
    with patch("requests.get") as mock_get:
        mock_response = Mock()
        mock_response.content = b'{"test": "data"}'
        mock_get.return_value = mock_response

        test_headers = {"Authorization": "Bearer test"}
        result = connect("http://example.com", "get", headers=test_headers)
        assert result == mock_response
        mock_get.assert_called_once_with("http://example.com", headers=test_headers)


def test_connect_post():
    """Test connect function with POST method"""
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.content = b'{"test": "data"}'
        mock_post.return_value = mock_response

        test_headers = {"Authorization": "Bearer test"}
        result = connect("http://example.com", "post", headers=test_headers)
        assert result == mock_response
        mock_post.assert_called_once_with("http://example.com", headers=test_headers)


def test_connect_delete():
    """Test connect function with DELETE method"""
    with patch("requests.delete") as mock_delete:
        mock_response = Mock()
        mock_response.content = b'{"test": "data"}'
        mock_delete.return_value = mock_response

        test_headers = {"Authorization": "Bearer test"}
        result = connect("http://example.com", "delete", headers=test_headers)
        assert result == mock_response
        mock_delete.assert_called_once_with("http://example.com", headers=test_headers)


def test_connect_connection_error():
    """Test connect function handling connection error"""
    with patch("requests.get", side_effect=ConnectionError("Service Down")):
        with pytest.raises(ConnectionError, match="Service Down"):
            connect("http://example.com", "get")


def test_connection_factory():
    """Test connection_factory function"""

    class MockClass:
        api_key = "test_key"
        service_url = "http://example.com"

    # Create a mock function through factory
    func = connection_factory(MockClass, "/api/test/{user}", "get")

    # Check that the function has correct docstring
    assert "This function will call" in func.__doc__
    assert "/api/test/{user}" in func.__doc__
    assert "GET" in func.__doc__


def test_connection_factory_missing_args():
    """Test connection_factory function handling missing arguments"""

    class MockClass:
        api_key = "test_key"
        service_url = "http://example.com"

    func = connection_factory(MockClass, "/api/test/{user}/{group}", "get")

    with pytest.raises(AssertionError, match="I need"):
        func(user="test_user")  # Missing 'group' argument


def test_connection_factory_full_functionality():
    """Test connection_factory creates a working function"""

    class MockClass:
        api_key = "test_key"
        service_url = "http://example.com"

    with patch("auth.core.REST.client.connect") as mock_connect:
        # Create a mock response
        mock_response = Mock()
        mock_response.content = b'{"result": true}'
        mock_connect.return_value = mock_response

        func = connection_factory(MockClass, "/api/test/{user}", "get")
        result = func(user="test_user")

        # Check the URL was constructed correctly
        expected_url = "http://example.com/api/test/test_user"
        mock_connect.assert_called_with(
            expected_url, "get", headers={"Authorization": "Bearer test_key"}
        )

        # Check the result was parsed from JSON
        assert result == {"result": True}


def test_client_creation():
    """Test Client class creation"""
    client = Client("test_api_key", "http://example.com")

    assert client.api_key == "test_api_key"
    assert client.service_url == "http://example.com"


def test_client_dynamic_methods():
    """Test Client class dynamic method creation"""
    client = Client("test_api_key", "http://example.com")

    # Check if methods were dynamically created
    methods_to_check = [
        "get_ping",
        "add_membership",
        "remove_membership",
        "get_membership",
        "add_permission",
        "remove_permission",
        "get_permission",
        "get_has_permission",
        "get_user_permissions",
        "get_role_permissions",
        "get_user_roles",
        "get_members",
        "add_role",
        "remove_role",
        "get_roles",
        "get_which_roles_can",
        "get_which_users_can",
    ]

    for method in methods_to_check:
        assert hasattr(client, method)


def test_client_repr():
    """Test Client class representation"""
    client = Client("test_api_key", "http://example.com")

    # The client class has dynamically created methods, so repr should work
    repr_output = repr(client)
    assert "Methods:" in repr_output
    # Should contain methods starting with get, add (which is post), or remove (which is delete)
    assert any(
        method_name in repr_output
        for method_name in [
            "get_ping",
            "post_membership",
            "get_user_permissions",
            "get_user_roles",
        ]
    )
