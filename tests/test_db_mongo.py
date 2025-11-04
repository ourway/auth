import os
from unittest.mock import Mock, patch

import pytest
from mongoengine.errors import NotUniqueError

from auth.CAS.models.db import (
    AuthGroup,
    AuthMembership,
    AuthPermission,
    make_db_connection,
)


@patch("auth.CAS.models.db.connect")
def test_make_db_connection(mock_connect):
    """Test make_db_connection function with default settings"""
    make_db_connection()

    # Verify connect was called with the correct parameters
    mock_connect.assert_called_once_with(
        "Authorization_0x0199", host="127.0.0.1", port=27017
    )


@patch("auth.CAS.models.db.connect")
def test_make_db_connection_with_env_vars(mock_connect):
    """Test make_db_connection function with environment variables"""
    # Test with custom environment variables
    with patch.dict(os.environ, {"MONGO_HOST": "localhost", "MONGO_PORT": "27018"}):
        make_db_connection()

        # Verify connect was called with the correct parameters from env vars
        mock_connect.assert_called_with(
            "Authorization_0x0199", host="localhost", port=27018
        )


def test_auth_group_repr():
    """Test AuthGroup __repr__ method"""
    group = AuthGroup(creator="test", role="admin")
    repr_str = repr(group)

    assert "AuthGroup:" in repr_str
    assert "<admin>" in repr_str


def test_auth_membership_repr():
    """Test AuthMembership __repr__ method"""
    membership = AuthMembership(user="test_user", creator="test")
    repr_str = repr(membership)

    assert "AuthMembership:" in repr_str
    assert "<test_user>" in repr_str


def test_auth_permission_repr():
    """Test AuthPermission __repr__ method"""
    permission = AuthPermission(name="read", creator="test")
    repr_str = repr(permission)

    assert "AuthPermission:" in repr_str
    assert "<read>" in repr_str
