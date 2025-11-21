__author__ = "Farshid Ashouri"
from typing import Optional

from auth.client import Client, EnhancedAuthClient  # Import the new client
from auth.database import SessionLocal
from auth.services.service import AuthorizationService


# Lazy import for Flask app to avoid immediate initialization
def _get_app():
    from auth.main import app

    return app


# Access app through lazy function
def get_app():
    """Get the Flask app instance. This avoids immediate initialization issues."""
    return _get_app()


app = get_app
api = app


# Compatibility wrapper for old tests
class Authorization:
    """Compatibility wrapper for old Authorization interface"""

    def __init__(self, client: str, db_session=None):
        self.client = client
        # Use provided session or create a new one
        self.db = db_session if db_session else SessionLocal()
        # Use legacy mode (no client validation) for backward compatibility
        self.service = AuthorizationService(self.db, client, validate_client=False)

    @property
    def roles(self):
        return self.service.get_roles()

    def add_role(self, role: str, description: Optional[str] = None) -> bool:
        return self.service.add_role(role, description)

    def del_role(self, role: str) -> bool:
        return self.service.del_role(role)

    def add_permission(self, role: str, name: str) -> bool:
        return self.service.add_permission(role, name)

    def del_permission(self, role: str, name: str) -> bool:
        return self.service.del_permission(role, name)

    def has_permission(self, role: str, name: str) -> bool:
        return self.service.has_permission(role, name)

    def get_permissions(self, role: str):
        return self.service.get_permissions(role)

    def add_membership(self, user: str, role: str) -> bool:
        return self.service.add_membership(user, role)

    def del_membership(self, user: str, role: str) -> bool:
        return self.service.del_membership(user, role)

    def has_membership(self, user: str, role: str) -> bool:
        return self.service.has_membership(user, role)

    def user_has_permission(self, user: str, name: str) -> bool:
        return self.service.user_has_permission(user, name)

    def get_user_permissions(self, user: str):
        return self.service.get_user_permissions(user)

    def get_user_roles(self, user: str):
        return self.service.get_user_roles(user)

    def get_role_members(self, role: str):
        return self.service.get_role_members(role)

    def which_roles_can(self, name: str):
        return self.service.which_roles_can(name)

    def which_users_can(self, name: str):
        return self.service.which_users_can(name)


# Export the new client for users who want enhanced features
__all__ = ["Authorization", "Client", "EnhancedAuthClient", "SessionLocal"]
