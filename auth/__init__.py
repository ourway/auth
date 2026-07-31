__author__ = "Farshid Ashouri"

from importlib.metadata import PackageNotFoundError, version
from typing import Optional

from auth.client import (  # Import the new client
    AuthTransportError,
    Client,
    EnhancedAuthClient,
)
from auth.database import SessionLocal
from auth.services.service import AuthorizationService

try:
    __version__ = version("auth")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.0.0.dev0"


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

    def __init__(
        self,
        client: str,
        db_session=None,
        strict_users: Optional[bool] = None,
    ):
        # Constructing this wrapper means running auth embedded, against a real
        # database — the one embedded path that never goes through create_app.
        # Weak server secrets are actionable here; on a bare `import auth` by a
        # client-only consumer they are not, which is why they are not emitted
        # at import time (issuedb #20).
        from auth.config import get_settings, warn_on_weak_secrets

        warn_on_weak_secrets(get_settings())

        self.client = client
        # Use provided session or create a new one
        self.db = db_session if db_session else SessionLocal()
        # Use legacy mode (no client validation) for backward compatibility.
        # strict_users: None reads the tenant's stored setting (identical
        # semantics to the REST layer); an explicit bool pins it per instance.
        self.service = AuthorizationService(
            self.db, client, validate_client=False, strict_users=strict_users
        )

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

    # Tenant settings & strict user identity (SPEC 0010) — embedded consumers
    # get the same semantics the REST layer serves.
    def get_settings(self):
        return self.service.get_settings()

    def set_strict_users(self, enabled: bool):
        return self.service.set_strict_users(enabled)

    # Per-user API keys (SPEC 0004)
    def create_api_key(self, user: str, label: Optional[str] = None):
        return self.service.create_api_key(user, label)

    def list_api_keys(self, user: str):
        return self.service.list_api_keys(user)

    def revoke_api_key(self, user: str, key_id: str):
        return self.service.revoke_api_key(user, key_id)

    def validate_api_key(self, api_key: str):
        return self.service.validate_api_key(api_key)

    def check_api_key_permission(self, api_key: str, permission: str):
        return self.service.check_api_key_permission(api_key, permission)


# Export the new client for users who want enhanced features
__all__ = [
    "Authorization",
    "AuthTransportError",
    "Client",
    "EnhancedAuthClient",
    "SessionLocal",
    "__version__",
]
