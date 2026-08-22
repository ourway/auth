"""
SQLAlchemy-based authorization service

The implementation is split across a linear chain of mixins — see
:mod:`auth.services.base`, :mod:`auth.services.tenant`,
:mod:`auth.services.queries`, :mod:`auth.services.rbac`,
:mod:`auth.services.keys` and :mod:`auth.services.rotation`. This module stays
the public import path: ``from auth.services.service import
AuthorizationService`` resolves exactly as it did before the split.
"""

from auth.api_keys import generate_api_key, hash_api_key

# Re-exported so every name that resolved through this module before the split
# still resolves through it. The models and helpers below are imported by the
# mixins, not defined here; a consumer doing
# ``from auth.services.service import AuthApiKey`` predates the split and must
# keep working.
from auth.audit import AuditLog, client_fingerprint
from auth.encryption import encrypt_sensitive_data
from auth.models.sql import (
    AuthApiKey,
    AuthGroup,
    AuthMembership,
    AuthPermission,
    AuthTenantSettings,
    membership_groups,
    permission_groups,
)
from auth.services.base import (
    ServiceBase,
    _utcnow,
    logger,
    validate_client_key,
)
from auth.services.keys import (
    _LAST_USED_THROTTLE_SECONDS,
    API_KEYS_PER_USER_CAP,
    ApiKeyMixin,
)
from auth.services.queries import QueryMixin
from auth.services.rbac import RbacMixin
from auth.services.rotation import RotationMixin
from auth.services.tenant import TenantMixin


class AuthorizationService(RotationMixin):
    """Authorization service using SQLAlchemy"""


__all__ = [
    "API_KEYS_PER_USER_CAP",
    "ApiKeyMixin",
    "AuditLog",
    "AuthApiKey",
    "AuthGroup",
    "AuthMembership",
    "AuthPermission",
    "AuthTenantSettings",
    "AuthorizationService",
    "QueryMixin",
    "RbacMixin",
    "RotationMixin",
    "ServiceBase",
    "TenantMixin",
    "_LAST_USED_THROTTLE_SECONDS",
    "_utcnow",
    "client_fingerprint",
    "encrypt_sensitive_data",
    "generate_api_key",
    "hash_api_key",
    "logger",
    "membership_groups",
    "permission_groups",
    "validate_client_key",
]
