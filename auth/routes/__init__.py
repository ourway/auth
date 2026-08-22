"""
Flask routes for authorization service

The handlers are grouped by resource across the sibling modules; this package
stays the public import path, so ``from auth.routes import register_routes``
resolves exactly as it did before the split.
"""

from auth.routes import (
    apikeys,
    membership,
    permissions,
    public,
    roles,
    tenant,
    workflow,
)
from auth.routes._common import (
    _get_auth_service,
    _strict_reason,
    logger,
    with_db_session,
)

# Registration order does not affect matching — Werkzeug sorts the map by
# specificity — but it keeps `flask routes` output grouped the way the modules
# are, with the public gate first.
_ROUTE_MODULES = (
    public,
    membership,
    permissions,
    roles,
    workflow,
    apikeys,
    tenant,
)


def register_routes(app):
    """Register all routes with the Flask app"""
    for module in _ROUTE_MODULES:
        module.register(app)


__all__ = [
    "_get_auth_service",
    "_strict_reason",
    "logger",
    "register_routes",
    "with_db_session",
]
