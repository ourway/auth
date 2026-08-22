"""Shared plumbing for the route modules: session ownership and tenant binding."""

import logging
from functools import wraps

from flask import abort, g

from auth.database import get_db
from auth.services.service import AuthorizationService

logger = logging.getLogger(__name__)


def with_db_session(route_func):
    """Provide a request-scoped DB session and own its single transaction.

    The route (and the ``@audit_log`` decorator it wraps) do their work on this
    session WITHOUT committing; this wrapper commits once at the end, so a
    mutation and its audit row land in the same transaction — either both commit
    or both roll back. Any exception rolls the whole thing back.
    """

    @wraps(route_func)  # Preserve function metadata to avoid Flask endpoint conflicts
    def wrapper(*args, **kwargs):
        with get_db() as db:
            try:
                result = route_func(db, *args, **kwargs)
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    return wrapper


def _get_auth_service(db):
    """Return a tenant-scoped auth service for the current request.

    Authentication (Bearer header parsing + UUID4 validation) is performed once,
    up front, by the ``_authenticate_api`` ``before_request`` hook registered in
    ``register_routes``, which stores the validated client key on ``g``. This
    helper only binds that key to the request's database session.
    """
    client_key = getattr(g, "client_key", None)
    if not client_key:
        # Reached only if a route outside the /api/* gate calls this helper.
        abort(401, description="Authorization required.")
    # manage_transaction=False: the mutation is committed once by
    # ``with_db_session``, together with the audit row (see that wrapper).
    return AuthorizationService(
        db, client_key, validate_client=True, manage_transaction=False
    )


def _strict_reason(auth_service, user):
    """Additive reason for negative answers under strict user identity.

    Computed only on negative paths; None whenever strict mode is off or
    the user is key-backed (i.e. the negative is a genuine denial).
    """
    if auth_service.strict_users_enabled() and not auth_service.user_is_key_backed(
        user
    ):
        return "user_not_key_backed"
    return None
