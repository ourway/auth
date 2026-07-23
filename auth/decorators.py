from functools import wraps

from flask import Response, g, request

from auth.audit import AuditAction, client_fingerprint, log_audit_event
from auth.config import get_settings


def _status_code(response) -> int:
    """Best-effort HTTP status of a Flask view return value."""
    if isinstance(response, Response):
        return response.status_code
    if isinstance(response, tuple) and len(response) >= 2 and isinstance(
        response[1], int
    ):
        return response[1]
    return 200


def audit_log(action: AuditAction, resource_extractor=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not get_settings().enable_audit_logging:
                return func(*args, **kwargs)

            # ``before_request`` has already authenticated every /api/* request
            # and stored the validated client key on ``g``. We record only a
            # non-reversible fingerprint of it — never the raw key, which is the
            # caller's credential.
            client_ref = client_fingerprint(getattr(g, "client_key", None))
            user = kwargs.get("user")
            resource = resource_extractor(kwargs) if resource_extractor else None

            try:
                response = func(*args, **kwargs)
                status_code = _status_code(response)
                log_audit_event(
                    client_id=client_ref,
                    user=user,
                    action=action,
                    resource=resource,
                    details={"status_code": status_code},
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                    success=200 <= status_code < 400,
                )
                return response
            except Exception as e:
                log_audit_event(
                    client_id=client_ref,
                    user=user,
                    action=action,
                    resource=resource,
                    details={"error": str(e)},
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                    success=False,
                )
                raise

        return wrapper

    return decorator
