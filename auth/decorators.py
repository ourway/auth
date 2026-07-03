
from functools import wraps

from flask import Response, request

from auth.audit import AuditAction, log_audit_event


def _extract_client_id() -> str:
    """Best-effort client id from the Authorization header for audit rows."""
    header = request.headers.get("Authorization", "")
    parts = header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return header or "unknown"


def audit_log(action: AuditAction, resource_extractor=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_id = _extract_client_id()
            user = kwargs.get("user")
            resource = resource_extractor(kwargs) if resource_extractor else None

            try:
                response = func(*args, **kwargs)
                if isinstance(response, Response):
                    status_code = response.status_code
                elif isinstance(response, tuple):
                    status_code = response[1]
                else:
                    status_code = 200
                log_audit_event(
                    client_id=client_id,
                    user=user,
                    action=action,
                    resource=resource,
                    details={"status_code": status_code},
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                    success=True
                )
                return response
            except Exception as e:
                log_audit_event(
                    client_id=client_id,
                    user=user,
                    action=action,
                    resource=resource,
                    details={"error": str(e)},
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                    success=False
                )
                raise

        return wrapper
    return decorator
