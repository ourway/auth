from functools import wraps
from typing import Any, Optional

from flask import Response, g, request

from auth.audit import (
    AuditAction,
    client_fingerprint,
    log_audit_event,
    record_audit,
)
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


def _response_body(response) -> Any:
    """Best-effort decoded JSON body of a Flask view return value."""
    obj = response
    if isinstance(response, tuple) and response:
        obj = response[0]
    if isinstance(obj, Response):
        return obj.get_json(silent=True)
    return None


def _derive_success(response) -> bool:
    """Whether the operation actually took effect — not merely whether HTTP was
    2xx.

    Write endpoints return HTTP 200 with ``{"result": false}`` (bare) or
    ``{"data": {"result": false}}`` (wrapped) when the write did nothing (e.g. a
    missing role). Recording those as ``success`` would let the audit trail claim
    a grant happened when it did not, so pull the real boolean out. Read
    endpoints (e.g. a permission check answering ``has_permission: false``) have
    no ``result`` field and are treated as successful — the query succeeded.
    """
    status_code = _status_code(response)
    if not (200 <= status_code < 400):
        return False
    body = _response_body(response)
    if isinstance(body, dict):
        result = body.get("result")
        if isinstance(result, bool):
            return result
        data = body.get("data")
        if isinstance(data, dict):
            inner = data.get("result")
            if isinstance(inner, bool):
                return inner
    return True


def _request_db(args) -> Optional[Any]:
    """The request session injected by ``with_db_session`` as the first arg."""
    return args[0] if args else None


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
            db = _request_db(args)

            try:
                response = func(*args, **kwargs)
            except Exception as e:
                # The request transaction is being rolled back, so the audit row
                # must NOT ride on it — write it on its own session so the failed
                # attempt is still recorded.
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

            status_code = _status_code(response)
            success = _derive_success(response)
            # Stage the audit row on the SAME session as the mutation; the
            # ``with_db_session`` wrapper commits both together. If this raises,
            # the whole request fails closed rather than committing an unaudited
            # mutation.
            record_audit(
                db,
                client_id=client_ref,
                user=user,
                action=action,
                resource=resource,
                details={"status_code": status_code},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=success,
            )
            return response

        return wrapper

    return decorator
