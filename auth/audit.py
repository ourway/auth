"""
Audit logging for the authorization system
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text

from auth.config import get_settings
from auth.database import SessionLocal
from auth.models.sql import _SCHEMA, Base


def _utcnow() -> datetime:
    """Naive UTC now — same values datetime.utcnow() produced, no deprecation."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AuditAction(Enum):
    """Enumeration of audit actions"""

    CREATE_ROLE = "CREATE_ROLE"
    DELETE_ROLE = "DELETE_ROLE"
    ADD_PERMISSION = "ADD_PERMISSION"
    REMOVE_PERMISSION = "REMOVE_PERMISSION"
    ADD_MEMBERSHIP = "ADD_MEMBERSHIP"
    REMOVE_MEMBERSHIP = "REMOVE_MEMBERSHIP"
    CHECK_PERMISSION = "CHECK_PERMISSION"
    CHECK_MEMBERSHIP = "CHECK_MEMBERSHIP"
    LIST_ROLES = "LIST_ROLES"
    LIST_PERMISSIONS = "LIST_PERMISSIONS"
    LIST_MEMBERSHIPS = "LIST_MEMBERSHIPS"
    USER_PERMISSIONS = "USER_PERMISSIONS"
    ROTATE_KEY = "ROTATE_KEY"
    CREATE_API_KEY = "CREATE_API_KEY"
    LIST_API_KEYS = "LIST_API_KEYS"
    REVOKE_API_KEY = "REVOKE_API_KEY"
    VALIDATE_API_KEY = "VALIDATE_API_KEY"
    CHECK_API_KEY_PERMISSION = "CHECK_API_KEY_PERMISSION"
    GET_SETTINGS = "GET_SETTINGS"
    UPDATE_SETTINGS = "UPDATE_SETTINGS"


class AuditLog(Base):
    """Audit log model"""

    __tablename__ = "audit_log"
    # Follows database_schema like the RBAC tables. Existing deployments that
    # created audit_log in the default schema can move it with:
    #   ALTER TABLE audit_log SET SCHEMA <schema>;
    __table_args__ = {"schema": _SCHEMA}

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=_utcnow, nullable=False)
    client_id = Column(Text, index=True, nullable=False)
    user = Column(String(64), index=True)
    action = Column(String(50), nullable=False)
    resource = Column(Text)
    details = Column(Text)  # JSON string of additional details
    ip_address = Column(String(45))  # Support for IPv6
    user_agent = Column(Text)
    success = Column(Integer)  # 1 for success, 0 for failure


# Set up audit logger
audit_logger = logging.getLogger("auth.audit")
audit_logger.setLevel(logging.INFO)

# Create a handler for audit logs
if not audit_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - AUDIT - %(message)s")
    handler.setFormatter(formatter)
    audit_logger.addHandler(handler)


# Column widths of the audit_log table (see AuditLog above). Values are clamped
# to these before insert so an over-length field — an attacker-controlled
# User-Agent, or an oversized Authorization header — can never abort the INSERT
# and silently drop the whole audit row on PostgreSQL. Phase C widens these
# columns to TEXT and relaxes the clamp.
_AUDIT_MAXLEN = {
    "client_id": 64,
    "user": 64,
    "action": 50,
    "resource": 100,
    "ip_address": 45,
    "user_agent": 500,
}


def _fit(value: Optional[str], column: str) -> Optional[str]:
    """Clamp a value to its audit column width (no-op for None)."""
    if value is None:
        return None
    return str(value)[: _AUDIT_MAXLEN[column]]


def client_fingerprint(token: Optional[str]) -> str:
    """A stable, non-reversible reference for a client key — safe to store and
    log in place of the raw key.

    HMAC-SHA256 under a server-side pepper, so reading the audit log neither
    reveals the key nor lets an attacker confirm a guessed key offline without
    also holding the pepper. The pepper is ``AUTH_AUDIT_PEPPER`` and falls back
    to the JWT secret so it is never unsalted.
    """
    if not token:
        return "anonymous"
    settings = get_settings()
    pepper = (settings.audit_pepper or settings.jwt_secret_key or "auth").encode()
    digest = hmac.new(pepper, token.encode(), hashlib.sha256).hexdigest()
    return "fpr_" + digest[:32]


def _build_audit_entry(
    client_id: str,
    user: Optional[str],
    action: AuditAction,
    resource: Optional[str],
    details: Optional[Dict[str, Any]],
    ip_address: Optional[str],
    user_agent: Optional[str],
    success: bool,
) -> "AuditLog":
    # The managed user is a human identifier (often an email) — store a
    # non-reversible fingerprint, never plaintext, matching how the client key is
    # handled. Auditors correlate by fingerprint and can confirm a known user by
    # computing its fingerprint. Role/permission/workflow names (the `resource`)
    # are application identifiers, not PII, and stay readable — except the caller
    # is responsible for fingerprinting any user embedded in `resource`.
    user_fp = client_fingerprint(user) if user else None
    return AuditLog(
        client_id=_fit(client_id, "client_id"),
        user=_fit(user_fp, "user"),
        action=_fit(action.value, "action"),
        resource=_fit(resource, "resource"),
        details=json.dumps(details) if details else None,
        ip_address=_fit(ip_address, "ip_address"),
        user_agent=_fit(user_agent, "user_agent"),
        success=1 if success else 0,
    )


def _emit_structured_log(
    client_id: str,
    user: Optional[str],
    action: AuditAction,
    resource: Optional[str],
    details: Optional[Dict[str, Any]],
    ip_address: Optional[str],
    success: bool,
) -> None:
    # The DB row is the system of record. The log STREAM (journald / SIEM /
    # shipping) is more widely exposed, so it carries no PII: no raw user and no
    # resource string (which may embed a user). Only the non-reversible client
    # fingerprint, the action, and the outcome.
    log_msg: Dict[str, Any] = {
        "type": "audit",
        "client_id": client_id,
        "action": action.value,
        "success": success,
        "timestamp": _utcnow().isoformat(),
    }
    if details:
        log_msg["details"] = details
    if ip_address:
        log_msg["ip"] = ip_address
    audit_logger.info(json.dumps(log_msg))


def record_audit(
    session,
    *,
    client_id: str,
    user: Optional[str],
    action: AuditAction,
    resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
) -> None:
    """Add an audit row to an EXISTING session so it commits atomically with the
    caller's transaction (the mutation and its audit land together, or not at
    all). The caller is responsible for committing.

    This does NOT swallow errors: a failure to stage the audit row must fail the
    surrounding request (fail-closed), never leave a committed mutation
    unaudited.
    """
    session.add(
        _build_audit_entry(
            client_id, user, action, resource, details, ip_address, user_agent, success
        )
    )
    _emit_structured_log(client_id, user, action, resource, details, ip_address, success)


def log_audit_event(
    client_id: str,
    user: Optional[str],
    action: AuditAction,
    resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
) -> None:
    """Write an audit event on its OWN committed session.

    For contexts with no request transaction to join: in-process/library
    callers, and the *failure* path of the request decorator (where the request
    transaction is being rolled back and must not carry the audit row). This one
    is best-effort — a failure is logged, not raised, so it cannot mask the
    original error it is recording.
    """
    session = SessionLocal()
    try:
        session.add(
            _build_audit_entry(
                client_id, user, action, resource, details, ip_address, user_agent, success
            )
        )
        session.commit()
        _emit_structured_log(
            client_id, user, action, resource, details, ip_address, success
        )
    except Exception:
        audit_logger.error(
            f"Failed to log audit event: client_id={client_id}, action={action.value}"
        )
        session.rollback()
    finally:
        session.close()


def setup_audit_tables():
    """Create audit log table if it doesn't exist"""
    from auth.database import engine

    Base.metadata.create_all(bind=engine, tables=[AuditLog.__table__])  # type: ignore[list-item]
