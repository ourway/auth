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
    """
    Log an audit event to the database and to structured logs
    """
    session = SessionLocal()
    try:
        # Create audit log entry
        audit_entry = AuditLog(
            client_id=_fit(client_id, "client_id"),
            user=_fit(user, "user"),
            action=_fit(action.value, "action"),
            resource=_fit(resource, "resource"),
            details=json.dumps(details) if details else None,
            ip_address=_fit(ip_address, "ip_address"),
            user_agent=_fit(user_agent, "user_agent"),
            success=1 if success else 0,
        )

        session.add(audit_entry)
        session.commit()

        # Also log to structured logger
        log_msg: Dict[str, Any] = {
            "type": "audit",
            "client_id": client_id,
            "user": user,
            "action": action.value,
            "resource": resource,
            "success": success,
            "timestamp": _utcnow().isoformat(),
        }
        if details:
            log_msg["details"] = details
        if ip_address:
            log_msg["ip"] = ip_address

        audit_logger.info(json.dumps(log_msg))
    except Exception:
        # If audit logging fails, we don't want to break the main operation
        # But log the failure for monitoring
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
