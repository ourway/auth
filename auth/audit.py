"""
Audit logging for the authorization system
"""

import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text

from auth.database import SessionLocal
from auth.models.sql import Base


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

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    client_id = Column(String(64), index=True, nullable=False)
    user = Column(String(64), index=True)
    action = Column(String(50), nullable=False)
    resource = Column(String(100))
    details = Column(Text)  # JSON string of additional details
    ip_address = Column(String(45))  # Support for IPv6
    user_agent = Column(String(500))
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
            client_id=client_id,
            user=user,
            action=action.value,
            resource=resource,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            user_agent=user_agent,
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
            "timestamp": datetime.utcnow().isoformat(),
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
