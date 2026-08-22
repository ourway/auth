"""Shared foundation for the authorization service.

Holds the state every part of :class:`~auth.services.service.AuthorizationService`
needs — the session, the tenant key, transaction ownership — plus the encryption
and dialect helpers the mixins build on. The service is assembled from a linear
chain of mixins rooted here; see :mod:`auth.services.service`.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from auth.encryption import encrypt_sensitive_data

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Naive UTC now — matches the DateTime columns (see auth.audit)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def validate_client_key(client: str) -> bool:
    """
    Validate that the client key is a valid UUID4
    """
    try:
        uuid_obj = uuid.UUID(client, version=4)
        return str(uuid_obj) == client.lower()
    except ValueError:
        return False


class ServiceBase:
    """Session, tenant identity and the helpers shared by every mixin."""

    def __init__(
        self,
        db: Session,
        client: str,
        validate_client: bool = True,
        manage_transaction: bool = True,
        strict_users: Optional[bool] = None,
    ):
        if validate_client and not validate_client_key(client):
            # Never echo the raw key (it is the credential) — it would land in
            # the traceback logger. Report only that validation failed.
            raise ValueError("Invalid client key: must be a valid UUID4.")
        self.db = db
        # Canonicalize the key: it is the tenant identifier and the per-tenant
        # encryption KDF input, so case variants must not fork the namespace.
        self.client = client.lower()
        self.validate_client = validate_client
        # When True (default; the in-process/library callers) each mutating
        # method commits its own transaction. The HTTP layer sets this False and
        # commits once itself, so the mutation and its audit row commit together.
        self.manage_transaction = manage_transaction
        # SPEC 0008/0010: None reads the tenant's stored setting (HTTP path);
        # an explicit bool overrides it for in-process/library callers.
        self._strict_override = strict_users
        self._strict_cache: Optional[bool] = None

    def _commit(self) -> None:
        """Commit only when this service owns the transaction (see __init__)."""
        if self.manage_transaction:
            self.db.commit()

    def _lock_tenant(self) -> None:
        """Serialize this tenant's writes against key rotation (PostgreSQL).

        A transaction-scoped advisory lock keyed on the tenant, so a rotation and
        a concurrent write — or a second rotation — for the same tenant cannot
        interleave. Rotation therefore sees a stable set of rows: none is
        stranded under the old key, and no concurrent update is clobbered by the
        re-encrypt/reassign pass. Auto-released at commit/rollback. On SQLite
        (single writer) it is unnecessary and skipped.
        """
        if self.db.get_bind().dialect.name == "postgresql":
            self.db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                {"k": self.client},
            )

    def _get_encrypted_user(self, user: str) -> str:
        """Get the encrypted version of a user string for database queries"""
        return encrypt_sensitive_data(user, self.client) or user

    def _get_encrypted_permission(self, name: str) -> str:
        """Get the encrypted version of a permission name for database queries"""
        return encrypt_sensitive_data(name, self.client) or name

    def _dialect_insert(self, table) -> Any:
        """INSERT construct with ON CONFLICT support for the bound dialect.

        The table objects carry the configured schema (settings.database_schema),
        so upserts follow the deployment's schema instead of a hardcoded name.
        """
        dialect = self.db.get_bind().dialect.name
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            return pg_insert(table)
        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            return sqlite_insert(table)
        raise NotImplementedError(f"Upserts not supported on dialect {dialect!r}")
