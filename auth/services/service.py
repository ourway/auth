"""
SQLAlchemy-based authorization service
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, cast

from sqlalchemy import Table, func, select, text, update
from sqlalchemy.orm import Session

from auth.api_keys import generate_api_key, hash_api_key
from auth.audit import client_fingerprint
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

logger = logging.getLogger(__name__)

# Active per-user API keys allowed per (tenant, user) — bounds namespace abuse
# while staying far above any legitimate "one key per device/CI job" usage.
API_KEYS_PER_USER_CAP = 25

# A validate only rewrites last_used_at when it is at least this stale, so the
# hot path does at most one row-update per key per window.
_LAST_USED_THROTTLE_SECONDS = 60


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


class AuthorizationService:
    """Authorization service using SQLAlchemy"""

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

    def get_roles(self) -> List[Dict[str, Any]]:
        """Get all roles for the client"""
        groups = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.is_active)
            .all()
        )
        return [
            {"role": group.role, "description": group.description} for group in groups
        ]

    def get_permissions(self, role: str) -> List[Dict[str, Any]]:
        """Get permissions for a role"""
        group = (
            self.db.query(AuthGroup)
            .filter(
                AuthGroup.creator == self.client,
                AuthGroup.role == role,
                AuthGroup.is_active,
            )
            .first()
        )

        if not group:
            return []

        permissions = group.permissions
        return [{"name": perm.name} for perm in permissions if perm.is_active]

    def get_user_permissions(self, user: str) -> List[Dict[str, Any]]:
        """Get all permissions for a user"""
        if self._strict_blocks(user):
            return []
        membership = (
            self.db.query(AuthMembership)
            .filter(
                AuthMembership.creator == self.client,
                AuthMembership._user == self._get_encrypted_user(user),
                AuthMembership.is_active,
            )
            .first()
        )

        if not membership:
            return []

        results = []
        for group in membership.groups:
            if group.is_active:
                for permission in group.permissions:
                    if permission.is_active:
                        results.append({"name": permission.name})
        return results

    def get_user_roles(self, user: str) -> List[Dict[str, Any]]:
        """Get all roles for a user"""
        membership = (
            self.db.query(AuthMembership)
            .filter(
                AuthMembership.creator == self.client,
                AuthMembership._user == self._get_encrypted_user(user),
                AuthMembership.is_active,
            )
            .first()
        )

        if not membership:
            return []

        # Return membership format (user, role) for user_roles endpoint
        return [
            {"user": membership.user, "role": group.role}
            for group in membership.groups
            if group.is_active
        ]

    def get_role_members(self, role: str) -> List[Dict[str, Any]]:
        """Get all members of a role"""
        group = (
            self.db.query(AuthGroup)
            .filter(
                AuthGroup.creator == self.client,
                AuthGroup.role == role,
                AuthGroup.is_active,
            )
            .first()
        )

        if not group:
            return []

        members = []
        for membership in group.memberships:
            if membership.is_active:
                # Return membership format (user, role) for members endpoint
                members.append({"user": membership.user, "role": group.role})
        return members

    def which_roles_can(self, name: str) -> List[Dict[str, Any]]:
        """Get roles that have a specific permission"""
        permission = (
            self.db.query(AuthPermission)
            .filter(
                AuthPermission.creator == self.client,
                AuthPermission._name == self._get_encrypted_permission(name),
                AuthPermission.is_active,
            )
            .first()
        )

        if not permission:
            return []

        return [{"role": group.role} for group in permission.groups if group.is_active]

    def which_users_can(self, name: str) -> List[Dict[str, Any]]:
        """Get users that have a specific permission"""
        roles = self.which_roles_can(name)
        result = []
        for role_dict in roles:
            members = self.get_role_members(role_dict["role"])
            result.extend(members)
        return result

    def add_role(self, role: str, description: Optional[str] = None) -> bool:
        """Add a new role - atomic idempotent upsert.

        Uses INSERT ... ON CONFLICT (PostgreSQL and SQLite) for a
        race-condition-free upsert. The unique constraint (creator, role)
        ensures atomicity.
        """
        self._lock_tenant()
        try:
            table = AuthGroup.__table__
            # Mirror the AuthGroup.description setter: store encrypted.
            encrypted_description = (
                encrypt_sensitive_data(description, self.client)
                if description
                else description
            )
            stmt = self._dialect_insert(table).values(
                creator=self.client,
                role=role,
                description=encrypted_description,
                is_active=True,
                date_created=func.now(),
                modified=func.now(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["creator", "role"],
                set_={
                    "is_active": True,
                    "description": func.coalesce(
                        stmt.excluded.description, table.c.description
                    ),
                    "modified": func.now(),
                },
            )
            self.db.execute(stmt)
            self._commit()
            return True
        except Exception:
            logger.exception(
                "add_role failed (client=%s, role=%r)",
                client_fingerprint(self.client),
                role,
            )
            self.db.rollback()
            # Do not mask a real DB failure as a legitimate False — re-raise so
            # the request becomes a 500 and the audit records the failure.
            raise

    def del_role(self, role: str) -> bool:
        """Delete a role and PURGE its grants.

        The group row is soft-deleted, and its membership/permission links are
        removed so the grants cannot come back. Without the purge, re-creating a
        role with the same name silently restored every previous member and
        permission — a privilege-restoration hazard, since deleting a role is
        how callers revoke access.

        Re-adding a role that is still live is untouched and remains idempotent:
        callers that bootstrap roles repeatedly keep their members. Only a
        delete purges.

        The user and permission rows themselves are not deleted — they are
        tenant-level entities that may still belong to other roles.
        """
        self._lock_tenant()
        group = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.role == role)
            .first()
        )

        if group and group.is_active:
            group.memberships.clear()
            group.permissions.clear()
            group.is_active = False  # type: ignore[assignment]
            self._commit()
            return True
        return False

    def add_membership(self, user: str, role: str) -> bool:
        """Add user to a role - atomic idempotent upsert.

        Uses INSERT ... ON CONFLICT (PostgreSQL and SQLite) for
        race-condition-free operations. Under strict user identity a user with
        no live API key cannot be granted membership (create the key first);
        removal is deliberately NOT strict-gated, so revocation always works.
        """
        if self._strict_blocks(user):
            return False
        self._lock_tenant()
        try:
            group_table = AuthGroup.__table__
            group_id = self.db.execute(
                select(group_table.c.id).where(
                    group_table.c.creator == self.client,
                    group_table.c.role == role,
                    group_table.c.is_active.is_(True),
                )
            ).scalar()
            if group_id is None:
                return False

            # Upsert membership
            encrypted_user = self._get_encrypted_user(user)
            m_table = AuthMembership.__table__
            stmt = self._dialect_insert(m_table).values(
                creator=self.client,
                user=encrypted_user,
                is_active=True,
                date_created=func.now(),
                modified=func.now(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["creator", "user"],
                set_={"is_active": True, "modified": func.now()},
            )
            self.db.execute(stmt)
            membership_id = self.db.execute(
                select(m_table.c.id).where(
                    m_table.c.creator == self.client,
                    m_table.c.user == encrypted_user,
                )
            ).scalar_one()

            # Link membership to group (junction table)
            link = (
                self._dialect_insert(membership_groups)
                .values(membership_id=membership_id, group_id=group_id)
                .on_conflict_do_nothing(index_elements=["membership_id", "group_id"])
            )
            self.db.execute(link)
            self._commit()
            return True
        except Exception:
            logger.exception(
                "add_membership failed (client=%s, role=%r)",
                client_fingerprint(self.client),
                role,
            )
            self.db.rollback()
            # Re-raise a real DB failure (a legitimate "role missing" already
            # returned False above) so it surfaces as 500 + a failed audit.
            raise

    def del_membership(self, user: str, role: str) -> bool:
        """Remove user from a role"""
        self._lock_tenant()
        if not self.has_membership(user, role):
            return True

        group = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.role == role)
            .first()
        )

        if not group:
            return True

        membership = (
            self.db.query(AuthMembership)
            .filter(AuthMembership.creator == self.client, AuthMembership._user == self._get_encrypted_user(user))
            .first()
        )

        if not membership:
            return True

        if group in membership.groups:
            membership.groups.remove(group)
            self._commit()

        return True

    def has_membership(self, user: str, role: str) -> bool:
        """Check if user is in a role"""
        membership = (
            self.db.query(AuthMembership)
            .filter(
                AuthMembership.creator == self.client,
                AuthMembership._user == self._get_encrypted_user(user),
                AuthMembership.is_active,
            )
            .first()
        )

        if not membership:
            return False

        return any(
            group.role == role and group.is_active for group in membership.groups
        )

    def add_permission(self, role: str, name: str) -> bool:
        """Add permission to a role - atomic idempotent upsert.

        Uses INSERT ... ON CONFLICT (PostgreSQL and SQLite) for
        race-condition-free operations.
        """
        self._lock_tenant()
        if self.has_permission(role, name):
            return True

        try:
            group_table = AuthGroup.__table__
            group_id = self.db.execute(
                select(group_table.c.id).where(
                    group_table.c.creator == self.client,
                    group_table.c.role == role,
                    group_table.c.is_active.is_(True),
                )
            ).scalar()
            if group_id is None:
                return False

            # Upsert permission
            encrypted_name = self._get_encrypted_permission(name)
            p_table = AuthPermission.__table__
            stmt = (
                self._dialect_insert(p_table)
                .values(
                    creator=self.client,
                    name=encrypted_name,
                    is_active=True,
                    date_created=func.now(),
                    modified=func.now(),
                )
                .on_conflict_do_update(
                    index_elements=["creator", "name"],
                    set_={"is_active": True, "modified": func.now()},
                )
            )
            self.db.execute(stmt)
            perm_id = self.db.execute(
                select(p_table.c.id).where(
                    p_table.c.creator == self.client,
                    p_table.c.name == encrypted_name,
                )
            ).scalar_one()

            # Link permission to group (junction table)
            link = (
                self._dialect_insert(permission_groups)
                .values(permission_id=perm_id, group_id=group_id)
                .on_conflict_do_nothing(index_elements=["permission_id", "group_id"])
            )
            self.db.execute(link)
            self._commit()
            return True
        except Exception:
            logger.exception(
                "add_permission failed (client=%s, role=%r, name=%r)",
                client_fingerprint(self.client),
                role,
                name,
            )
            self.db.rollback()
            # Re-raise a real DB failure (a legitimate "role missing" already
            # returned False above) so it surfaces as 500 + a failed audit.
            raise

    def del_permission(self, role: str, name: str) -> bool:
        """Remove permission from a role"""
        self._lock_tenant()
        if not self.has_permission(role, name):
            return True

        group = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.role == role)
            .first()
        )

        if not group:
            return True

        permission = (
            self.db.query(AuthPermission)
            .filter(AuthPermission.creator == self.client, AuthPermission._name == self._get_encrypted_permission(name))
            .first()
        )

        if not permission:
            return True

        if group in permission.groups:
            permission.groups.remove(group)
            self._commit()

        return True

    def has_permission(self, role: str, name: str) -> bool:
        """Check if role has permission"""
        group = (
            self.db.query(AuthGroup)
            .filter(
                AuthGroup.creator == self.client,
                AuthGroup.role == role,
                AuthGroup.is_active,
            )
            .first()
        )

        if not group:
            return False

        return any(perm.name == name and perm.is_active for perm in group.permissions)

    def user_has_permission(self, user: str, name: str) -> bool:
        """Check if user has permission"""
        if self._strict_blocks(user):
            return False
        membership = (
            self.db.query(AuthMembership)
            .filter(
                AuthMembership.creator == self.client,
                AuthMembership._user == self._get_encrypted_user(user),
                AuthMembership.is_active,
            )
            .first()
        )

        if not membership:
            return False

        for group in membership.groups:
            if group.is_active and self.has_permission(group.role, name):
                return True
        return False

    def check_api_key_permission(
        self, api_key: str, permission: str
    ) -> Dict[str, Any]:
        """Validate a secret and answer its subject's permission in one call.

        An invalid key returns the validate result unchanged; a valid key adds
        the effective-permission answer. The subject is key-backed by
        construction (this very key just validated), so strict mode never
        blocks the second half.
        """
        validated = self.validate_api_key(api_key)
        if not validated["valid"]:
            return validated
        user = cast(str, validated["user"])
        return {
            "valid": True,
            "user": user,
            "key_id": validated["key_id"],
            "has_permission": self.user_has_permission(user, permission),
        }

    # --- Tenant settings & strict user identity (SPEC 0008/0010) ---------

    def strict_users_enabled(self) -> bool:
        """Whether strict user identity applies to this tenant.

        Explicit constructor override wins; otherwise the tenant's stored
        setting is read once per service instance (one PK-adjacent lookup,
        cached for the request).
        """
        if self._strict_override is not None:
            return self._strict_override
        if self._strict_cache is None:
            row = (
                self.db.query(AuthTenantSettings)
                .filter(AuthTenantSettings.creator == self.client)
                .first()
            )
            if row is not None:
                self._strict_cache = bool(row.strict_users)
            else:
                # 3.0.0: tenants with no stored setting follow the server
                # default (strict). Pre-3.0 tenants never reach this branch —
                # grandfathering wrote them explicit false rows.
                from auth.config import get_settings

                self._strict_cache = bool(get_settings().strict_users_default)
        return self._strict_cache

    def get_settings(self) -> Dict[str, Any]:
        """This tenant's settings (defaults when no row exists)."""
        return {"strict_users": self.strict_users_enabled()}

    def set_strict_users(self, enabled: bool) -> Dict[str, Any]:
        """Upsert this tenant's strict_users flag (serialized vs rotation)."""
        self._lock_tenant()
        row = (
            self.db.query(AuthTenantSettings)
            .filter(AuthTenantSettings.creator == self.client)
            .first()
        )
        if row is None:
            row = AuthTenantSettings(creator=self.client, strict_users=enabled)
            self.db.add(row)
        else:
            row.strict_users = enabled  # type: ignore[assignment]
        self._strict_cache = enabled
        self._commit()
        return {"strict_users": enabled}

    def user_is_key_backed(self, user: str) -> bool:
        """True when the user holds ≥1 active, unexpired API key here."""
        row = (
            self.db.query(AuthApiKey.id)
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey._user == self._get_encrypted_user(user),
                AuthApiKey.is_active,
            )
            .filter(
                (AuthApiKey.expires_at.is_(None))
                | (AuthApiKey.expires_at > _utcnow())
            )
            .first()
        )
        return row is not None

    def _strict_blocks(self, user: str) -> bool:
        """Strict mode on AND the user has no live key → decision is negative."""
        return self.strict_users_enabled() and not self.user_is_key_backed(user)

    # --- Per-user API keys (SPEC 0004) -----------------------------------

    @staticmethod
    def _api_key_meta(row: AuthApiKey) -> Dict[str, Any]:
        """Listing/metadata view of a key row — never the hash or secret."""

        def iso(dt: Any) -> Optional[str]:
            return dt.isoformat() if dt else None

        return {
            "key_id": row.key_id,
            "key_prefix": row.key_prefix,
            "label": row.label,
            "is_active": bool(row.is_active),
            "created": iso(row.date_created),
            "revoked_at": iso(row.revoked_at),
            "expires_at": iso(row.expires_at),
            "last_used_at": iso(row.last_used_at),
        }

    def create_api_key(
        self, user: str, label: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Mint and store an API key for ``user`` in this tenant's namespace.

        Returns the one-time secret plus metadata, or ``None`` when the user
        already holds ``API_KEYS_PER_USER_CAP`` active keys. The tenant lock
        serializes against key rotation so the new row cannot strand under a
        creator that is being moved.
        """
        self._lock_tenant()
        active = (
            self.db.query(func.count(AuthApiKey.id))
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey._user == self._get_encrypted_user(user),
                AuthApiKey.is_active,
            )
            .scalar()
            or 0
        )
        if active >= API_KEYS_PER_USER_CAP:
            return None

        secret, key_id, key_hash, key_prefix = generate_api_key()
        row = AuthApiKey(
            key_id=key_id,
            creator=self.client,
            key_hash=key_hash,
            key_prefix=key_prefix,
            is_active=True,
        )
        row.user = user
        if label:
            row.label = label
        self.db.add(row)
        self.db.flush()
        self._commit()
        return {
            "api_key": secret,
            "key_id": key_id,
            "user": user,
            "label": label,
            "key_prefix": key_prefix,
            "created": row.date_created.isoformat() if row.date_created else None,
            "expires_at": None,
        }

    def list_api_keys(self, user: str) -> List[Dict[str, Any]]:
        """All of ``user``'s keys in this namespace, revoked ones included."""
        rows = (
            self.db.query(AuthApiKey)
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey._user == self._get_encrypted_user(user),
            )
            .order_by(AuthApiKey.id)
            .all()
        )
        return [self._api_key_meta(row) for row in rows]

    def revoke_api_key(self, user: str, key_id: str) -> Optional[str]:
        """Revoke ``key_id`` for ``user``.

        Returns ``"revoked"``, ``"already_revoked"`` (idempotent repeat), or
        ``None`` when no such row exists in this namespace — the route maps
        that to 404 without revealing whether the id exists elsewhere.
        """
        self._lock_tenant()
        row = (
            self.db.query(AuthApiKey)
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey.key_id == key_id.lower(),
                AuthApiKey._user == self._get_encrypted_user(user),
            )
            .first()
        )
        if row is None:
            return None
        if not row.is_active and row.revoked_at is not None:
            return "already_revoked"
        row.is_active = False  # type: ignore[assignment]
        row.revoked_at = _utcnow()  # type: ignore[assignment]
        self._commit()
        return "revoked"

    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """Resolve a presented secret within THIS tenant's namespace.

        Single unique-index probe on the hash. A key that exists under a
        different tenant answers exactly like one that does not exist, so a
        foreign tenant cannot probe key existence. Touches ``last_used_at``
        at most once per throttle window.
        """
        row = (
            self.db.query(AuthApiKey)
            .filter(AuthApiKey.key_hash == hash_api_key(api_key))
            .first()
        )
        if row is None or row.creator != self.client:
            return {"valid": False, "reason": "unknown_key"}
        if not row.is_active:
            return {"valid": False, "reason": "revoked"}
        now = _utcnow()
        if row.expires_at is not None and row.expires_at <= now:
            return {"valid": False, "reason": "expired"}
        if (
            row.last_used_at is None
            or (now - row.last_used_at).total_seconds() >= _LAST_USED_THROTTLE_SECONDS
        ):
            row.last_used_at = now  # type: ignore[assignment]
            self._commit()
        return {
            "valid": True,
            "user": row.user,
            "key_id": row.key_id,
            "label": row.label,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        }

    # --- Key rotation ----------------------------------------------------

    @staticmethod
    def _rotate_cell(enc, stored, old_creator: str, new_creator: str):
        """Re-key one encrypted cell from ``old_creator`` to ``new_creator``.

        Returns the ciphertext sealed under the new creator, or ``None`` when
        the cell is empty (nothing to write). Mirrors
        ``scripts/reencrypt_pertenant.reencrypt_value`` but decrypts under the
        OLD creator and re-encrypts under the NEW one — necessary because field
        keys are derived per-creator (HKDF), so ciphertext is bound to the
        creator that wrote it. Legacy global-key ciphertext and never-encrypted
        plaintext both recover their plaintext and are then sealed (v2) under
        the new key. A value that looks like ciphertext but fails authentication
        raises ``InvalidCiphertextError`` rather than being silently rewritten.
        """
        from auth.encryption import InvalidCiphertextError

        if not stored:
            return None
        try:
            plaintext = enc.decrypt(stored, old_creator)
        except InvalidCiphertextError:
            raise
        except ValueError:
            plaintext = stored  # legacy plaintext row (never encrypted)
        return enc.encrypt(plaintext, new_creator)

    def rotate_client_key(self, new_key: str) -> Dict[str, Any]:
        """Atomically move this client's namespace to a fresh key (cutover).

        Reassigns every ``auth_group`` / ``auth_membership`` / ``auth_permission``
        / ``auth_api_key`` row from ``creator = self.client`` (the old key) to
        ``creator = new_key`` in a single transaction, then returns the migrated
        row counts. Junction tables reference row ids and follow automatically,
        so they need no change.

        When field encryption is enabled the encrypted columns (``user`` /
        ``name`` / ``description`` / ``label``) are cryptographically bound to
        the creator, so each is decrypted under the old key and re-encrypted
        under the new key in the same pass, keeping the new namespace
        equality-queryable. When encryption is off the columns are plaintext and
        a single bulk ``creator`` update per table suffices. Per-user API-key
        hashes are creator-independent and survive rotation unchanged — issued
        secrets keep validating under the new tenant key.

        The new key is generated by the caller (server-side) and is a fresh
        UUID4, so the target namespace is empty and the ``UNIQUE(creator, ...)``
        constraints cannot conflict. On any error the transaction is rolled back
        — leaving the old namespace intact — and the error re-raised.
        """
        if not validate_client_key(new_key):
            raise ValueError("new_key must be a valid UUID4")
        if new_key == self.client:
            raise ValueError("new_key must differ from the current key")

        from auth.encryption import field_encryption

        # Serialize against concurrent writes/rotation for this tenant so the
        # scan-then-update pass below sees a stable row set (no stranded insert,
        # no clobbered update). Held until this transaction commits/rolls back.
        self._lock_tenant()

        old = self.client
        # (result label, table, encrypted column names)
        # __table__ is a Table at runtime; the declarative stubs type it as the
        # broader FromClause, so cast for the DML/column APIs below.
        # auth_api_key carries TWO encrypted cells; its key_hash/key_id are
        # creator-independent on purpose and move untouched, so issued secrets
        # keep validating under the new tenant key.
        targets: List[Tuple[str, Table, List[str]]] = [
            ("roles", cast(Table, AuthGroup.__table__), ["description"]),
            ("memberships", cast(Table, AuthMembership.__table__), ["user"]),
            ("permissions", cast(Table, AuthPermission.__table__), ["name"]),
            ("api_keys", cast(Table, AuthApiKey.__table__), ["user", "label"]),
            ("settings", cast(Table, AuthTenantSettings.__table__), []),
        ]
        migrated: Dict[str, int] = {}
        try:
            for label, table, enc_cols in targets:
                if field_encryption.enabled and field_encryption.encryptor is not None:
                    # Re-key each row's encrypted cells (bound to creator), then
                    # flip creator — all in the same UPDATE.
                    rows = self.db.execute(
                        select(
                            table.c.id, *(table.c[col] for col in enc_cols)
                        ).where(table.c.creator == old)
                    ).fetchall()
                    for fetched in rows:
                        row_id = fetched[0]
                        values: Dict[str, Any] = {"creator": new_key}
                        for offset, col in enumerate(enc_cols, start=1):
                            new_cell = self._rotate_cell(
                                field_encryption.encryptor,
                                fetched[offset],
                                old,
                                new_key,
                            )
                            if new_cell is not None:
                                values[col] = new_cell
                        self.db.execute(
                            update(table).where(table.c.id == row_id).values(values)
                        )
                    migrated[label] = len(rows)
                else:
                    # Plaintext columns: count, then one bulk creator update.
                    count = self.db.execute(
                        select(func.count())
                        .select_from(table)
                        .where(table.c.creator == old)
                    ).scalar_one()
                    self.db.execute(
                        update(table)
                        .where(table.c.creator == old)
                        .values(creator=new_key)
                    )
                    migrated[label] = int(count)
            self._commit()
        except Exception:
            logger.exception(
                "rotate_client_key failed (old_creator=%s)", client_fingerprint(old)
            )
            self.db.rollback()
            raise

        # The old scope is now empty; point this instance at the new key so any
        # further use is consistent with what was just committed.
        self.client = new_key
        return {"new_key": new_key, "migrated": migrated}
