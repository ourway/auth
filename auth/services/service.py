"""
SQLAlchemy-based authorization service
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple, cast

from sqlalchemy import Table, func, select, update
from sqlalchemy.orm import Session

from auth.encryption import encrypt_sensitive_data
from auth.models.sql import (
    AuthGroup,
    AuthMembership,
    AuthPermission,
    membership_groups,
    permission_groups,
)

logger = logging.getLogger(__name__)


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

    def __init__(self, db: Session, client: str, validate_client: bool = True):
        if validate_client and not validate_client_key(client):
            raise ValueError(
                f"Invalid client key: {client}. Client key must be a valid UUID4."
            )
        self.db = db
        self.client = client
        self.validate_client = validate_client

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
            self.db.commit()
            return True
        except Exception:
            logger.exception("add_role failed (client=%s, role=%r)", self.client, role)
            self.db.rollback()
            return False

    def del_role(self, role: str) -> bool:
        """Delete a role"""
        group = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.role == role)
            .first()
        )

        if group and group.is_active:
            group.is_active = False  # type: ignore[assignment]
            self.db.commit()
            return True
        return False

    def add_membership(self, user: str, role: str) -> bool:
        """Add user to a role - atomic idempotent upsert.

        Uses INSERT ... ON CONFLICT (PostgreSQL and SQLite) for
        race-condition-free operations.
        """
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
            self.db.commit()
            return True
        except Exception:
            logger.exception(
                "add_membership failed (client=%s, user=%r, role=%r)",
                self.client,
                user,
                role,
            )
            self.db.rollback()
            return False

    def del_membership(self, user: str, role: str) -> bool:
        """Remove user from a role"""
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
            self.db.commit()

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
            self.db.commit()
            return True
        except Exception:
            logger.exception(
                "add_permission failed (client=%s, role=%r, name=%r)",
                self.client,
                role,
                name,
            )
            self.db.rollback()
            return False

    def del_permission(self, role: str, name: str) -> bool:
        """Remove permission from a role"""
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
            self.db.commit()

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
        row from ``creator = self.client`` (the old key) to ``creator = new_key``
        in a single transaction, then returns the migrated row counts. Junction
        tables reference row ids and follow automatically, so they need no change.

        When field encryption is enabled the encrypted columns (``user`` /
        ``name`` / ``description``) are cryptographically bound to the creator, so
        each is decrypted under the old key and re-encrypted under the new key in
        the same pass, keeping the new namespace equality-queryable. When
        encryption is off the columns are plaintext and a single bulk ``creator``
        update per table suffices.

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

        old = self.client
        # (result label, table, encrypted column name)
        # __table__ is a Table at runtime; the declarative stubs type it as the
        # broader FromClause, so cast for the DML/column APIs below.
        targets: List[Tuple[str, Table, str]] = [
            ("roles", cast(Table, AuthGroup.__table__), "description"),
            ("memberships", cast(Table, AuthMembership.__table__), "user"),
            ("permissions", cast(Table, AuthPermission.__table__), "name"),
        ]
        migrated: Dict[str, int] = {}
        try:
            for label, table, enc_col in targets:
                if field_encryption.enabled and field_encryption.encryptor is not None:
                    # Re-key each row's encrypted cell (bound to creator), then
                    # flip creator — both in the same UPDATE.
                    rows = self.db.execute(
                        select(table.c.id, table.c[enc_col]).where(
                            table.c.creator == old
                        )
                    ).fetchall()
                    for row_id, cell in rows:
                        values: Dict[str, Any] = {"creator": new_key}
                        new_cell = self._rotate_cell(
                            field_encryption.encryptor, cell, old, new_key
                        )
                        if new_cell is not None:
                            values[enc_col] = new_cell
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
            self.db.commit()
        except Exception:
            logger.exception("rotate_client_key failed (old_creator=%s)", old)
            self.db.rollback()
            raise

        # The old scope is now empty; point this instance at the new key so any
        # further use is consistent with what was just committed.
        self.client = new_key
        return {"new_key": new_key, "migrated": migrated}
