"""Roles, memberships and permissions — the mutating RBAC core."""

import logging
from typing import Optional

from sqlalchemy import func, select

from auth.audit import client_fingerprint
from auth.encryption import encrypt_sensitive_data
from auth.models.sql import (
    AuthGroup,
    AuthMembership,
    AuthPermission,
    membership_groups,
    permission_groups,
)
from auth.services.queries import QueryMixin

logger = logging.getLogger(__name__)


class RbacMixin(QueryMixin):
    """Create and remove roles, memberships and permission grants."""

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
            .filter(
                AuthMembership.creator == self.client,
                AuthMembership._user == self._get_encrypted_user(user),
            )
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
            .filter(
                AuthPermission.creator == self.client,
                AuthPermission._name == self._get_encrypted_permission(name),
            )
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
