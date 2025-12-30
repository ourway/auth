"""
SQLAlchemy-based authorization service
"""

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from auth.encryption import encrypt_sensitive_data
from auth.models.sql import AuthGroup, AuthMembership, AuthPermission


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
        return encrypt_sensitive_data(user) or user

    def _get_encrypted_permission(self, name: str) -> str:
        """Get the encrypted version of a permission name for database queries"""
        return encrypt_sensitive_data(name) or name

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
        """Add a new role - atomic idempotent using ON CONFLICT.

        Uses PostgreSQL's INSERT ... ON CONFLICT for race-condition-free upsert.
        The unique constraint (creator, role) ensures atomicity.
        """
        from sqlalchemy import text

        try:
            self.db.execute(
                text("""
                    INSERT INTO auth_rbac.auth_group
                        (creator, role, description, is_active, date_created, modified)
                    VALUES
                        (:creator, :role, :description, true, NOW(), NOW())
                    ON CONFLICT (creator, role) DO UPDATE SET
                        is_active = true,
                        description = COALESCE(EXCLUDED.description, auth_rbac.auth_group.description),
                        modified = NOW()
                """),
                {"creator": self.client, "role": role, "description": description},
            )
            self.db.commit()
            return True
        except Exception:
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
        """Add user to a role - atomic idempotent using ON CONFLICT.

        Uses PostgreSQL's INSERT ... ON CONFLICT for race-condition-free operations.
        """
        from sqlalchemy import text

        # Get group ID
        group_result = self.db.execute(
            text("""
                SELECT id FROM auth_rbac.auth_group
                WHERE creator = :creator AND role = :role AND is_active = true
            """),
            {"creator": self.client, "role": role},
        )
        row = group_result.fetchone()
        if not row:
            return False
        group_id = row[0]

        try:
            # Upsert membership
            encrypted_user = self._get_encrypted_user(user)
            membership_result = self.db.execute(
                text("""
                    INSERT INTO auth_rbac.auth_membership
                        (creator, "user", is_active, date_created, modified)
                    VALUES
                        (:creator, :user, true, NOW(), NOW())
                    ON CONFLICT (creator, "user") DO UPDATE SET
                        is_active = true,
                        modified = NOW()
                    RETURNING id
                """),
                {"creator": self.client, "user": encrypted_user},
            )
            membership_id = membership_result.fetchone()[0]

            # Link membership to group (junction table)
            self.db.execute(
                text("""
                    INSERT INTO auth_rbac.membership_groups (membership_id, group_id)
                    VALUES (:membership_id, :group_id)
                    ON CONFLICT (membership_id, group_id) DO NOTHING
                """),
                {"membership_id": membership_id, "group_id": group_id},
            )
            self.db.commit()
            return True
        except Exception:
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
        """Add permission to a role - atomic idempotent using ON CONFLICT.

        Uses PostgreSQL's INSERT ... ON CONFLICT for race-condition-free operations.
        """
        from sqlalchemy import text

        if self.has_permission(role, name):
            return True

        # Get group ID
        group_result = self.db.execute(
            text("""
                SELECT id FROM auth_rbac.auth_group
                WHERE creator = :creator AND role = :role AND is_active = true
            """),
            {"creator": self.client, "role": role},
        )
        row = group_result.fetchone()
        if not row:
            return False
        group_id = row[0]

        try:
            # Upsert permission
            encrypted_name = self._get_encrypted_permission(name)
            perm_result = self.db.execute(
                text("""
                    INSERT INTO auth_rbac.auth_permission
                        (creator, name, is_active, date_created, modified)
                    VALUES
                        (:creator, :name, true, NOW(), NOW())
                    ON CONFLICT (creator, name) DO UPDATE SET
                        is_active = true,
                        modified = NOW()
                    RETURNING id
                """),
                {"creator": self.client, "name": encrypted_name},
            )
            perm_id = perm_result.fetchone()[0]

            # Link permission to group (junction table)
            self.db.execute(
                text("""
                    INSERT INTO auth_rbac.permission_groups (permission_id, group_id)
                    VALUES (:perm_id, :group_id)
                    ON CONFLICT (permission_id, group_id) DO NOTHING
                """),
                {"perm_id": perm_id, "group_id": group_id},
            )
            self.db.commit()
            return True
        except Exception:
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
