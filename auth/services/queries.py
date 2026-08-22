"""Read-only projections of the tenant's roles, members and permissions."""

from typing import Any, Dict, List

from auth.models.sql import (
    AuthGroup,
    AuthMembership,
    AuthPermission,
)
from auth.services.tenant import TenantMixin


class QueryMixin(TenantMixin):
    """The read side: nothing here mutates a row."""

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
