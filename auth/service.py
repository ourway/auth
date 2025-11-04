"""
SQLAlchemy-based authorization service
"""

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from auth.database import AuthGroup, AuthMembership, AuthPermission


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
                AuthMembership.user == user,
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
                AuthMembership.user == user,
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
                AuthPermission.name == name,
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
        """Add a new role"""
        # Check if role already exists
        existing = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.role == role)
            .first()
        )

        if existing:
            if not existing.is_active:
                existing.is_active = True
                if description is not None:
                    existing.description = description
                self.db.commit()
                return True
            # For compatibility with old tests, return True if role already exists
            return True

        new_group = AuthGroup(creator=self.client, role=role, description=description)
        self.db.add(new_group)
        self.db.commit()
        return True

    def del_role(self, role: str) -> bool:
        """Delete a role"""
        group = (
            self.db.query(AuthGroup)
            .filter(AuthGroup.creator == self.client, AuthGroup.role == role)
            .first()
        )

        if group and group.is_active:
            group.is_active = False
            self.db.commit()
            return True
        return False

    def add_membership(self, user: str, role: str) -> bool:
        """Add user to a role"""
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

        # Get or create membership
        membership = (
            self.db.query(AuthMembership)
            .filter(AuthMembership.creator == self.client, AuthMembership.user == user)
            .first()
        )

        if not membership:
            membership = AuthMembership(creator=self.client, user=user)
            self.db.add(membership)
            self.db.flush()  # Get the ID

        # Check if user is already in the group
        if group not in membership.groups:
            membership.groups.append(group)
            self.db.commit()

        return True

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
            .filter(AuthMembership.creator == self.client, AuthMembership.user == user)
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
                AuthMembership.user == user,
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
        """Add permission to a role"""
        if self.has_permission(role, name):
            return True

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

        # Get or create permission
        permission = (
            self.db.query(AuthPermission)
            .filter(AuthPermission.creator == self.client, AuthPermission.name == name)
            .first()
        )

        if not permission:
            permission = AuthPermission(creator=self.client, name=name)
            self.db.add(permission)
            self.db.flush()

        # Check if permission is already in the group
        if group not in permission.groups:
            permission.groups.append(group)
            self.db.commit()

        return True

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
            .filter(AuthPermission.creator == self.client, AuthPermission.name == name)
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
                AuthMembership.user == user,
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
