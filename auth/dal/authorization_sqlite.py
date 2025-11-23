#!/usr/bin/env python

"""
Modernized Authorization class using SQLite3 instead of MongoDB
"""

from auth.models.sqlite import (
    AuthGroup,
    AuthMembership,
    AuthPermission,
    make_db_connection,
)


class Authorization(object):
    """Main Authorization class"""

    def __init__(self, client, conn=None):
        """Initialize Authorization with a client
        @type client: String
        @type conn: Optional database connection (for testing)
        """
        self.client = client
        self.conn = conn if conn is not None else make_db_connection()
        self.group_model = AuthGroup(self.conn)
        self.membership_model = AuthMembership(self.conn)
        self.permission_model = AuthPermission(self.conn)

    @property
    def roles(self):
        """gets user groups"""
        groups = self.group_model.get_all_by_creator(self.client)
        return [{"role": group["role"]} for group in groups]

    def get_permissions(self, role):
        """gets permissions of role"""
        target_role = self.group_model.get_by_role(self.client, role)
        if not target_role:
            return []

        permissions = self.permission_model.get_all_by_group(
            self.client, target_role["id"]
        )
        return [{"name": perm["name"]} for perm in permissions]

    def get_user_permissions(self, user):
        """get permissions of a user"""
        groups = self.membership_model.get_groups(self.client, user)
        results = []
        for group in groups:
            permissions = self.permission_model.get_all_by_group(
                self.client, group["id"]
            )
            for permission in permissions:
                results.append({"name": permission["name"]})
        return results

    def get_user_roles(self, user):
        """get roles of a user"""
        groups = self.membership_model.get_groups(self.client, user)
        return [{"user": user, "role": group["role"]} for group in groups]

    def get_role_members(self, role):
        """get members of a role"""
        target_role = self.group_model.get_by_role(self.client, role)
        if not target_role:
            return []

        # Get all memberships that have this group
        rows = self.membership_model._fetch_all(
            """
            SELECT am.user FROM auth_membership am
            JOIN membership_groups mg ON am.id = mg.membership_id
            WHERE mg.group_id = ? AND am.is_active = 1
        """,
            (target_role["id"],),
        )

        return [{"user": row["user"], "role": role} for row in rows]

    def which_roles_can(self, name):
        """Which role can perform action?"""
        groups = self.permission_model.get_groups(self.client, name)
        return [{"role": group["role"]} for group in groups]

    def which_users_can(self, name):
        """Which users can perform action?"""
        roles = self.which_roles_can(name)
        result = []
        for role_dict in roles:
            members = self.get_role_members(role_dict["role"])
            result.extend(members)
        return result

    def get_role(self, role):
        """Returns a role object"""
        return self.group_model.get_by_role(self.client, role)

    def add_role(self, role, description=None):
        """Creates a new group"""
        result = self.group_model.create(self.client, role, description)
        # Return True even if role exists (for compatibility)
        return True if result or self.group_model.get_by_role(self.client, role) else False

    def del_role(self, role):
        """deletes a group"""
        return self.group_model.delete(self.client, role)

    def add_membership(self, user, role):
        """make user a member of a group"""
        target_group = self.group_model.get_by_role(self.client, role)
        if not target_group:
            return False

        membership_id = self.membership_model.create_or_get(self.client, user)
        return self.membership_model.add_group(membership_id, target_group["id"])

    def del_membership(self, user, role):
        """dismember user from a group"""
        if not self.has_membership(user, role):
            return True

        target_group = self.group_model.get_by_role(self.client, role)
        if not target_group:
            return True

        membership = self.membership_model.get_by_user(self.client, user)
        if not membership:
            return True

        return self.membership_model.remove_group(membership["id"], target_group["id"])

    def has_membership(self, user, role):
        """checks if user is member of a group"""
        groups = self.membership_model.get_groups(self.client, user)
        return any(group["role"] == role for group in groups)

    def add_permission(self, role, name):
        """authorize a group for something"""
        if self.has_permission(role, name):
            return True

        target_group = self.group_model.get_by_role(self.client, role)
        if not target_group:
            return False

        permission_id = self.permission_model.create_or_get(self.client, name)
        return self.permission_model.add_group(permission_id, target_group["id"])

    def del_permission(self, role, name):
        """revoke authorization of a group"""
        if not self.has_permission(role, name):
            return True

        target_group = self.group_model.get_by_role(self.client, role)
        if not target_group:
            return True

        permission = self.permission_model.get_by_name(self.client, name)
        if not permission:
            return True

        return self.permission_model.remove_group(permission["id"], target_group["id"])

    def has_permission(self, role, name):
        """verify groups authorization"""
        target_group = self.group_model.get_by_role(self.client, role)
        if not target_group:
            return False

        groups = self.permission_model.get_groups(self.client, name)
        return any(group["id"] == target_group["id"] for group in groups)

    def user_has_permission(self, user, name):
        """verify user has permission"""
        groups = self.membership_model.get_groups(self.client, user)
        for group in groups:
            if self.has_permission(group["role"], name):
                return True
        return False
