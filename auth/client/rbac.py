"""Roles, memberships and permissions — the RBAC surface of the client."""

from typing import Any, Dict

from auth.client.base import ClientBase


class RbacMixin(ClientBase):
    """The role, membership and permission calls."""

    def add_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Add user to a group.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "group": group})

    def remove_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Remove user from a group.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "group": group})

    def has_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Check if user is member of a group.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "group": group})

    def add_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Add permission to a group.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"group": group, "name": name})

    def remove_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Remove permission from a group.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"group": group, "name": name})

    def has_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Check if group has permission.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"group": group, "name": name})

    def user_has_permission(self, user: str, name: str) -> Dict[str, Any]:
        """Check if user has permission.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["has_permission"].format(user=user, name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "name": name})

    def get_user_permissions(self, user: str) -> Dict[str, Any]:
        """Get all permissions for a user.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["user_permissions"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user})

    def get_role_permissions(self, role: str) -> Dict[str, Any]:
        """Get all permissions for a role.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["role_permissions"].format(role=role)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def get_user_roles(self, user: str) -> Dict[str, Any]:
        """Get all roles for a user.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["user_roles"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user})

    def get_role_members(self, role: str) -> Dict[str, Any]:
        """Get all members of a role.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["role_members"].format(role=role)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def list_roles(self) -> Dict[str, Any]:
        """List all roles.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request("GET", self.endpoints["roles"])
        except Exception as e:
            return self._transport_failure(e)

    def which_roles_can(self, name: str) -> Dict[str, Any]:
        """Get roles that can perform an action.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["which_roles_can"].format(name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"name": name})

    def which_users_can(self, name: str) -> Dict[str, Any]:
        """Get users that can perform an action.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["which_users_can"].format(name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"name": name})

    def create_role(self, role: str) -> Dict[str, Any]:
        """Create a new role.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["role"].format(role=role)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def delete_role(self, role: str) -> Dict[str, Any]:
        """Delete a role.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["role"].format(role=role)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})
