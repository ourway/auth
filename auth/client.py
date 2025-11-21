"""
Enhanced client library with connection pooling, retry logic, and circuit breaker
"""

import json
from typing import Any, Dict
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError
from requests.packages.urllib3.util.retry import Retry

from auth.circuit_breaker import circuit_breaker


class RetryableHTTPAdapter(HTTPAdapter):
    """HTTP adapter with retry logic"""

    def __init__(
        self, retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), **kwargs
    ):
        self.retries = retries
        self.backoff_factor = backoff_factor
        self.status_forcelist = status_forcelist
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["retries"] = Retry(
            total=self.retries,
            read=self.retries,
            connect=self.retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=self.status_forcelist,
        )
        return super().init_poolmanager(*args, **kwargs)


class EnhancedAuthClient:
    """Enhanced client with connection pooling, retry logic, and circuit breaker"""

    def __init__(
        self,
        api_key: str,
        service_url: str,
        max_retries: int = 3,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        timeout: int = 30,
        circuit_breaker_enabled: bool = True,
    ):
        """
        Initialize the enhanced client

        Args:
            api_key: The API key for authentication
            service_url: The base URL for the auth service
            max_retries: Number of times to retry failed requests
            pool_connections: Number of connection pools
            pool_maxsize: Max connections per pool
            timeout: Request timeout in seconds
            circuit_breaker_enabled: Whether circuit breaker is enabled
        """
        self.api_key = api_key
        self.service_url = service_url
        self.timeout = timeout
        self.circuit_breaker_enabled = circuit_breaker_enabled

        # Create session with connection pooling
        self.session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            backoff_factor=0.3,
        )

        # Use our custom adapter for more control
        adapter = RetryableHTTPAdapter(
            retries=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            max_retries=retry_strategy,
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        )

        # API endpoints
        self.endpoints = {
            "ping": "/ping",
            "membership": "/api/membership/{user}/{group}",
            "permission": "/api/permission/{group}/{name}",
            "has_permission": "/api/has_permission/{user}/{name}",
            "user_permissions": "/api/user_permissions/{user}",
            "role_permissions": "/api/role_permissions/{role}",
            "user_roles": "/api/user_roles/{user}",
            "role_members": "/api/members/{role}",
            "roles": "/api/roles",
            "which_roles_can": "/api/which_roles_can/{name}",
            "which_users_can": "/api/which_users_can/{name}",
            "role": "/api/role/{role}",
            "workflow_users": "/api/workflow/users/{workflow_name}",
            "workflow_permission": "/api/workflow/user/{user}/can_run/{workflow_name}",
        }

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make an HTTP request with circuit breaker, retry logic, and error handling
        """
        url = urljoin(self.service_url, endpoint)

        # Prepare the request function for the circuit breaker
        def request_func():
            try:
                response = self.session.request(
                    method=method, url=url, timeout=self.timeout, **kwargs
                )

                # Raise an exception for bad status codes
                response.raise_for_status()

                # Try to parse JSON response
                try:
                    json_response: Dict[str, Any] = response.json()
                    return json_response
                except json.JSONDecodeError:
                    # If JSON parsing fails, return the text content
                    text_response: Dict[str, Any] = {"result": response.text}
                    return text_response

            except requests.exceptions.RequestException as e:
                # Convert to our expected exception type
                raise ConnectionError(f"Request failed: {str(e)}") from e

        if self.circuit_breaker_enabled:
            # Use circuit breaker to wrap the request
            try:
                cb_result: Dict[str, Any] = circuit_breaker("api_call")(request_func)()
                return cb_result
            except Exception as e:
                raise ConnectionError(
                    f"Circuit breaker prevented request: {str(e)}"
                ) from e
        else:
            direct_result: Dict[str, Any] = request_func()
            return direct_result

    def ping(self) -> Dict[str, Any]:
        """Health check"""
        try:
            return self._make_request("GET", self.endpoints["ping"])
        except Exception as e:
            return {"error": str(e), "success": False}

    def add_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Add user to a group"""
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"user": user, "group": group},
            }

    def remove_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Remove user from a group"""
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"user": user, "group": group},
            }

    def has_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Check if user is member of a group"""
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"user": user, "group": group},
            }

    def add_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Add permission to a group"""
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"group": group, "name": name},
            }

    def remove_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Remove permission from a group"""
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"group": group, "name": name},
            }

    def has_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Check if group has permission"""
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"group": group, "name": name},
            }

    def user_has_permission(self, user: str, name: str) -> Dict[str, Any]:
        """Check if user has permission"""
        endpoint = self.endpoints["has_permission"].format(user=user, name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"user": user, "name": name},
            }

    def get_user_permissions(self, user: str) -> Dict[str, Any]:
        """Get all permissions for a user"""
        endpoint = self.endpoints["user_permissions"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"user": user}}

    def get_role_permissions(self, role: str) -> Dict[str, Any]:
        """Get all permissions for a role"""
        endpoint = self.endpoints["role_permissions"].format(role=role)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"role": role}}

    def get_user_roles(self, user: str) -> Dict[str, Any]:
        """Get all roles for a user"""
        endpoint = self.endpoints["user_roles"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"user": user}}

    def get_role_members(self, role: str) -> Dict[str, Any]:
        """Get all members of a role"""
        endpoint = self.endpoints["role_members"].format(role=role)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"role": role}}

    def list_roles(self) -> Dict[str, Any]:
        """List all roles"""
        try:
            return self._make_request("GET", self.endpoints["roles"])
        except Exception as e:
            return {"error": str(e), "success": False}

    def which_roles_can(self, name: str) -> Dict[str, Any]:
        """Get roles that can perform an action"""
        endpoint = self.endpoints["which_roles_can"].format(name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"name": name}}

    def which_users_can(self, name: str) -> Dict[str, Any]:
        """Get users that can perform an action"""
        endpoint = self.endpoints["which_users_can"].format(name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"name": name}}

    def create_role(self, role: str) -> Dict[str, Any]:
        """Create a new role"""
        endpoint = self.endpoints["role"].format(role=role)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"role": role}}

    def delete_role(self, role: str) -> Dict[str, Any]:
        """Delete a role"""
        endpoint = self.endpoints["role"].format(role=role)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return {"error": str(e), "success": False, "data": {"role": role}}

    # Workflow-related methods
    def get_users_for_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """Get all users who can run a specific workflow"""
        endpoint = self.endpoints["workflow_users"].format(workflow_name=workflow_name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"workflow_name": workflow_name},
            }

    def check_user_workflow_permission(
        self, user: str, workflow_name: str
    ) -> Dict[str, Any]:
        """Check if a user can run a specific workflow"""
        endpoint = self.endpoints["workflow_permission"].format(
            user=user, workflow_name=workflow_name
        )
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "data": {"user": user, "workflow_name": workflow_name},
            }

    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# For backward compatibility with the old client
class Client(EnhancedAuthClient):
    """Legacy client class for backward compatibility"""

    pass
