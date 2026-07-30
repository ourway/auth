"""
Enhanced client library with connection pooling, retry logic, and circuit breaker
"""

import json
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError
from urllib3.util.retry import Retry

from auth.circuit_breaker import circuit_breaker

# Methods eligible for retry. The auth server's write endpoints are
# idempotent upserts, so retrying POST/PUT/DELETE is safe here.
_RETRY_METHODS = ["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]


class AuthTransportError(Exception):
    """The client could not get an answer from the auth service.

    Raised instead of the legacy error-dict return when the client is
    constructed with ``raise_on_error=True``. Distinguishes "we could not
    ask" (connection failure, exhausted retries, open circuit breaker) from
    a genuine negative answer such as ``has_permission: false``.
    """


def _build_retry(total, backoff_factor, status_forcelist) -> Retry:
    """Build a Retry that works on both urllib3 1.x and 2.x.

    urllib3 renamed ``method_whitelist`` to ``allowed_methods`` in 1.26 and
    removed the old name in 2.0.
    """
    kwargs = {
        "total": total,
        "backoff_factor": backoff_factor,
        "status_forcelist": list(status_forcelist),
    }
    try:
        return Retry(allowed_methods=_RETRY_METHODS, **kwargs)
    except TypeError:  # urllib3 < 1.26
        return Retry(method_whitelist=_RETRY_METHODS, **kwargs)  # type: ignore[call-arg]


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
    """Enhanced client with connection pooling, retry logic, and circuit breaker.

    Error contract: methods do not raise by default. On transport failure
    (connection error, exhausted retries, open circuit breaker) they return::

        {"error": "<message>", "success": False, "transport_error": True,
         "data": {...the call's input arguments...}}

    ``data`` echoes the inputs and does NOT contain the answer field
    (``has_permission``, ``count``, ...), so reading it without checking
    ``success`` turns an outage into a false negative. Either check
    ``success`` first, or construct with ``raise_on_error=True`` to make
    every method raise :class:`AuthTransportError` on transport failure.
    """

    def __init__(
        self,
        api_key: str,
        service_url: str,
        max_retries: int = 3,
        pool_connections: int = 10,
        pool_maxsize: int = 64,
        timeout: int = 30,
        circuit_breaker_enabled: bool = True,
        raise_on_error: bool = False,
    ):
        """
        Initialize the enhanced client

        Args:
            api_key: The API key for authentication
            service_url: The base URL for the auth service
            max_retries: Number of times to retry failed requests
            pool_connections: Number of connection pools (passed to the HTTP adapter)
            pool_maxsize: Max connections per pool (passed to the HTTP adapter;
                size it to your caller concurrency — an exhausted pool surfaces
                as transport failures under load)
            timeout: Request timeout in seconds
            circuit_breaker_enabled: Whether circuit breaker is enabled
            raise_on_error: When True, methods raise AuthTransportError on
                transport failure instead of returning the legacy error dict
        """
        self.api_key = api_key
        self.service_url = service_url
        self.timeout = timeout
        self.circuit_breaker_enabled = circuit_breaker_enabled
        self.raise_on_error = raise_on_error

        # Create session with connection pooling
        self.session = requests.Session()

        # Configure retries
        retry_strategy = _build_retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        # Use our custom adapter for more control
        adapter = RetryableHTTPAdapter(
            retries=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
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
            "rotate_key": "/api/keys/rotate",
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

    def _transport_failure(
        self, exc: Exception, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Report a transport-level failure per the configured policy.

        Either raises :class:`AuthTransportError` (``raise_on_error=True``) or
        returns the legacy error payload, marked ``transport_error: True``.
        The payload's ``data`` only echoes call inputs — it never contains the
        queried answer field, which is why callers must check ``success``.
        """
        if self.raise_on_error:
            raise AuthTransportError(str(exc)) from exc
        payload: Dict[str, Any] = {
            "error": str(exc),
            "success": False,
            "transport_error": True,
        }
        if data is not None:
            payload["data"] = data
        return payload

    def ping(self) -> Dict[str, Any]:
        """Health check.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        try:
            return self._make_request("GET", self.endpoints["ping"])
        except Exception as e:
            return self._transport_failure(e)

    def add_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Add user to a group.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "group": group})

    def remove_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Remove user from a group.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "group": group})

    def has_membership(self, user: str, group: str) -> Dict[str, Any]:
        """Check if user is member of a group.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["membership"].format(user=user, group=group)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "group": group})

    def add_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Add permission to a group.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"group": group, "name": name})

    def remove_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Remove permission from a group.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"group": group, "name": name})

    def has_permission(self, group: str, name: str) -> Dict[str, Any]:
        """Check if group has permission.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["permission"].format(group=group, name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"group": group, "name": name})

    def user_has_permission(self, user: str, name: str) -> Dict[str, Any]:
        """Check if user has permission.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``
        before reading ``data`` — a missing ``has_permission`` is an outage,
        not a denial.
        """
        endpoint = self.endpoints["has_permission"].format(user=user, name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "name": name})

    def get_user_permissions(self, user: str) -> Dict[str, Any]:
        """Get all permissions for a user.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``
        before reading ``data`` — a missing ``count`` is an outage, not an
        unknown user.
        """
        endpoint = self.endpoints["user_permissions"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user})

    def get_role_permissions(self, role: str) -> Dict[str, Any]:
        """Get all permissions for a role.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["role_permissions"].format(role=role)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def get_user_roles(self, user: str) -> Dict[str, Any]:
        """Get all roles for a user.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["user_roles"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user})

    def get_role_members(self, role: str) -> Dict[str, Any]:
        """Get all members of a role.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["role_members"].format(role=role)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def list_roles(self) -> Dict[str, Any]:
        """List all roles.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        try:
            return self._make_request("GET", self.endpoints["roles"])
        except Exception as e:
            return self._transport_failure(e)

    def which_roles_can(self, name: str) -> Dict[str, Any]:
        """Get roles that can perform an action.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["which_roles_can"].format(name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"name": name})

    def which_users_can(self, name: str) -> Dict[str, Any]:
        """Get users that can perform an action.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["which_users_can"].format(name=name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"name": name})

    def create_role(self, role: str) -> Dict[str, Any]:
        """Create a new role.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["role"].format(role=role)
        try:
            return self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def delete_role(self, role: str) -> Dict[str, Any]:
        """Delete a role.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["role"].format(role=role)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"role": role})

    def rotate_key(self) -> Dict[str, Any]:
        """Rotate this client's API key (atomic cutover).

        The server mints a fresh key, moves the whole namespace onto it, and
        returns it in ``data.new_key``. On success this client is updated in
        place — ``self.api_key`` and the session ``Authorization`` header switch
        to the new key — so subsequent calls on this instance keep working. The
        returned key is the ONLY copy: persist ``data.new_key`` (e.g. to your
        secret store) or you lose access to the namespace.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["rotate_key"]
        try:
            response = self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={})

        new_key = (response or {}).get("data", {}).get("new_key")
        if new_key:
            self.api_key = new_key
            self.session.headers["Authorization"] = f"Bearer {new_key}"
        return response

    # Workflow-related methods
    def get_users_for_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """Get all users who can run a specific workflow.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["workflow_users"].format(workflow_name=workflow_name)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"workflow_name": workflow_name})

    def check_user_workflow_permission(
        self, user: str, workflow_name: str
    ) -> Dict[str, Any]:
        """Check if a user can run a specific workflow.

        Transport failure: error dict without the answer field (or
        ``AuthTransportError`` if ``raise_on_error=True``); check ``success``.
        """
        endpoint = self.endpoints["workflow_permission"].format(
            user=user, workflow_name=workflow_name
        )
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(
                e, data={"user": user, "workflow_name": workflow_name}
            )

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
