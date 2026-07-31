"""
Enhanced client library with connection pooling, retry logic, and circuit breaker
"""

import json
import warnings
from typing import Any, Dict, NoReturn, Optional
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

    Raised by every client method on transport failure (connection failure,
    exhausted retries, open circuit breaker, non-2xx status) since 3.0.0.
    Distinguishes "we could not ask" from a genuine negative answer such as
    ``has_permission: false`` — map it to your unavailable/503 path, never
    to a denial.
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

    Error contract (3.0.0): every method raises :class:`AuthTransportError`
    on transport failure — connection error, exhausted retries, open circuit
    breaker, or a non-2xx status. A transport failure can therefore never
    reach your authorization logic as a value: catch the exception and map it
    to your unavailable/503 path, never to a denial. Success payloads are
    unchanged from 2.x.
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
        raise_on_error: Optional[bool] = None,
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
            raise_on_error: DEPRECATED no-op kept so 2.x constructor calls
                keep working — since 3.0.0 the client ALWAYS raises
                AuthTransportError on transport failure
        """
        if raise_on_error is not None:
            warnings.warn(
                "raise_on_error is deprecated and ignored: since auth 3.0.0 "
                "the client always raises AuthTransportError on transport "
                "failure.",
                DeprecationWarning,
                stacklevel=2,
            )
        self.api_key = api_key
        self.service_url = service_url
        self.timeout = timeout
        self.circuit_breaker_enabled = circuit_breaker_enabled

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
            "apikeys_user": "/api/apikeys/user/{user}",
            "apikey_revoke": "/api/apikeys/user/{user}/{key_id}",
            "apikey_validate": "/api/apikeys/validate",
            "apikey_check_permission": "/api/apikeys/check_permission",
            "settings": "/api/settings",
        }

        # Built on first use: a session without retries for non-idempotent
        # calls (create_api_key). Shares the auth headers with the main
        # session so rotate_key() updates both.
        self._no_retry: Optional[requests.Session] = None

    def _no_retry_session(self) -> requests.Session:
        """Session for non-idempotent calls: same auth headers, zero retries."""
        if self._no_retry is None:
            session = requests.Session()
            session.mount("http://", HTTPAdapter(max_retries=0))
            session.mount("https://", HTTPAdapter(max_retries=0))
            # Shared mapping, not a copy: rotate_key() must apply to both.
            session.headers = self.session.headers
            self._no_retry = session
        return self._no_retry

    def _make_request(
        self, method: str, endpoint: str, retry: bool = True, **kwargs
    ) -> Dict[str, Any]:
        """
        Make an HTTP request with circuit breaker, retry logic, and error handling
        """
        url = urljoin(self.service_url, endpoint)
        session = self.session if retry else self._no_retry_session()

        # Prepare the request function for the circuit breaker
        def request_func():
            try:
                response = session.request(
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
    ) -> NoReturn:
        """Raise :class:`AuthTransportError` for a transport-level failure.

        Since 3.0.0 this ALWAYS raises — the 2.x error-dict return (an
        answer-shaped payload without the answer field) is gone, so an outage
        can never be misread as a denial. ``data`` is accepted for call-site
        compatibility and intentionally unused: inputs like key material must
        never ride on an exception.
        """
        raise AuthTransportError(str(exc)) from exc

    def ping(self) -> Dict[str, Any]:
        """Health check.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request("GET", self.endpoints["ping"])
        except Exception as e:
            return self._transport_failure(e)

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

    def rotate_key(self) -> Dict[str, Any]:
        """Rotate this client's API key (atomic cutover).

        The server mints a fresh key, moves the whole namespace onto it, and
        returns it in ``data.new_key``. On success this client is updated in
        place — ``self.api_key`` and the session ``Authorization`` header switch
        to the new key — so subsequent calls on this instance keep working. The
        returned key is the ONLY copy: persist ``data.new_key`` (e.g. to your
        secret store) or you lose access to the namespace.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
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

    # Per-user API keys (SPEC 0004)
    def create_api_key(
        self, user: str, label: Optional[str] = None
    ) -> Dict[str, Any]:
        """Mint an API key for a user; ``data.api_key`` is shown only once.

        Sent WITHOUT automatic retries: create is not idempotent, and a blind
        retry after an ambiguous failure could mint a second key whose secret
        nobody ever saw. On an ambiguous failure, list and revoke instead.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["apikeys_user"].format(user=user)
        payload = {"label": label} if label is not None else None
        try:
            return self._make_request("POST", endpoint, retry=False, json=payload)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "label": label})

    def list_api_keys(self, user: str) -> Dict[str, Any]:
        """List a user's API keys (metadata only; never the secrets).

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["apikeys_user"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user})

    def revoke_api_key(self, user: str, key_id: str) -> Dict[str, Any]:
        """Revoke one of a user's API keys by its public key_id (idempotent).

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["apikey_revoke"].format(user=user, key_id=key_id)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "key_id": key_id})

    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """Validate an API-key secret; answers ``data.valid`` true/false.

        The secret travels in the JSON body, never a URL, and never rides
        on an exception.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request(
                "POST", self.endpoints["apikey_validate"], json={"api_key": api_key}
            )
        except Exception as e:
            return self._transport_failure(e, data={"key_prefix": api_key[:12]})

    def check_api_key_permission(
        self, api_key: str, permission: str
    ) -> Dict[str, Any]:
        """Validate a secret AND check its subject's permission in one call.

        ``data.valid`` false → the key failed (reason as in validate_api_key);
        true → ``data.has_permission`` answers for the key's user. The secret
        travels in the JSON body and never rides on an exception.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request(
                "POST",
                self.endpoints["apikey_check_permission"],
                json={"api_key": api_key, "permission": permission},
            )
        except Exception as e:
            return self._transport_failure(
                e, data={"key_prefix": api_key[:12], "permission": permission}
            )

    # Tenant settings (SPEC 0010)
    def get_settings(self) -> Dict[str, Any]:
        """This tenant's settings (``data.strict_users``).

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request("GET", self.endpoints["settings"])
        except Exception as e:
            return self._transport_failure(e)

    def set_strict_users(self, enabled: bool) -> Dict[str, Any]:
        """Enable/disable strict user identity for this tenant (idempotent).

        While enabled, authorization decisions about users with no live API
        key answer negatively (``reason: user_not_key_backed``) — issue keys
        before flipping this on.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request(
                "PUT", self.endpoints["settings"], json={"strict_users": enabled}
            )
        except Exception as e:
            return self._transport_failure(e, data={"strict_users": enabled})

    # Workflow-related methods
    def get_users_for_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """Get all users who can run a specific workflow.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
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

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
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
        if self._no_retry is not None:
            self._no_retry.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# For backward compatibility with the old client
class Client(EnhancedAuthClient):
    """Legacy client class for backward compatibility"""

    pass
