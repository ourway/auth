"""The client's request machinery: session setup, request/response, teardown."""

import json
import warnings
from typing import Any, Dict, NoReturn, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError

from auth.circuit_breaker import circuit_breaker
from auth.client._transport import (
    AuthTransportError,
    RetryableHTTPAdapter,
    _build_retry,
)


class ClientBase:
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
