"""
Tests for the shipped REST client (auth.client.EnhancedAuthClient / Client).

Previously only the legacy auth.core.REST client had coverage; the client
that auth/__init__.py actually exports had none — and its constructor
crashed on urllib3 >= 2.0.
"""

import uuid

import responses

from auth.client import Client, EnhancedAuthClient, RetryableHTTPAdapter, _build_retry

API_KEY = str(uuid.uuid4())
BASE = "http://auth.test"


def make_client(**kwargs):
    kwargs.setdefault("circuit_breaker_enabled", False)
    return EnhancedAuthClient(api_key=API_KEY, service_url=BASE, **kwargs)


def test_constructor_works_on_installed_urllib3():
    """Regression: Retry(method_whitelist=...) raised TypeError on urllib3>=2."""
    client = EnhancedAuthClient(api_key=API_KEY, service_url=BASE)
    assert client.api_key == API_KEY
    client.close()


def test_client_alias_is_enhanced_client():
    assert issubclass(Client, EnhancedAuthClient)
    client = Client(api_key=API_KEY, service_url=BASE)
    client.close()


def test_build_retry_sets_methods():
    retry = _build_retry(total=3, backoff_factor=0.3, status_forcelist=[500])
    methods = getattr(retry, "allowed_methods", None) or getattr(
        retry, "method_whitelist", None
    )
    assert set(methods or []) == {"HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"}


def test_adapter_constructs():
    adapter = RetryableHTTPAdapter(retries=2)
    assert adapter.retries == 2


def test_auth_header_set():
    client = make_client()
    assert client.session.headers["Authorization"] == f"Bearer {API_KEY}"
    assert client.session.headers["Content-Type"] == "application/json"
    client.close()


@responses.activate
def test_ping_success():
    responses.get(f"{BASE}/ping", json={"message": "PONG"})
    with make_client() as client:
        assert client.ping() == {"message": "PONG"}


@responses.activate
def test_user_has_permission_returns_server_payload():
    responses.get(
        f"{BASE}/api/has_permission/alice/manage_users",
        json={"success": True, "data": {"has_permission": True}},
    )
    with make_client() as client:
        result = client.user_has_permission("alice", "manage_users")
    assert result["data"]["has_permission"] is True


@responses.activate
def test_create_role_and_membership_paths():
    responses.post(f"{BASE}/api/role/admin", json={"result": True})
    responses.post(f"{BASE}/api/membership/alice/admin", json={"result": True})
    responses.delete(f"{BASE}/api/membership/alice/admin", json={"result": True})
    with make_client() as client:
        assert client.create_role("admin") == {"result": True}
        assert client.add_membership("alice", "admin") == {"result": True}
        assert client.remove_membership("alice", "admin") == {"result": True}


@responses.activate
def test_error_contract_returns_dict_not_raise():
    """Transport failures come back as {'error':..., 'success': False} dicts."""
    with make_client() as client:
        result = client.list_roles()  # nothing registered -> connection error
        membership = client.add_membership("alice", "admin")
    assert result["success"] is False and "error" in result
    assert membership["success"] is False
    assert membership["data"] == {"user": "alice", "group": "admin"}


@responses.activate
def test_http_error_status_becomes_error_dict():
    responses.get(f"{BASE}/api/roles", json={"detail": "boom"}, status=400)
    with make_client() as client:
        result = client.list_roles()
    assert result["success"] is False


@responses.activate
def test_base_url_semantics_pinned():
    """urljoin with absolute-path endpoints drops any path prefix in
    service_url. This documents the CURRENT contract — changing it would
    silently retarget existing consumers' requests."""
    responses.get(f"{BASE}/ping", json={"message": "PONG"})
    client = EnhancedAuthClient(
        api_key=API_KEY,
        service_url=f"{BASE}/some/prefix",
        circuit_breaker_enabled=False,
    )
    assert client.ping() == {"message": "PONG"}  # hit /ping, not /some/prefix/ping
    client.close()


@responses.activate
def test_circuit_breaker_path_still_returns_result():
    responses.get(f"{BASE}/ping", json={"message": "PONG"})
    client = EnhancedAuthClient(
        api_key=API_KEY, service_url=BASE, circuit_breaker_enabled=True
    )
    assert client.ping() == {"message": "PONG"}
    client.close()
