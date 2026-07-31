"""
Tests for the shipped REST client (auth.client.EnhancedAuthClient / Client).

Previously only the legacy auth.core.REST client had coverage; the client
that auth/__init__.py actually exports had none — and its constructor
crashed on urllib3 >= 2.0.
"""

import uuid

import pytest
import responses

from auth.client import (
    AuthTransportError,
    Client,
    EnhancedAuthClient,
    RetryableHTTPAdapter,
    _build_retry,
)

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
def test_rotate_key_switches_the_live_client_to_the_new_key():
    new_key = str(uuid.uuid4())
    responses.post(
        f"{BASE}/api/keys/rotate",
        json={
            "success": True,
            "data": {
                "new_key": new_key,
                "migrated": {"roles": 1, "memberships": 0, "permissions": 0},
            },
        },
    )
    with make_client() as client:
        assert client.api_key == API_KEY
        result = client.rotate_key()
    assert result["data"]["new_key"] == new_key
    # The instance now authenticates as the new key.
    assert client.api_key == new_key
    assert client.session.headers["Authorization"] == f"Bearer {new_key}"


@responses.activate
def test_rotate_key_transport_failure_leaves_key_unchanged():
    with make_client() as client:  # nothing registered -> connection error
        result = client.rotate_key()
        assert result["success"] is False and "error" in result
        assert client.api_key == API_KEY  # not rotated on failure


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


def test_pool_params_reach_the_adapter():
    """Regression (runflow report): pool_connections/pool_maxsize were accepted
    by the constructor but never passed to the mounted adapter, leaving the
    pool at urllib3's default 10 regardless of what the caller asked for."""
    # Known-positive first: a custom value must propagate before the default
    # asserts below mean anything.
    with make_client(pool_connections=3, pool_maxsize=7) as client:
        adapter = client.session.get_adapter("https://x")
        assert adapter._pool_connections == 3
        assert adapter._pool_maxsize == 7
    with make_client() as client:
        adapter = client.session.get_adapter("https://x")
        assert adapter._pool_connections == 10
        assert adapter._pool_maxsize == 64
    # Both schemes get the same adapter config.
    with make_client(pool_maxsize=5) as client:
        assert client.session.get_adapter("http://x")._pool_maxsize == 5


@responses.activate
def test_transport_failure_payload_is_marked():
    """Failure payloads carry transport_error=True and data WITHOUT the answer
    field — the unmissable marker runflow asked for."""
    with make_client() as client:  # nothing registered -> connection error
        result = client.user_has_permission("alice", "manage_users")
    assert result["success"] is False
    assert result["transport_error"] is True
    assert "error" in result
    assert result["data"] == {"user": "alice", "name": "manage_users"}
    assert "has_permission" not in result["data"]


@responses.activate
def test_success_payload_has_no_transport_marker():
    responses.get(
        f"{BASE}/api/has_permission/alice/manage_users",
        json={"success": True, "data": {"has_permission": True}},
    )
    with make_client() as client:
        result = client.user_has_permission("alice", "manage_users")
    assert result["data"]["has_permission"] is True
    assert "transport_error" not in result


@responses.activate
def test_raise_on_error_raises_on_transport_failure():
    # Green first: with a live endpoint the flag changes nothing.
    responses.get(
        f"{BASE}/api/has_permission/alice/manage_users",
        json={"success": True, "data": {"has_permission": True}},
    )
    with make_client(raise_on_error=True) as client:
        ok = client.user_has_permission("alice", "manage_users")
        assert ok["data"]["has_permission"] is True
        # Red: unregistered endpoint -> connection error -> raises, never a dict.
        with pytest.raises(AuthTransportError):
            client.get_user_permissions("alice")
        with pytest.raises(AuthTransportError):
            client.rotate_key()
    # api_key untouched by the failed rotate.
    assert client.api_key == API_KEY


@responses.activate
def test_raise_on_error_chains_original_cause():
    with make_client(raise_on_error=True) as client:
        with pytest.raises(AuthTransportError) as excinfo:
            client.ping()
    assert excinfo.value.__cause__ is not None


@responses.activate
def test_http_error_status_raises_under_raise_on_error():
    """A 5xx after retries is a transport-level failure too."""
    responses.get(f"{BASE}/api/roles", json={"detail": "boom"}, status=500)
    with make_client(raise_on_error=True, max_retries=0) as client:
        with pytest.raises(AuthTransportError):
            client.list_roles()


SECRET = "rak_" + "a1B2" * 10 + "c3d"  # 43-char payload, display prefix rak_a1B2a1B2


@responses.activate
def test_create_api_key_posts_label_and_uses_no_retry_session():
    responses.post(
        f"{BASE}/api/apikeys/user/alice",
        json={"success": True, "data": {"api_key": SECRET, "key_id": "k"}},
    )
    with make_client() as client:
        result = client.create_api_key("alice", label="laptop")
        assert result["data"]["api_key"] == SECRET
        assert responses.calls[0].request.body == b'{"label": "laptop"}'
        # The create path runs on the dedicated no-retry session: its adapter
        # carries zero retries, while the main session's adapter retries.
        no_retry_adapter = client._no_retry.get_adapter("https://x")
        assert no_retry_adapter.max_retries.total == 0
        assert client.session.get_adapter("https://x").max_retries.total > 0
        # Both sessions share one header mapping, so rotate_key updates both.
        assert client._no_retry.headers is client.session.headers


@responses.activate
def test_create_api_key_without_label_sends_no_body():
    responses.post(
        f"{BASE}/api/apikeys/user/alice",
        json={"success": True, "data": {"api_key": SECRET}},
    )
    with make_client() as client:
        client.create_api_key("alice")
    assert responses.calls[0].request.body is None


@responses.activate
def test_api_key_lifecycle_methods_hit_expected_endpoints():
    responses.get(
        f"{BASE}/api/apikeys/user/alice",
        json={"success": True, "data": {"count": 0, "keys": []}},
    )
    responses.delete(
        f"{BASE}/api/apikeys/user/alice/kid-1",
        json={"success": True, "data": {"revoked": True, "already_revoked": False}},
    )
    responses.post(
        f"{BASE}/api/apikeys/validate",
        json={"success": True, "data": {"valid": True, "user": "alice"}},
    )
    with make_client() as client:
        assert client.list_api_keys("alice")["data"]["count"] == 0
        assert client.revoke_api_key("alice", "kid-1")["data"]["revoked"] is True
        validated = client.validate_api_key(SECRET)
        assert validated["data"]["valid"] is True
    assert responses.calls[2].request.body == (
        '{"api_key": "%s"}' % SECRET
    ).encode()


@responses.activate
def test_validate_api_key_failure_payload_echoes_prefix_never_secret():
    with make_client() as client:  # nothing registered -> connection error
        result = client.validate_api_key(SECRET)
    assert result["success"] is False and result["transport_error"] is True
    assert result["data"] == {"key_prefix": SECRET[:12]}
    assert SECRET not in str(result)


@responses.activate
def test_create_api_key_raises_under_raise_on_error():
    with make_client(raise_on_error=True) as client:
        with pytest.raises(AuthTransportError):
            client.create_api_key("alice")


@responses.activate
def test_check_api_key_permission_and_settings_methods():
    responses.post(
        f"{BASE}/api/apikeys/check_permission",
        json={
            "success": True,
            "data": {"valid": True, "user": "alice", "has_permission": True},
        },
    )
    responses.get(
        f"{BASE}/api/settings",
        json={"success": True, "data": {"strict_users": False}},
    )
    responses.put(
        f"{BASE}/api/settings",
        json={"success": True, "data": {"strict_users": True}},
    )
    with make_client() as client:
        checked = client.check_api_key_permission(SECRET, "deploy")
        assert checked["data"]["has_permission"] is True
        assert responses.calls[0].request.body == (
            '{"api_key": "%s", "permission": "deploy"}' % SECRET
        ).encode()
        assert client.get_settings()["data"]["strict_users"] is False
        flipped = client.set_strict_users(True)
        assert flipped["data"]["strict_users"] is True
        assert responses.calls[2].request.body == b'{"strict_users": true}'


@responses.activate
def test_check_api_key_permission_failure_echoes_prefix_never_secret():
    with make_client() as client:  # nothing registered -> connection error
        result = client.check_api_key_permission(SECRET, "deploy")
    assert result["success"] is False and result["transport_error"] is True
    assert result["data"] == {"key_prefix": SECRET[:12], "permission": "deploy"}
    assert SECRET not in str(result)
