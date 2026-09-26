import uuid

import pytest

import auth.keycheck as keycheck
from auth.main import create_app

MARKER = "Service degraded"
MARKER_OFFSET = 102

REAL_DETAILS = [
    "the configured AUTH_ENCRYPTION_KEY cannot decrypt this deployment's canary "
    "- every authorization lookup would miss and answer negatively",
    "row level security is not in force on: auth_api_key, auth_group, auth_membership, "
    "auth_permission, auth_tenant_settings, membership_groups, permission_groups "
    "- tenant isolation would rest on query convention alone",
]


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


@pytest.fixture
def client_key():
    return str(uuid.uuid4())


@pytest.fixture
def degraded():
    saved = (keycheck.state(), keycheck.detail())

    def _set(detail):
        keycheck._state, keycheck._detail = keycheck.MISMATCH, detail

    yield _set
    keycheck._state, keycheck._detail = saved


def test_healthy_api_is_not_degraded(client, client_key):
    """Known-positive control: without this, every assertion below could pass
    because the route is broken rather than because degraded mode works."""
    resp = client.get("/api/roles", headers={"Authorization": f"Bearer {client_key}"})
    assert resp.status_code == 200


@pytest.mark.parametrize("detail", REAL_DETAILS)
def test_degraded_api_carries_the_marker_at_a_stable_offset(client, client_key, degraded, detail):
    """RODMENA L10n classify this response by scanning for MARKER in the first
    200 bytes. That was a heuristic they inferred from a body I sent them; this
    makes it a contract, so moving it fails here instead of silently changing
    how a consumer logs an encryption-key mismatch.

    The offset is asserted rather than mere presence: the marker precedes the
    variable detail, which is the property that makes a fixed-size scan window
    safe regardless of which failure produced it.
    """
    degraded(detail)
    resp = client.get("/api/roles", headers={"Authorization": f"Bearer {client_key}"})
    body = resp.get_data(as_text=True)

    assert resp.status_code == 503
    assert body.index(MARKER) == MARKER_OFFSET
    assert MARKER_OFFSET < 200
    # Werkzeug HTML-escapes the description, so an apostrophe in the detail
    # arrives as &#39; -- markupsafe's form, not the stdlib's &#x27;. A consumer
    # matching raw detail text against a real response will miss; the marker,
    # which contains no escapable character, will not.
    from markupsafe import escape

    assert str(escape(detail)) in body


def test_degraded_readyz_and_health_also_refuse(client, degraded):
    degraded(REAL_DETAILS[0])
    assert client.get("/health").status_code == 503
    assert client.get("/readyz").status_code == 503
    assert client.head("/health").status_code == 503
    assert client.head("/readyz").status_code == 503
