"""HTTP-level tests for the per-user API-key lifecycle (SPEC 0004).

Every negative assertion here is paired with a positive that proves the check
can go green: validate is shown valid=True on a live key before revoked/
expired/unknown reds are trusted, the cap is shown blocking AND releasing, and
the audit-leak scan first proves audit rows exist at all.
"""

import re
import uuid
from datetime import timedelta

import pytest

from auth.main import create_app
from auth.services.service import API_KEYS_PER_USER_CAP, _utcnow

RAK = re.compile(r"^rak_[0-9A-Za-z]{43}$")


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _create(client, key, user, **body):
    if body:
        return client.post(f"/api/apikeys/user/{user}", headers=_h(key), json=body)
    return client.post(f"/api/apikeys/user/{user}", headers=_h(key))


def _validate(client, key, secret):
    return client.post(
        "/api/apikeys/validate", headers=_h(key), json={"api_key": secret}
    )


def _list(client, key, user):
    return client.get(f"/api/apikeys/user/{user}", headers=_h(key)).get_json()["data"]


def _row(secret):
    """Direct row lookup — used only to seed states (expiry, staleness) that
    the API deliberately cannot produce in v1."""
    from auth.api_keys import hash_api_key
    from auth.database import SessionLocal
    from auth.models.sql import AuthApiKey

    session = SessionLocal()
    row = (
        session.query(AuthApiKey)
        .filter(AuthApiKey.key_hash == hash_api_key(secret))
        .one()
    )
    return session, row


def test_create_returns_secret_once_with_metadata(client):
    key = str(uuid.uuid4())
    resp = _create(client, key, "alice")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    data = body["data"]
    assert RAK.match(data["api_key"])
    assert str(uuid.UUID(data["key_id"], version=4)) == data["key_id"]
    assert data["user"] == "alice"
    assert data["label"] is None
    assert data["key_prefix"] == data["api_key"][:12]
    assert data["created"] is not None
    assert data["expires_at"] is None
    # Two creates never repeat a secret or key_id.
    second = _create(client, key, "alice").get_json()["data"]
    assert second["api_key"] != data["api_key"]
    assert second["key_id"] != data["key_id"]


def test_list_shows_metadata_never_secret_or_hash(client):
    key = str(uuid.uuid4())
    created = _create(client, key, "alice", label="laptop").get_json()["data"]
    listing = _list(client, key, "alice")
    assert listing["count"] == 1
    entry = listing["keys"][0]
    assert entry["key_id"] == created["key_id"]
    assert entry["label"] == "laptop"
    assert entry["is_active"] is True
    assert entry["revoked_at"] is None
    assert "api_key" not in entry and "key_hash" not in entry
    # The full secret appears nowhere in the listing (the 12-char display
    # prefix is expected; the 47-char secret is not).
    import json as _json

    assert created["api_key"] not in _json.dumps(listing)
    # Unknown user: empty list, not an error.
    assert _list(client, key, "nobody")["count"] == 0


def test_create_input_validation(client):
    key = str(uuid.uuid4())
    assert _create(client, key, "bad name").status_code == 400
    assert _create(client, key, "alice", label="<script>").status_code == 400
    assert _create(client, key, "alice", label="x" * 65).status_code == 400
    malformed = client.post(
        "/api/apikeys/user/alice",
        headers=_h(key),
        data="{not json",
        content_type="application/json",
    )
    assert malformed.status_code == 400
    # And the happy path still works after the rejects (nothing was created).
    assert _list(client, key, "alice")["count"] == 0
    assert _create(client, key, "alice", label="ok label").status_code == 200


def test_validate_green_then_revoked_red_and_idempotent_revoke(client):
    key = str(uuid.uuid4())
    data = _create(client, key, "alice").get_json()["data"]
    secret, key_id = data["api_key"], data["key_id"]

    # GREEN first.
    valid = _validate(client, key, secret).get_json()["data"]
    assert valid["valid"] is True
    assert valid["user"] == "alice"
    assert valid["key_id"] == key_id

    # Tampered secret (same shape, wrong value) -> unknown_key.
    tampered = secret[:-1] + ("A" if secret[-1] != "A" else "B")
    assert _validate(client, key, tampered).get_json()["data"] == {
        "valid": False,
        "reason": "unknown_key",
    }

    # Revoke flips validate to red and the listing to inactive.
    revoke = client.delete(f"/api/apikeys/user/alice/{key_id}", headers=_h(key))
    assert revoke.status_code == 200
    assert revoke.get_json()["data"] == {"revoked": True, "already_revoked": False}
    assert _validate(client, key, secret).get_json()["data"] == {
        "valid": False,
        "reason": "revoked",
    }
    entry = _list(client, key, "alice")["keys"][0]
    assert entry["is_active"] is False
    assert entry["revoked_at"] is not None

    # Second revoke: 200, marked as the repeat it is.
    again = client.delete(f"/api/apikeys/user/alice/{key_id}", headers=_h(key))
    assert again.status_code == 200
    assert again.get_json()["data"] == {"revoked": True, "already_revoked": True}


def test_validate_body_and_format_errors(client):
    key = str(uuid.uuid4())
    no_body = client.post("/api/apikeys/validate", headers=_h(key))
    assert no_body.status_code == 400
    assert (
        client.post(
            "/api/apikeys/validate", headers=_h(key), json={"api_key": 123}
        ).status_code
        == 400
    )
    assert _validate(client, key, "rak_tooshort").status_code == 400
    assert _validate(client, key, "not_a_key_at_all").status_code == 400
    # Well-formed but never issued: an answer (unknown_key), not an error.
    ghost = "rak_" + "a" * 43
    resp = _validate(client, key, ghost)
    assert resp.status_code == 200
    assert resp.get_json()["data"] == {"valid": False, "reason": "unknown_key"}


def test_revoke_error_matrix(client):
    key = str(uuid.uuid4())
    data = _create(client, key, "alice").get_json()["data"]
    assert (
        client.delete("/api/apikeys/user/alice/not-a-uuid", headers=_h(key)).status_code
        == 400
    )
    assert (
        client.delete("/api/apikeys/user/bad name/x", headers=_h(key)).status_code
        == 400
    )
    ghost_id = str(uuid.uuid4())
    missing = client.delete(f"/api/apikeys/user/alice/{ghost_id}", headers=_h(key))
    assert missing.status_code == 404
    assert missing.get_json()["success"] is False
    # Right key_id, wrong user: same 404, and the key stays live.
    wrong_user = client.delete(
        f"/api/apikeys/user/bob/{data['key_id']}", headers=_h(key)
    )
    assert wrong_user.status_code == 404
    assert _validate(client, key, data["api_key"]).get_json()["data"]["valid"] is True


def test_cross_tenant_isolation(client):
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    data = _create(client, tenant_a, "alice").get_json()["data"]

    # Owner green FIRST, then the foreign red means something.
    assert _validate(client, tenant_a, data["api_key"]).get_json()["data"]["valid"] is True
    assert _validate(client, tenant_b, data["api_key"]).get_json()["data"] == {
        "valid": False,
        "reason": "unknown_key",
    }
    # Foreign tenant cannot see or revoke it either.
    assert _list(client, tenant_b, "alice")["count"] == 0
    assert (
        client.delete(
            f"/api/apikeys/user/alice/{data['key_id']}", headers=_h(tenant_b)
        ).status_code
        == 404
    )
    # And the owner still validates green afterwards.
    assert _validate(client, tenant_a, data["api_key"]).get_json()["data"]["valid"] is True


def test_active_key_cap_blocks_and_releases(client):
    key = str(uuid.uuid4())
    created = [
        _create(client, key, "alice").get_json()["data"]
        for _ in range(API_KEYS_PER_USER_CAP)
    ]
    assert len(created) == API_KEYS_PER_USER_CAP

    over = _create(client, key, "alice")
    assert over.status_code == 400
    assert "limit" in over.get_json()["message"].lower()
    # The cap is per (tenant, user): another user is unaffected.
    assert _create(client, key, "bob").status_code == 200

    # Revoking one key must free the slot again (a cap that only blocks is a
    # deadlock, not a limit).
    client.delete(
        f"/api/apikeys/user/alice/{created[0]['key_id']}", headers=_h(key)
    )
    assert _create(client, key, "alice").status_code == 200


def test_expired_key_answers_expired(client):
    key = str(uuid.uuid4())
    secret = _create(client, key, "alice").get_json()["data"]["api_key"]
    # Green while unexpired.
    assert _validate(client, key, secret).get_json()["data"]["valid"] is True

    session, row = _row(secret)
    try:
        row.expires_at = _utcnow() - timedelta(seconds=1)
        session.commit()
    finally:
        session.close()

    assert _validate(client, key, secret).get_json()["data"] == {
        "valid": False,
        "reason": "expired",
    }


def test_last_used_at_is_set_and_throttled(client):
    key = str(uuid.uuid4())
    secret = _create(client, key, "alice").get_json()["data"]["api_key"]
    assert _list(client, key, "alice")["keys"][0]["last_used_at"] is None

    _validate(client, key, secret)
    first = _list(client, key, "alice")["keys"][0]["last_used_at"]
    assert first is not None

    # Inside the 60s window a second validate must not rewrite it.
    _validate(client, key, secret)
    assert _list(client, key, "alice")["keys"][0]["last_used_at"] == first

    # Backdate beyond the window: the next validate refreshes it.
    session, row = _row(secret)
    try:
        stale = _utcnow() - timedelta(seconds=120)
        row.last_used_at = stale
        session.commit()
    finally:
        session.close()
    _validate(client, key, secret)
    refreshed = _list(client, key, "alice")["keys"][0]["last_used_at"]
    assert refreshed != stale.isoformat()
    assert refreshed > stale.isoformat()


def test_audit_rows_exist_and_never_carry_the_secret(client):
    from auth.audit import AuditLog
    from auth.database import SessionLocal

    key = str(uuid.uuid4())
    data = _create(client, key, "alice", label="laptop").get_json()["data"]
    secret = data["api_key"]
    _list(client, key, "alice")
    _validate(client, key, secret)
    client.delete(f"/api/apikeys/user/alice/{data['key_id']}", headers=_h(key))

    session = SessionLocal()
    try:
        rows = session.query(AuditLog).all()
        actions = {row.action for row in rows}
        # Known-positive: the actions were recorded at all.
        for expected in (
            "CREATE_API_KEY",
            "LIST_API_KEYS",
            "VALIDATE_API_KEY",
            "REVOKE_API_KEY",
        ):
            assert expected in actions
        # The managed user is fingerprinted on the api-key rows, never plaintext.
        api_rows = [r for r in rows if r.action.endswith("_API_KEY") or r.action == "LIST_API_KEYS"]
        assert any(r.user and r.user.startswith("fpr_") for r in api_rows)
        assert all(r.user != "alice" for r in api_rows)
        # And no row, in any column, contains the secret — or any rak_ string.
        for row in rows:
            flat = "|".join(
                str(v)
                for v in (
                    row.client_id,
                    row.user,
                    row.action,
                    row.resource,
                    row.details,
                    row.user_agent,
                )
            )
            assert secret not in flat
            assert "rak_" not in flat
    finally:
        session.close()


def test_all_apikey_endpoints_require_auth(client):
    assert client.post("/api/apikeys/user/alice").status_code == 401
    assert client.get("/api/apikeys/user/alice").status_code == 401
    assert (
        client.delete(f"/api/apikeys/user/alice/{uuid.uuid4()}").status_code == 401
    )
    assert client.post("/api/apikeys/validate").status_code == 401
    # Malformed bearer -> 400 from the gate, same as every /api/* route.
    assert (
        client.post(
            "/api/apikeys/validate", headers={"Authorization": "Bearer nope"}
        ).status_code
        == 400
    )
