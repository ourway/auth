"""Self-service audit + actionable strict_users 409 (issuedb #2, SPEC 0016).

Covers the two gaps surfaced on 2026-08-12:
- ``GET /api/audit`` is namespace-scoped self-service diagnosis (own trail,
  newest first, paginated, action-filterable, never another tenant's rows,
  never a raw key/user).
- A strict-mode membership grant refused because the user is not key-backed
  answers 409 with ``reason: user_not_key_backed`` AND a ``hint`` naming the
  two ways forward.
"""

import uuid

import pytest

from auth.main import create_app


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


def _fresh_namespace(client):
    """A private namespace key (isolated per test, like the service model)."""
    key = str(uuid.uuid4())
    client.put("/api/settings", json={"strict_users": False}, headers=_h(key))
    return key


def _seed(client, key, user="alice", role="engineers"):
    h = _h(key)
    assert client.post(f"/api/role/{role}", headers=h).get_json()["result"] is True
    assert (
        client.post(f"/api/permission/{role}/deploy", headers=h).get_json()["result"]
        is True
    )
    assert (
        client.post(f"/api/membership/{user}/{role}", headers=h).get_json()["result"]
        is True
    )
    assert client.post(f"/api/apikeys/user/{user}", headers=h).status_code == 200


def test_audit_returns_own_namespace_only(client):
    """A caller sees exactly its own trail; another namespace sees zero rows."""
    key = _fresh_namespace(client)
    _seed(client, key)

    mine = client.get("/api/audit", headers=_h(key)).get_json()["data"]
    assert mine["total"] >= 5  # role + permission + membership + apikey + opt-out
    assert all(e["action"] for e in mine["entries"])
    # newest first
    ts = [e["id"] for e in mine["entries"]]
    assert ts == sorted(ts, reverse=True)

    # A brand-new, never-used namespace is genuinely empty — nothing of the
    # first namespace's trail leaks across.
    other = str(uuid.uuid4())
    theirs = client.get("/api/audit", headers=_h(other)).get_json()["data"]
    assert theirs["total"] == 0
    assert theirs["entries"] == []


def test_audit_pagination_and_action_filter(client):
    key = _fresh_namespace(client)
    _seed(client, key)

    page = client.get("/api/audit?limit=2&offset=0", headers=_h(key)).get_json()["data"]
    assert len(page["entries"]) == 2
    assert page["total"] >= 5

    filtered = client.get(
        "/api/audit?action=ADD_PERMISSION", headers=_h(key)
    ).get_json()["data"]
    assert filtered["total"] >= 1
    assert all(e["action"] == "ADD_PERMISSION" for e in filtered["entries"])


def test_audit_validates_pagination_bounds(client):
    key = _fresh_namespace(client)
    assert client.get("/api/audit?limit=501", headers=_h(key)).status_code == 400
    assert client.get("/api/audit?limit=0", headers=_h(key)).status_code == 400
    assert client.get("/api/audit?offset=-1", headers=_h(key)).status_code == 400
    assert client.get("/api/audit?limit=abc", headers=_h(key)).status_code == 400


def test_audit_never_leaks_raw_key_or_user(client):
    """Client/user fields stay non-reversible fingerprints; no raw key anywhere."""
    key = _fresh_namespace(client)
    _seed(client, key)
    data = client.get("/api/audit", headers=_h(key)).get_json()["data"]
    for e in data["entries"]:
        if e["user"]:
            assert e["user"].startswith("fpr_")
        raw = f"{e.get('resource') or ''} {e.get('details') or ''}"
        assert key.lower() not in raw.lower()


def test_strict_409_names_the_fix(client):
    """Strict-mode key-less membership answers 409 with reason + actionable hint."""
    key = str(uuid.uuid4())
    h = _h(key)
    client.put("/api/settings", json={"strict_users": True}, headers=h)
    assert client.post("/api/role/eng", headers=h).get_json()["result"] is True

    resp = client.post("/api/membership/alice/eng", headers=h)
    assert resp.status_code == 409
    body = resp.get_json()
    assert body["result"] is False
    assert body["reason"] == "user_not_key_backed"
    hint = body["hint"]
    assert "strict_users" in hint
    assert "/api/apikeys/user/alice" in hint
    assert "api/settings" in hint

    # the refused grant is recorded as a FAILED audit entry, not a success
    data = client.get("/api/audit", headers=h).get_json()["data"]
    failed = [e for e in data["entries"] if e["action"] == "ADD_MEMBERSHIP"]
    assert any(not e["success"] for e in failed)


def test_strict_409_releases_after_opt_out(client):
    """Opting the namespace out unblocks the same key-less grant (both directions)."""
    key = str(uuid.uuid4())
    h = _h(key)
    client.put("/api/settings", json={"strict_users": True}, headers=h)
    client.post("/api/role/eng", headers=h)
    assert client.post("/api/membership/alice/eng", headers=h).status_code == 409
    client.put("/api/settings", json={"strict_users": False}, headers=h)
    ok = client.post("/api/membership/alice/eng", headers=h)
    assert ok.status_code == 200
    assert ok.get_json()["result"] is True
