import uuid
from datetime import datetime, timedelta, timezone

import pytest

import auth.services.keys as keys_module
from auth.main import create_app
from auth.services.keys import API_KEYS_PER_USER_CAP


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _namespace(client):
    key = str(uuid.uuid4())
    client.put("/api/settings", json={"strict_users": False}, headers=_h(key))
    return key


def _mint(client, key, body=None, user="svc"):
    return client.post(f"/api/apikeys/user/{user}", json=body or {}, headers=_h(key))


def _listing(client, key, user="svc"):
    return client.get(f"/api/apikeys/user/{user}", headers=_h(key)).get_json()["data"]


def _fill(client, key, live):
    ids = []
    for i in range(live):
        resp = _mint(client, key, {"label": f"k{i}"})
        assert resp.status_code == 200, resp.get_json()
        ids.append(resp.get_json()["data"]["key_id"])
    return ids


def test_cap_refuses_once_full_of_unexpired_keys(client):
    key = _namespace(client)
    _fill(client, key, API_KEYS_PER_USER_CAP)
    refused = _mint(client, key, {"label": "one-too-many"})
    assert refused.status_code == 400
    assert "limit reached" in refused.get_json()["message"]
    assert _listing(client, key)["count"] == API_KEYS_PER_USER_CAP


def test_expired_key_frees_its_slot_exactly_at_expiry(client, monkeypatch):
    key = _namespace(client)
    _fill(client, key, API_KEYS_PER_USER_CAP - 1)
    when = (_now() + timedelta(days=1)).replace(microsecond=0)
    short = _mint(client, key, {"label": "short", "expires_at": when.isoformat()})
    assert short.status_code == 200
    short_id = short.get_json()["data"]["key_id"]

    monkeypatch.setattr(keys_module, "_utcnow", lambda: when - timedelta(seconds=1))
    before = _mint(client, key, {"label": "before-expiry"})
    assert before.status_code == 400

    monkeypatch.setattr(keys_module, "_utcnow", lambda: when)
    after = _mint(client, key, {"label": "at-expiry"})
    assert after.status_code == 200, after.get_json()

    again = _mint(client, key, {"label": "cap-again"})
    assert again.status_code == 400

    listing = _listing(client, key)
    assert listing["count"] == API_KEYS_PER_USER_CAP + 1
    expired = next(k for k in listing["keys"] if k["key_id"] == short_id)
    assert expired["is_active"] is True
    assert expired["revoked_at"] is None
    assert expired["expires_at"] == when.isoformat()


def test_revoked_key_still_frees_its_slot(client):
    key = _namespace(client)
    ids = _fill(client, key, API_KEYS_PER_USER_CAP)
    assert _mint(client, key).status_code == 400
    revoked = client.delete(f"/api/apikeys/user/svc/{ids[0]}", headers=_h(key))
    assert revoked.get_json()["data"] == {"revoked": True, "already_revoked": False}
    assert _mint(client, key).status_code == 200
    assert _mint(client, key).status_code == 400


def test_other_users_expired_keys_do_not_free_this_users_slots(client, monkeypatch):
    key = _namespace(client)
    when = (_now() + timedelta(days=1)).replace(microsecond=0)
    other = _mint(client, key, {"expires_at": when.isoformat()}, user="other")
    assert other.status_code == 200
    _fill(client, key, API_KEYS_PER_USER_CAP)
    monkeypatch.setattr(keys_module, "_utcnow", lambda: when)
    assert _mint(client, key).status_code == 400
