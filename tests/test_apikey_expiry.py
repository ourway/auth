import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import responses

import auth.services.keys as keys_module
from auth import EnhancedAuthClient
from auth.key_expiry import KeyExpiryError, check_expiry, parse_expiry
from auth.main import create_app


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def _namespace(client):
    key = str(uuid.uuid4())
    h = _h(key)
    client.put("/api/settings", json={"strict_users": False}, headers=h)
    client.post("/api/role/clients", headers=h)
    client.post("/api/permission/clients/cases-read", headers=h)
    client.post("/api/membership/svc/clients", headers=h)
    return key


def _create(client, key, body, user="svc"):
    return client.post(f"/api/apikeys/user/{user}", json=body, headers=_h(key))


def _count(client, key, user="svc"):
    return client.get(f"/api/apikeys/user/{user}", headers=_h(key)).get_json()["data"]["count"]


def _patch(client, key, key_id, body, user="svc"):
    return client.patch(f"/api/apikeys/user/{user}/{key_id}", json=body, headers=_h(key))


def test_create_stores_and_reports_the_expiry(client):
    key = _namespace(client)
    when = _now() + timedelta(days=30)
    response = _create(client, key, {"label": "ci", "expires_at": _iso(when) + "Z"})
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["expires_at"] == _iso(when)
    listed = client.get("/api/apikeys/user/svc", headers=_h(key)).get_json()["data"]["keys"]
    assert listed[0]["expires_at"] == _iso(when)
    validated = client.post(
        "/api/apikeys/validate", json={"api_key": data["api_key"]}, headers=_h(key)
    ).get_json()["data"]
    assert validated["valid"] is True
    assert validated["expires_at"] == _iso(when)


def test_offset_form_is_converted_to_utc(client):
    key = _namespace(client)
    when = _now() + timedelta(days=2)
    local = when.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=2)))
    data = _create(client, key, {"expires_at": local.replace(microsecond=0).isoformat()}).get_json()["data"]
    assert data["expires_at"] == _iso(when)


def test_null_expiry_means_none(client):
    key = _namespace(client)
    data = _create(client, key, {"expires_at": None}).get_json()["data"]
    assert data["expires_at"] is None


@pytest.mark.parametrize(
    "offset,status",
    [
        (timedelta(days=365) - timedelta(minutes=5), 200),
        (timedelta(days=365) + timedelta(minutes=5), 400),
        (timedelta(minutes=5), 200),
        (-timedelta(minutes=5), 400),
    ],
)
def test_create_enforces_both_sides_of_the_window(client, offset, status):
    key = _namespace(client)
    response = _create(client, key, {"expires_at": _iso(_now() + offset)})
    assert response.status_code == status
    assert _count(client, key) == (1 if status == 200 else 0)


@pytest.mark.parametrize(
    "body",
    [
        {"expires_in_days": 30},
        {"label": "x", "scope": "read"},
        {"expires_at": "next tuesday"},
        {"expires_at": 1798761600},
    ],
)
def test_create_refuses_bad_bodies_and_creates_nothing(client, body):
    key = _namespace(client)
    response = _create(client, key, body)
    assert response.status_code == 400
    assert response.is_json
    assert _count(client, key) == 0


def test_patch_shortens_but_never_extends(client):
    key = _namespace(client)
    when = _now() + timedelta(days=90)
    key_id = _create(client, key, {"expires_at": _iso(when)}).get_json()["data"]["key_id"]
    shorter = _now() + timedelta(days=10)
    response = _patch(client, key, key_id, {"expires_at": _iso(shorter)})
    assert response.status_code == 200
    assert response.get_json()["data"]["expires_at"] == _iso(shorter)
    longer = _patch(client, key, key_id, {"expires_at": _iso(_now() + timedelta(days=20))})
    assert longer.status_code == 400
    same = _patch(client, key, key_id, {"expires_at": _iso(shorter)})
    assert same.status_code == 400
    listed = client.get("/api/apikeys/user/svc", headers=_h(key)).get_json()["data"]["keys"]
    assert listed[0]["expires_at"] == _iso(shorter)


def test_patch_sets_a_first_expiry_within_the_window(client):
    key = _namespace(client)
    key_id = _create(client, key, {}).get_json()["data"]["key_id"]
    too_far = _patch(client, key, key_id, {"expires_at": _iso(_now() + timedelta(days=400))})
    assert too_far.status_code == 400
    ok = _patch(client, key, key_id, {"expires_at": _iso(_now() + timedelta(days=100))})
    assert ok.status_code == 200


def test_patch_refuses_revoked_unknown_and_malformed(client):
    key = _namespace(client)
    key_id = _create(client, key, {}).get_json()["data"]["key_id"]
    when = {"expires_at": _iso(_now() + timedelta(days=5))}
    assert _patch(client, key, key_id, {**when, "label": "x"}).status_code == 400
    assert _patch(client, key, key_id, {}).status_code == 400
    assert _patch(client, key, str(uuid.uuid4()), when).status_code == 404
    other = _namespace(client)
    assert _patch(client, other, key_id, when).status_code == 404
    client.delete(f"/api/apikeys/user/svc/{key_id}", headers=_h(key))
    revoked = _patch(client, key, key_id, when)
    assert revoked.status_code == 400
    assert "revoked" in revoked.get_json()["message"]


def test_expiry_takes_effect_exactly_at_the_boundary(client, monkeypatch):
    key = _namespace(client)
    when = (_now() + timedelta(days=1)).replace(microsecond=0)
    secret = _create(client, key, {"expires_at": when.isoformat()}).get_json()["data"]["api_key"]

    def check():
        return client.post(
            "/api/apikeys/check_permission",
            json={"api_key": secret, "permission": "cases-read"},
            headers=_h(key),
        ).get_json()["data"]

    monkeypatch.setattr(keys_module, "_utcnow", lambda: when - timedelta(seconds=1))
    assert check() == {
        "valid": True,
        "user": "svc",
        "key_id": check()["key_id"],
        "has_permission": True,
    }
    monkeypatch.setattr(keys_module, "_utcnow", lambda: when)
    assert check() == {"valid": False, "reason": "expired"}
    entries = client.get(
        "/api/audit?limit=5&action=CHECK_API_KEY_PERMISSION", headers=_h(key)
    ).get_json()["data"]["entries"]
    assert entries[0]["success"] is False
    assert entries[0]["details"]["reason"] == "expired"
    assert entries[0]["details"]["key_id"]


def test_update_is_audited_with_the_key_id(client):
    key = _namespace(client)
    key_id = _create(client, key, {}).get_json()["data"]["key_id"]
    _patch(client, key, key_id, {"expires_at": _iso(_now() + timedelta(days=7))})
    [entry] = client.get(
        "/api/audit?limit=5&action=UPDATE_API_KEY", headers=_h(key)
    ).get_json()["data"]["entries"]
    assert entry["success"] is True
    assert entry["details"]["key_id"] == key_id
    assert entry["resource"].endswith(f":{key_id}")


def test_parse_and_check_units():
    now = datetime(2026, 10, 27, 12, 0, 0)
    assert parse_expiry("2026-11-01T00:00:00Z") == datetime(2026, 11, 1)
    assert parse_expiry("2026-11-01T02:00:00+02:00") == datetime(2026, 11, 1)
    assert parse_expiry("2026-11-01T00:00:00") == datetime(2026, 11, 1)
    for bad in ["", "soon", None, 5]:
        with pytest.raises(KeyExpiryError):
            parse_expiry(bad)
    check_expiry(now + timedelta(days=365), now)
    with pytest.raises(KeyExpiryError):
        check_expiry(now + timedelta(days=365, seconds=1), now)
    with pytest.raises(KeyExpiryError):
        check_expiry(now, now)
    with pytest.raises(KeyExpiryError):
        check_expiry(now + timedelta(days=2), now, current=now + timedelta(days=2))


@responses.activate
def test_client_sends_expiry_on_create_and_patch():
    base = "https://auth.example"
    key_id = str(uuid.uuid4())
    responses.add(responses.POST, f"{base}/api/apikeys/user/svc", json={"success": True, "data": {}})
    responses.add(responses.PATCH, f"{base}/api/apikeys/user/svc/{key_id}", json={"success": True, "data": {}})
    c = EnhancedAuthClient(api_key=str(uuid.uuid4()), service_url=base)
    when = datetime(2027, 1, 1, 2, 0, tzinfo=timezone(timedelta(hours=2)))
    c.create_api_key("svc", label="ci", expires_at=when)
    c.set_api_key_expiry("svc", key_id, "2026-12-01T00:00:00Z")
    assert json.loads(responses.calls[0].request.body or b"") == {
        "label": "ci",
        "expires_at": "2027-01-01T00:00:00",
    }
    assert responses.calls[1].request.method == "PATCH"
    assert json.loads(responses.calls[1].request.body or b"") == {"expires_at": "2026-12-01T00:00:00Z"}
