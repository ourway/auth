import json
import uuid

import pytest

from auth.main import create_app


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _namespace(client):
    key = str(uuid.uuid4())
    h = _h(key)
    client.put("/api/settings", json={"strict_users": False}, headers=h)
    assert client.post("/api/role/clients", headers=h).get_json()["result"] is True
    assert client.post("/api/permission/clients/cases-read", headers=h).get_json()["result"] is True
    assert client.post("/api/membership/svc/clients", headers=h).get_json()["result"] is True
    return key


def _create_key(client, key, user="svc"):
    data = client.post(f"/api/apikeys/user/{user}", headers=_h(key)).get_json()["data"]
    return data["api_key"], data["key_id"]


def _entries(client, key, action):
    body = client.get(f"/api/audit?limit=100&action={action}", headers=_h(key)).get_json()
    return body["data"]["entries"]


def _check(client, key, secret, permission="cases-read"):
    return client.post(
        "/api/apikeys/check_permission",
        json={"api_key": secret, "permission": permission},
        headers=_h(key),
    )


def test_create_records_the_key_id(client):
    key = _namespace(client)
    secret, key_id = _create_key(client, key)
    [entry] = _entries(client, key, "CREATE_API_KEY")
    assert entry["details"]["key_id"] == key_id
    assert entry["success"] is True
    assert secret not in json.dumps(entry)


def test_valid_check_records_success_and_the_decision(client):
    key = _namespace(client)
    secret, key_id = _create_key(client, key)
    assert _check(client, key, secret).get_json()["data"]["has_permission"] is True
    assert _check(client, key, secret, "cases-write").get_json()["data"]["has_permission"] is False
    newest, older = _entries(client, key, "CHECK_API_KEY_PERMISSION")[:2]
    assert older["success"] is True
    assert older["resource"] == f"api_key:{key_id}"
    assert older["details"] == {
        "status_code": 200,
        "key_id": key_id,
        "valid": True,
        "permission": "cases-read",
        "has_permission": True,
    }
    assert newest["success"] is True
    assert newest["details"]["permission"] == "cases-write"
    assert newest["details"]["has_permission"] is False


def test_revoked_key_check_is_recorded_as_refused(client):
    key = _namespace(client)
    secret, key_id = _create_key(client, key)
    client.delete(f"/api/apikeys/user/svc/{key_id}", headers=_h(key))
    response = _check(client, key, secret)
    assert response.status_code == 200
    assert response.get_json()["data"] == {"valid": False, "reason": "revoked"}
    [entry] = _entries(client, key, "CHECK_API_KEY_PERMISSION")
    assert entry["success"] is False
    assert entry["resource"] == f"api_key:{key_id}"
    assert entry["details"]["key_id"] == key_id
    assert entry["details"]["valid"] is False
    assert entry["details"]["reason"] == "revoked"
    assert "has_permission" not in entry["details"]


def test_validate_records_both_outcomes(client):
    key = _namespace(client)
    secret, key_id = _create_key(client, key)
    client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    client.delete(f"/api/apikeys/user/svc/{key_id}", headers=_h(key))
    client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    refused, accepted = _entries(client, key, "VALIDATE_API_KEY")[:2]
    assert accepted["success"] is True
    assert accepted["details"]["valid"] is True
    assert accepted["details"]["key_id"] == key_id
    assert refused["success"] is False
    assert refused["details"]["reason"] == "revoked"
    assert refused["details"]["key_id"] == key_id


def test_unknown_and_foreign_keys_record_no_key_id(client):
    owner = _namespace(client)
    secret, key_id = _create_key(client, owner)
    stranger = _namespace(client)
    assert _check(client, stranger, secret).get_json()["data"]["reason"] == "unknown_key"
    _check(client, stranger, "rak_" + "A" * 43)
    for entry in _entries(client, stranger, "CHECK_API_KEY_PERMISSION"):
        assert entry["success"] is False
        assert entry["resource"] == "api_key"
        assert entry["details"]["key_id"] is None
        assert entry["details"]["reason"] == "unknown_key"
        assert key_id not in json.dumps(entry)


def test_no_secret_or_hash_in_any_key_audit_entry(client):
    from auth.api_keys import hash_api_key

    key = _namespace(client)
    secret, _ = _create_key(client, key)
    client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    _check(client, key, secret)
    entries = client.get("/api/audit?limit=100", headers=_h(key)).get_json()["data"]["entries"]
    assert any(e["action"] == "CHECK_API_KEY_PERMISSION" for e in entries)
    dumped = json.dumps(entries)
    assert secret not in dumped
    assert secret[4:] not in dumped
    assert hash_api_key(secret) not in dumped
