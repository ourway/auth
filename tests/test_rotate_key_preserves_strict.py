import uuid

import pytest

from auth.config import get_settings
from auth.main import create_app


@pytest.fixture(autouse=True)
def production_default(monkeypatch):
    monkeypatch.setattr(get_settings(), "strict_users_default", True)


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _strict(client, key):
    return client.get("/api/settings", headers=_h(key)).get_json()["data"]["strict_users"]


def _rotate_key(client, key):
    response = client.post("/api/keys/get_rotate_key", headers=_h(key))
    assert response.status_code == 200
    return response.get_json()["data"]["rotate_key"]


def _updates(client, key):
    return client.get("/api/audit?action=UPDATE_SETTINGS", headers=_h(key)).get_json()["data"]["total"]


def test_fetching_the_rotate_key_keeps_a_default_strict_namespace_strict(client):
    key = str(uuid.uuid4())
    client.post("/api/role/viewer", headers=_h(key))
    assert _strict(client, key) is True
    _rotate_key(client, key)
    assert _strict(client, key) is True
    refused = client.post("/api/membership/nokey/viewer", headers=_h(key))
    assert refused.status_code == 409
    assert refused.get_json()["reason"] == "user_not_key_backed"
    assert _updates(client, key) == 0


def test_fetching_the_rotate_key_keeps_an_opted_out_namespace_non_strict(client):
    key = str(uuid.uuid4())
    client.put("/api/settings", json={"strict_users": False}, headers=_h(key))
    _rotate_key(client, key)
    assert _strict(client, key) is False


def test_the_row_follows_the_configured_default(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "strict_users_default", False)
    key = str(uuid.uuid4())
    _rotate_key(client, key)
    monkeypatch.setattr(get_settings(), "strict_users_default", True)
    assert _strict(client, key) is False


def test_recovery_keeps_the_namespace_strict(client):
    key = str(uuid.uuid4())
    client.post("/api/role/viewer", headers=_h(key))
    secret = _rotate_key(client, key)
    new_key = str(uuid.uuid4())
    recovered = client.post(
        "/api/keys/recover", json={"rotate_key": secret, "new_client_key": new_key}
    )
    assert recovered.status_code == 200
    assert _strict(client, new_key) is True
    assert client.post("/api/membership/nokey/viewer", headers=_h(new_key)).status_code == 409


def test_rotate_key_audit_records_the_strict_value(client):
    key = str(uuid.uuid4())
    _rotate_key(client, key)
    client.post("/api/keys/get_rotate_key", headers=_h(key))
    entries = client.get(
        "/api/audit?action=GET_ROTATE_KEY", headers=_h(key)
    ).get_json()["data"]["entries"]
    second, first = entries[0], entries[1]
    assert first["details"]["strict_users"] is True
    assert first["details"]["settings_row_created"] is True
    assert second["details"]["strict_users"] is True
    assert second["details"]["settings_row_created"] is False
