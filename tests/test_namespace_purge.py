import hashlib
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


def _fp(key):
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _seed(client):
    key = str(uuid.uuid4())
    h = _h(key)
    secret = client.post("/api/apikeys/user/alice", headers=h).get_json()["data"]["api_key"]
    client.post("/api/apikeys/user/bob", headers=h)
    for role in ("editors", "viewers", "retired"):
        assert client.post(f"/api/role/{role}", headers=h).status_code in (200, 201)
    client.post("/api/permission/editors/doc-edit", headers=h)
    client.post("/api/permission/viewers/doc-read", headers=h)
    assert client.post("/api/membership/alice/editors", headers=h).get_json()["result"] is True
    assert client.post("/api/membership/bob/viewers", headers=h).get_json()["result"] is True
    client.delete("/api/role/retired", headers=h)
    rotate_key = client.post("/api/keys/get_rotate_key", headers=h).get_json()["data"]["rotate_key"]
    return key, secret, rotate_key


def _summary(client, key):
    response = client.get("/api/namespace", headers=_h(key))
    assert response.status_code == 200
    return response.get_json()["data"]


def _purge(client, key, body):
    return client.delete("/api/namespace", json=body, headers=_h(key))


def _audit(client, key, action):
    return client.get(f"/api/audit?action={action}", headers=_h(key)).get_json()["data"]["entries"]


def test_summary_counts_what_a_purge_would_delete(client):
    key, _, _ = _seed(client)
    assert _summary(client, key) == {
        "fingerprint": _fp(key),
        "roles": 3,
        "permissions": 2,
        "memberships": 2,
        "api_keys": 2,
        "settings": True,
        "recovery_key": True,
    }


def test_empty_namespace_summary(client):
    key = str(uuid.uuid4())
    assert _summary(client, key) == {
        "fingerprint": _fp(key),
        "roles": 0,
        "permissions": 0,
        "memberships": 0,
        "api_keys": 0,
        "settings": False,
        "recovery_key": False,
    }


@pytest.mark.parametrize(
    "body",
    [None, {}, {"confirm": ""}, {"confirm": "0" * 12}, {"confirm": "FP", "force": True}],
)
def test_refused_purge_deletes_nothing_and_is_audited(client, body):
    key, secret, _ = _seed(client)
    before = _summary(client, key)
    if body is not None and body.get("confirm") == "FP":
        body["confirm"] = _fp(key)
    response = _purge(client, key, body)
    assert response.status_code == 400
    assert _summary(client, key) == before
    valid = client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    assert valid.get_json()["data"]["valid"] is True
    entry = _audit(client, key, "PURGE_NAMESPACE")[0]
    assert entry["success"] is False
    assert entry["details"]["reason"] in ("confirm_required", "confirm_mismatch")


def test_purge_erases_everything_and_reports_counts(client):
    key, secret, rotate_key = _seed(client)
    response = _purge(client, key, {"confirm": _fp(key)})
    assert response.status_code == 200
    assert response.get_json()["data"] == {
        "fingerprint": _fp(key),
        "memberships": 2,
        "permissions": 2,
        "roles": 3,
        "api_keys": 2,
        "settings": True,
        "recovery_key": True,
        "role_links": 4,
    }
    h = _h(key)
    after = _summary(client, key)
    assert {k: v for k, v in after.items() if k != "fingerprint"} == {
        "roles": 0,
        "permissions": 0,
        "memberships": 0,
        "api_keys": 0,
        "settings": False,
        "recovery_key": False,
    }
    valid = client.post("/api/apikeys/validate", json={"api_key": secret}, headers=h)
    assert valid.get_json()["data"] == {"valid": False, "reason": "unknown_key"}
    assert client.get("/api/roles", headers=h).get_json() == {"result": []}
    has = client.get("/api/has_permission/alice/doc-edit", headers=h).get_json()["data"]
    assert has["has_permission"] is False
    recovered = client.post("/api/keys/recover", json={"rotate_key": rotate_key})
    assert recovered.status_code == 401
    assert client.get("/api/settings", headers=h).get_json()["data"]["strict_users"] is True


def test_purge_is_audited_with_the_counts_and_keeps_earlier_entries(client):
    key, _, _ = _seed(client)
    created_before = len(_audit(client, key, "CREATE_ROLE"))
    assert created_before == 3
    _purge(client, key, {"confirm": _fp(key)})
    entry = _audit(client, key, "PURGE_NAMESPACE")[0]
    assert entry["success"] is True
    assert entry["resource"] == "namespace"
    assert entry["details"]["roles"] == 3
    assert entry["details"]["api_keys"] == 2
    assert entry["details"]["role_links"] == 4
    assert len(_audit(client, key, "CREATE_ROLE")) == created_before


def test_purge_leaves_other_namespaces_untouched(client):
    key, _, _ = _seed(client)
    other, other_secret, _ = _seed(client)
    before = _summary(client, other)
    assert _purge(client, key, {"confirm": _fp(key)}).status_code == 200
    assert _summary(client, other) == before
    valid = client.post("/api/apikeys/validate", json={"api_key": other_secret}, headers=_h(other))
    assert valid.get_json()["data"]["valid"] is True
    has = client.get("/api/has_permission/alice/doc-edit", headers=_h(other)).get_json()["data"]
    assert has["has_permission"] is True


def test_confirm_for_another_namespace_is_refused(client):
    key, _, _ = _seed(client)
    other, _, _ = _seed(client)
    assert _purge(client, key, {"confirm": _fp(other)}).status_code == 400
    assert _summary(client, other)["roles"] == 3
    assert _summary(client, key)["roles"] == 3


def test_the_same_key_reopens_an_empty_namespace(client):
    key, _, _ = _seed(client)
    _purge(client, key, {"confirm": _fp(key)})
    h = _h(key)
    assert client.post("/api/role/fresh", headers=h).status_code in (200, 201)
    assert client.post("/api/membership/alice/fresh", headers=h).get_json()["result"] is False
    assert _summary(client, key)["roles"] == 1
