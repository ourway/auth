import hashlib
import os
import uuid

import pytest

pytestmark = pytest.mark.postgres

if os.environ.get("AUTH_DATABASE_TYPE") != "postgresql":
    pytest.skip(
        "AUTH_DATABASE_TYPE != postgresql — run via 'make test-postgres'",
        allow_module_level=True,
    )

import auth.admin as admin  # noqa: E402
import auth.services.purge as purge_module  # noqa: E402
from auth.database import create_tables, engine  # noqa: E402
from auth.main import create_app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


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
    client.put("/api/settings", json={"strict_users": False}, headers=h)
    secret = client.post("/api/apikeys/user/alice", headers=h).get_json()["data"]["api_key"]
    client.post("/api/role/editors", headers=h)
    client.post("/api/permission/editors/doc-edit", headers=h)
    client.post("/api/membership/alice/editors", headers=h)
    client.post("/api/keys/get_rotate_key", headers=h)
    return key, secret


def _summary(client, key):
    return client.get("/api/namespace", headers=_h(key)).get_json()["data"]


def test_purge_erases_one_namespace_and_leaves_the_other(client):
    key, secret = _seed(client)
    other, other_secret = _seed(client)
    before_other = _summary(client, other)
    assert _summary(client, key)["roles"] == 1
    response = client.delete("/api/namespace", json={"confirm": _fp(key)}, headers=_h(key))
    assert response.status_code == 200
    assert response.get_json()["data"]["role_links"] == 2
    after = _summary(client, key)
    assert (after["roles"], after["memberships"], after["api_keys"], after["settings"]) == (0, 0, 0, False)
    assert _summary(client, other) == before_other
    gone = client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    assert gone.get_json()["data"] == {"valid": False, "reason": "unknown_key"}
    kept = client.post("/api/apikeys/validate", json={"api_key": other_secret}, headers=_h(other))
    assert kept.get_json()["data"]["valid"] is True


def test_a_failure_part_way_rolls_back_everything(client, monkeypatch):
    key, secret = _seed(client)
    before = _summary(client, key)
    real_delete = purge_module.delete
    calls = {"n": 0}

    def failing_delete(table):
        calls["n"] += 1
        if calls["n"] == 4:
            raise RuntimeError("injected failure")
        return real_delete(table)

    monkeypatch.setattr(purge_module, "delete", failing_delete)
    response = client.delete("/api/namespace", json={"confirm": _fp(key)}, headers=_h(key))
    monkeypatch.setattr(purge_module, "delete", real_delete)
    assert response.status_code == 500
    assert calls["n"] == 4
    assert _summary(client, key) == before
    valid = client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    assert valid.get_json()["data"]["valid"] is True


def test_listing_needs_the_privileged_connection(client):
    url = admin.admin_url(os.environ)
    if url is None:
        pytest.skip("AUTH_ADMIN_DATABASE_URL not set; make test-postgres sets it")
    from sqlalchemy import create_engine

    with engine.connect() as conn:
        flags = conn.exec_driver_sql(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).one()
    assert tuple(flags) == (False, False)

    key, _ = _seed(client)
    assert admin.list_namespaces(engine) == []
    privileged = create_engine(url)
    try:
        listed = [r["fingerprint"] for r in admin.list_namespaces(privileged)]
    finally:
        privileged.dispose()
    assert hashlib.sha256(key.encode()).hexdigest()[:16] in listed
