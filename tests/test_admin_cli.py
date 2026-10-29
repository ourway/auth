import hashlib
import os
import uuid

import pytest
from sqlalchemy import create_engine

import auth.admin as admin
from auth.config import get_settings
from auth.database import SessionLocal, engine
from auth.main import create_app


@pytest.fixture(autouse=True)
def production_default(monkeypatch):
    monkeypatch.setattr(get_settings(), "strict_users_default", True)


@pytest.fixture(scope="module")
def admin_engine():
    url = admin.admin_url(os.environ)
    if url is None:
        yield engine
        return
    privileged = create_engine(url)
    yield privileged
    privileged.dispose()


@pytest.fixture
def client():
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _fp(key, n=16):
    return hashlib.sha256(key.encode()).hexdigest()[:n]


def _seed(client, role="casework"):
    key = str(uuid.uuid4())
    h = _h(key)
    secret = client.post("/api/apikeys/user/alice@example.test", headers=h).get_json()["data"][
        "api_key"
    ]
    client.post(f"/api/role/{role}", headers=h)
    client.post(f"/api/permission/{role}/case-read", headers=h)
    client.post(f"/api/membership/alice@example.test/{role}", headers=h)
    return key, secret


def _run(capsys, admin_engine, *argv):
    code = admin.run(list(argv), admin_engine, SessionLocal)
    out = capsys.readouterr()
    return code, out.out, out.err


def _row(out, key):
    lines = [line for line in out.splitlines() if line.startswith(_fp(key))]
    assert len(lines) == 1, out
    return lines[0].split()


def test_list_shows_counts_and_role_names_but_no_key_or_user(client, capsys, admin_engine):
    key, secret = _seed(client, role="admintest-reviewer")
    bare, _ = _seed(client, role="admintest-bare")
    client.put("/api/settings", json={"strict_users": True}, headers=_h(key))
    code, out, _ = _run(capsys, admin_engine, "namespaces", "list")
    assert _row(out, bare)[1:6] == ["1", "1", "1", "1", "no"]
    assert code == 0
    row = _row(out, key)
    assert row[1:6] == ["1", "1", "1", "1", "yes"]
    assert row[-1] == "admintest-reviewer"
    assert row[-2].endswith("Z") and row[-2] != "-"
    assert key not in out
    assert secret not in out
    assert "alice" not in out


def test_list_filters_by_role(client, capsys, admin_engine):
    key, _ = _seed(client, role="admintest-only-here")
    other, _ = _seed(client, role="admintest-elsewhere")
    code, out, _ = _run(capsys, admin_engine, "namespaces", "list", "--role", "admintest-only-here")
    assert code == 0
    assert _fp(key) in out
    assert _fp(other) not in out


@pytest.mark.parametrize(
    "fp, confirm, message",
    [
        ("KEY", "0" * 12, "--confirm must repeat --fp"),
        ("SHORT", "SHORT", "at least 12 hex"),
        ("f" * 12 + "zz", "f" * 12 + "zz", "at least 12 hex"),
        ("0" * 64, "0" * 64, "no namespace"),
    ],
)
def test_purge_refusals_change_nothing(client, capsys, admin_engine, fp, confirm, message):
    key, secret = _seed(client)
    full = _fp(key, 64)
    fp = {"KEY": full[:12], "SHORT": full[:11]}.get(fp, fp)
    confirm = {"SHORT": full[:11]}.get(confirm, confirm)
    code, _, err = _run(capsys, admin_engine, "namespaces", "purge", "--fp", fp, "--confirm", confirm)
    assert code == 2
    assert message in err
    summary = client.get("/api/namespace", headers=_h(key)).get_json()["data"]
    assert (summary["roles"], summary["api_keys"]) == (1, 1)
    valid = client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    assert valid.get_json()["data"]["valid"] is True


def test_ambiguous_prefix_is_refused(client, capsys, admin_engine, monkeypatch):
    _seed(client)
    _seed(client)
    monkeypatch.setattr(admin, "MIN_PREFIX", 0)
    code, _, err = _run(capsys, admin_engine, "namespaces", "purge", "--fp", "", "--confirm", "")
    assert code == 2
    assert "share that prefix" in err


def test_purge_by_fingerprint_erases_one_namespace_and_is_audited(client, capsys, admin_engine):
    key, secret = _seed(client)
    other, other_secret = _seed(client)
    prefix = _fp(key, 12)
    code, out, _ = _run(capsys, admin_engine, "namespaces", "purge", "--fp", prefix, "--confirm", prefix)
    assert code == 0
    assert out.startswith(f"purged {_fp(key)}: ")
    assert "roles=1" in out and "api_keys=1" in out
    assert key not in out
    summary = client.get("/api/namespace", headers=_h(key)).get_json()["data"]
    assert (summary["roles"], summary["memberships"], summary["api_keys"]) == (0, 0, 0)
    gone = client.post("/api/apikeys/validate", json={"api_key": secret}, headers=_h(key))
    assert gone.get_json()["data"] == {"valid": False, "reason": "unknown_key"}
    kept = client.post("/api/apikeys/validate", json={"api_key": other_secret}, headers=_h(other))
    assert kept.get_json()["data"]["valid"] is True
    entries = client.get(
        "/api/audit?action=PURGE_NAMESPACE", headers=_h(key)
    ).get_json()["data"]["entries"]
    assert entries[0]["details"]["via"] == "auth-admin"
    assert entries[0]["details"]["roles"] == 1
    assert entries[0]["success"] is True


@pytest.mark.parametrize(
    "value, message",
    [(None, "set AUTH_ADMIN_DATABASE_URL"), ("sqlite:///x.db", "must name a PostgreSQL")],
)
def test_main_refuses_without_a_postgresql_admin_url(monkeypatch, capsys, value, message):
    if value is None:
        monkeypatch.delenv("AUTH_ADMIN_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("AUTH_ADMIN_DATABASE_URL", value)
    assert admin.main(["namespaces", "list"]) == 2
    err = capsys.readouterr().err
    assert message in err
    assert "x.db" not in err


def test_admin_url_normalises_the_driver():
    url = admin.admin_url({"AUTH_ADMIN_DATABASE_URL": "postgresql://u:p@h/db"})
    assert url == "postgresql+psycopg://u:p@h/db"
    assert admin.admin_url({}) is None
