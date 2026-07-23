"""Phase A hardening: credential secrecy, auth-before-audit, audit robustness,
and the optional application-layer rate limiter.

These pin the security-relevant behaviour introduced in Phase A so it cannot
silently regress:
  * the raw client key never lands in an audit row (only a fingerprint);
  * unauthenticated / malformed requests do no audit (or DB) work;
  * an over-length field can never drop an audit row;
  * ``success`` reflects the real status code;
  * the rate limiter, when enabled, returns 429 and exempts public routes.
"""

import uuid

import pytest

from auth.audit import AuditLog, client_fingerprint
from auth.database import SessionLocal
from auth.main import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _audit_count() -> int:
    session = SessionLocal()
    try:
        return int(session.query(AuditLog).count())
    finally:
        session.close()


def _latest_audit():
    session = SessionLocal()
    try:
        return session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    finally:
        session.close()


def test_audit_stores_fingerprint_not_raw_token(client):
    key = str(uuid.uuid4())
    resp = client.get("/api/roles", headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 200

    session = SessionLocal()
    try:
        rows = session.query(AuditLog).all()
    finally:
        session.close()

    assert rows, "an authenticated request should produce an audit row"
    latest = rows[-1]
    assert latest.client_id == client_fingerprint(key)
    assert latest.client_id.startswith("fpr_")
    assert latest.client_id != key
    # The raw key must not appear in ANY audit row's client_id.
    assert all(key not in (row.client_id or "") for row in rows)


def test_fingerprint_is_deterministic_and_opaque():
    key = str(uuid.uuid4())
    assert client_fingerprint(key) == client_fingerprint(key)
    assert client_fingerprint(key) != client_fingerprint(str(uuid.uuid4()))
    assert client_fingerprint(None) == "anonymous"


def test_unauthenticated_request_writes_no_audit_row(client):
    before = _audit_count()
    resp = client.get("/api/roles")  # no Authorization header
    assert resp.status_code == 401
    assert _audit_count() == before


def test_invalid_client_key_writes_no_audit_row(client):
    before = _audit_count()
    resp = client.get("/api/roles", headers={"Authorization": "Bearer not-a-uuid"})
    assert resp.status_code == 400
    assert _audit_count() == before


def test_audit_row_survives_oversized_user_agent(client):
    key = str(uuid.uuid4())
    before = _audit_count()
    resp = client.get(
        "/api/roles",
        headers={"Authorization": f"Bearer {key}", "User-Agent": "A" * 5000},
    )
    assert resp.status_code == 200
    # The row was written, not dropped by an over-length INSERT.
    assert _audit_count() == before + 1
    assert len(_latest_audit().user_agent) <= 500


def test_authenticated_bad_input_is_recorded_as_failure(client):
    key = str(uuid.uuid4())
    resp = client.post("/api/role/bad!name", headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 400
    assert _latest_audit().success == 0


def test_rate_limiter_returns_429_when_enabled(monkeypatch):
    pytest.importorskip("flask_limiter")
    from auth.config import Settings

    rl = Settings(  # type: ignore[call-arg]
        enable_rate_limit=True,
        ratelimit_default="2/second",
        ratelimit_storage_uri="memory://",
    )
    monkeypatch.setattr("auth.main.get_settings", lambda: rl)

    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()

    key = str(uuid.uuid4())
    headers = {"Authorization": f"Bearer {key}"}
    codes = [c.get("/api/roles", headers=headers).status_code for _ in range(5)]

    assert 429 in codes, codes
    # Public endpoints stay exempt from limiting.
    assert c.get("/ping").status_code == 200
