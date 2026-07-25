"""
Auditability integrity (audit findings A1/A2/A4).

A1 — the audit row is written in the SAME transaction as the mutation, so a
mutation cannot commit unaudited: if the audit write fails, the mutation rolls
back (fail-closed).
A2 — the recorded ``success`` reflects whether the write actually took effect,
not merely that HTTP was 200. A no-op write (missing role -> result:false) is
audited as a failure; a read that answers "false" is still a success.
A4 — key rotation is audited on success AND failure.
"""

import uuid
from unittest.mock import patch

import pytest

from auth.audit import AuditLog, client_fingerprint
from auth.database import SessionLocal
from auth.main import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _audit_rows(key):
    fpr = client_fingerprint(key)
    s = SessionLocal()
    try:
        return (
            s.query(AuditLog)
            .filter(AuditLog.client_id == fpr)
            .order_by(AuditLog.id)
            .all()
        )
    finally:
        s.close()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def test_successful_write_is_audited_success_true(client):
    key = str(uuid.uuid4())
    assert client.post("/api/role/engineers", headers=_h(key)).status_code == 200
    rows = _audit_rows(key)
    assert len(rows) == 1
    assert rows[0].action == "CREATE_ROLE"
    assert rows[0].success == 1


def test_noop_write_to_missing_role_is_audited_as_failure(client):
    """A2: 200 {"result": false} did nothing — the audit must not claim success."""
    key = str(uuid.uuid4())
    resp = client.post("/api/membership/alice/ghosts", headers=_h(key))
    assert resp.get_json() == {"result": False}
    rows = _audit_rows(key)
    assert len(rows) == 1
    assert rows[0].action == "ADD_MEMBERSHIP"
    assert rows[0].success == 0  # <-- the write did not take effect


def test_read_answering_false_is_still_a_success(client):
    """A permission check that answers has_permission:false succeeded as a read."""
    key = str(uuid.uuid4())
    client.get("/api/has_permission/alice/deploy", headers=_h(key))
    rows = _audit_rows(key)
    assert len(rows) == 1
    assert rows[0].action == "CHECK_PERMISSION"
    assert rows[0].success == 1


def test_audit_failure_rolls_back_the_mutation(client):
    """A1 (the load-bearing one): if the audit row cannot be written, the
    mutation must NOT commit. Force record_audit to raise and prove the role was
    never created and no audit row leaked."""
    key = str(uuid.uuid4())
    with patch(
        "auth.decorators.record_audit", side_effect=RuntimeError("audit sink down")
    ):
        resp = client.post("/api/role/engineers", headers=_h(key))
    assert resp.status_code == 500

    # The mutation must have rolled back: the role does not exist...
    roles = client.get("/api/roles", headers=_h(key)).get_json()["result"]
    assert roles == []
    # ...and no CREATE_ROLE audit row was committed for it (the read above is
    # itself audited as LIST_ROLES, which is expected — but the failed write's
    # audit must be absent).
    assert [r for r in _audit_rows(key) if r.action == "CREATE_ROLE"] == []


def test_audit_stores_no_plaintext_user_pii(client):
    """A3: the managed user is PII (often an email). It must be fingerprinted in
    the `user` column and inside `resource`, never stored in plaintext."""
    key = str(uuid.uuid4())
    user = "alice@example.com"
    client.post("/api/role/engineers", headers=_h(key))
    client.post(f"/api/membership/{user}/engineers", headers=_h(key))

    add = [r for r in _audit_rows(key) if r.action == "ADD_MEMBERSHIP"]
    assert len(add) == 1
    row = add[0]
    # user column is a fingerprint, not the raw email
    assert row.user == client_fingerprint(user)
    assert user not in (row.user or "")
    # resource embeds the fingerprint, not the raw email
    assert user not in (row.resource or "")
    assert client_fingerprint(user) in (row.resource or "")


def test_rotation_success_and_failure_are_audited(client):
    key = str(uuid.uuid4())
    client.post("/api/role/engineers", headers=_h(key))

    # success
    new_key = client.post("/api/keys/rotate", headers=_h(key)).get_json()["data"][
        "new_key"
    ]
    rot = [r for r in _audit_rows(key) if r.action == "ROTATE_KEY"]
    assert len(rot) == 1 and rot[0].success == 1
    # links old -> new fingerprint, never raw keys
    assert rot[0].resource == client_fingerprint(new_key)
    assert key not in (rot[0].resource or "") and new_key not in (rot[0].client_id or "")

    # failure (rotate again from new_key, but force the service to blow up)
    with patch(
        "auth.services.service.AuthorizationService.rotate_client_key",
        side_effect=RuntimeError("boom"),
    ):
        resp = client.post("/api/keys/rotate", headers=_h(new_key))
    assert resp.status_code == 500
    rot2 = [r for r in _audit_rows(new_key) if r.action == "ROTATE_KEY"]
    assert len(rot2) == 1 and rot2[0].success == 0
