"""
Encryption-ON integration in the DEFAULT (sqlite) gate (audit T1/T3).

The routine CI gate (`make test`) runs with encryption OFF, so the encrypt/
decrypt integration that protects data at rest was only exercised by the
Docker-gated Postgres suite. This module flips field encryption ON for the whole
app (as production runs it) and drives the real HTTP paths, so a crypto-
integration regression fails CI without needing Docker. It also proves the
service fails CLOSED on a tampered/undecryptable row (T3), never serving garbage.
"""

import base64
import uuid

import pytest
from sqlalchemy import update

from auth.database import SessionLocal
from auth.main import create_app
from auth.models.sql import AuthMembership


@pytest.fixture
def enc(monkeypatch):
    from auth.encryption import DeterministicEncryption, FieldEncryption

    fe = FieldEncryption()
    fe.encryptor = DeterministicEncryption("ci-integration-encryption-key")
    fe.enabled = True
    # Both the model getters/setters and the service reference this module global.
    monkeypatch.setattr("auth.encryption.field_encryption", fe)
    return fe


@pytest.fixture
def client(enc):
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def test_full_lifecycle_with_encryption_on(client, enc):
    key = str(uuid.uuid4())
    user = "alice@example.com"
    assert client.post("/api/role/engineers", headers=_h(key)).get_json()["result"]
    assert client.post(
        "/api/permission/engineers/deploy", headers=_h(key)
    ).get_json()["result"]
    assert client.post(
        f"/api/membership/{user}/engineers", headers=_h(key)
    ).get_json()["result"]

    # Encrypt-on-write + decrypt-on-read + equality-query all work end to end.
    ans = client.get(f"/api/has_permission/{user}/deploy", headers=_h(key)).get_json()
    assert ans["data"]["has_permission"] is True
    members = client.get("/api/members/engineers", headers=_h(key)).get_json()["result"]
    assert [m["user"] for m in members] == [user]

    # And the value really is ciphertext at rest (v2, decryptable under the key).
    s = SessionLocal()
    try:
        stored = s.execute(
            AuthMembership.__table__.select().where(
                AuthMembership.__table__.c.creator == key
            )
        ).first()
    finally:
        s.close()
    raw_user = stored._mapping["user"]
    assert raw_user.startswith("v2:")
    assert enc.encryptor.decrypt(raw_user, key) == user


def test_tampered_row_fails_closed_at_the_api(client, enc):
    """T3: a stored cell that does not authenticate must make the read fail
    closed (500), not return corrupted/garbage plaintext."""
    key = str(uuid.uuid4())
    client.post("/api/role/engineers", headers=_h(key))
    client.post("/api/membership/bob@example.com/engineers", headers=_h(key))

    # Corrupt the encrypted user cell: a v2 value whose synthetic IV cannot be
    # reproduced from the recovered plaintext -> InvalidCiphertextError on read.
    corrupt = "v2:" + base64.b64encode(b"\x00" * 48).decode()
    s = SessionLocal()
    try:
        s.execute(
            update(AuthMembership.__table__)  # type: ignore[arg-type]
            .where(AuthMembership.__table__.c.creator == key)
            .values(user=corrupt)
        )
        s.commit()
    finally:
        s.close()

    # Reading the members decrypts that cell -> must fail closed, not serve junk.
    resp = client.get("/api/members/engineers", headers=_h(key))
    assert resp.status_code == 500
    assert "Traceback" not in resp.get_data(as_text=True)
