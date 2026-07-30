"""Service-level proof that api-key rows join the field-encryption scheme.

Forces per-tenant encryption on (same harness as the rotation crypto test) and
asserts what is actually stored: `user`/`label` cells are v2 ciphertext bound
to the tenant, `key_hash` stays a plain SHA-256 hex (it must remain
equality-queryable and creator-independent), and the product paths (list,
validate) round-trip the plaintext.
"""

import re
import uuid

import pytest
from sqlalchemy import select

from auth.models.sql import AuthApiKey

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture
def forced_encryption(monkeypatch):
    from auth.encryption import DeterministicEncryption, FieldEncryption

    enc = DeterministicEncryption("unit-test-encryption-key")
    fe = FieldEncryption()
    fe.encryptor = enc
    fe.enabled = True
    monkeypatch.setattr("auth.encryption.field_encryption", fe)
    return enc


def test_api_key_cells_are_encrypted_at_rest(forced_encryption):
    from auth.database import SessionLocal
    from auth.encryption import InvalidCiphertextError
    from auth.main import create_app
    from auth.services.service import AuthorizationService

    create_app()
    enc = forced_encryption
    tenant = str(uuid.uuid4())
    other = str(uuid.uuid4())

    db = SessionLocal()
    try:
        svc = AuthorizationService(db, tenant)
        created = svc.create_api_key("alice@example.com", label="laptop key")
        assert created is not None

        stored = db.execute(
            select(
                AuthApiKey.__table__.c.user,
                AuthApiKey.__table__.c.label,
                AuthApiKey.__table__.c.key_hash,
            ).where(AuthApiKey.__table__.c.creator == tenant)
        ).one()

        # Ciphertext at rest, bound to THIS tenant.
        assert stored.user.startswith("v2:")
        assert stored.label.startswith("v2:")
        assert enc.decrypt(stored.user, tenant) == "alice@example.com"
        assert enc.decrypt(stored.label, tenant) == "laptop key"
        with pytest.raises(InvalidCiphertextError):
            enc.decrypt(stored.user, other)

        # The hash column is NOT ciphertext — plain sha256 hex, so validate
        # stays a single index probe and survives rotation.
        assert _SHA256_HEX.match(stored.key_hash)

        # Product paths round-trip the plaintext (deterministic encryption
        # keeps the user column equality-queryable).
        listing = svc.list_api_keys("alice@example.com")
        assert len(listing) == 1
        assert listing[0]["label"] == "laptop key"

        validated = svc.validate_api_key(created["api_key"])
        assert validated["valid"] is True
        assert validated["user"] == "alice@example.com"
        assert validated["label"] == "laptop key"

        # Revoke through the service finds the row via the encrypted equality
        # query too — and flips validate to red.
        assert svc.revoke_api_key("alice@example.com", created["key_id"]) == "revoked"
        assert svc.validate_api_key(created["api_key"]) == {
            "valid": False,
            "reason": "revoked",
        }
    finally:
        db.close()
