"""Tests for the per-tenant, authenticated deterministic field-encryption layer.

The library-wide default in this suite is encryption OFF (see conftest.py);
enabled-mode tests build their own DeterministicEncryption/FieldEncryption
instances so the module singleton stays untouched.
"""

import base64

import pytest

import auth.encryption as encryption_module
from auth.encryption import (
    DeterministicEncryption,
    FieldEncryption,
    InvalidCiphertextError,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)

PASSWORD = "test-encryption-password"
TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def enc():
    return DeterministicEncryption(password=PASSWORD)


def test_roundtrip(enc):
    assert enc.decrypt(enc.encrypt("hello world", TENANT_A), TENANT_A) == "hello world"


def test_roundtrip_unicode(enc):
    value = "うずまき ナルト 🍥 – ürlaub"
    assert enc.decrypt(enc.encrypt(value, TENANT_A), TENANT_A) == value


def test_roundtrip_empty_string(enc):
    assert enc.decrypt(enc.encrypt("", TENANT_A), TENANT_A) == ""


def test_ciphertext_is_tagged_v2(enc):
    assert enc.encrypt("x", TENANT_A).startswith("v2:")


def test_deterministic_same_plaintext_same_ciphertext(enc):
    # Every DB lookup on encrypted columns relies on this property.
    token = enc.encrypt("alice@example.com", TENANT_A)
    assert token == enc.encrypt("alice@example.com", TENANT_A)


def test_different_plaintexts_different_ciphertexts(enc):
    assert enc.encrypt("alice@example.com", TENANT_A) != enc.encrypt(
        "bob@example.com", TENANT_A
    )


def test_same_plaintext_differs_across_tenants(enc):
    # The whole point of per-tenant keys: no cross-tenant correlation.
    assert enc.encrypt("alice@example.com", TENANT_A) != enc.encrypt(
        "alice@example.com", TENANT_B
    )


def test_wrong_tenant_cannot_decrypt(enc):
    token = enc.encrypt("secret", TENANT_A)
    with pytest.raises(InvalidCiphertextError):
        enc.decrypt(token, TENANT_B)


def test_tampered_ciphertext_is_rejected(enc):
    token = enc.encrypt("sensitive-value", TENANT_A)
    raw = bytearray(base64.b64decode(token[len("v2:"):]))
    raw[-1] ^= 0x01  # flip a bit in the ciphertext body
    tampered = "v2:" + base64.b64encode(bytes(raw)).decode()
    with pytest.raises(InvalidCiphertextError):
        enc.decrypt(tampered, TENANT_A)


def test_different_master_keys_produce_different_ciphertexts(enc):
    other = DeterministicEncryption(password="another-password")
    assert enc.encrypt("same input", TENANT_A) != other.encrypt("same input", TENANT_A)


def test_wrong_master_key_raises(enc):
    other = DeterministicEncryption(password="another-password")
    with pytest.raises(InvalidCiphertextError):
        other.decrypt(enc.encrypt("sensitive", TENANT_A), TENANT_A)


def test_missing_key_raises():
    with pytest.raises(ValueError):
        DeterministicEncryption(password="")


def test_reads_legacy_global_ciphertext(enc):
    """Values written by older versions (global key, untagged) still decrypt,
    so a deployment can read old rows before re-encrypting them."""
    aes_key, hmac_key = enc._global_keys
    legacy = enc._seal(b"legacy-user", aes_key, hmac_key)  # v1: unprefixed
    assert not legacy.startswith("v2:")
    assert enc.decrypt(legacy, TENANT_A) == "legacy-user"  # creator ignored for v1


# ---- FieldEncryption ----


def _enabled_field_encryption() -> FieldEncryption:
    fe = FieldEncryption()
    fe.encryptor = DeterministicEncryption(password=PASSWORD)
    fe.enabled = True
    return fe


def test_field_encryption_disabled_is_passthrough():
    fe = FieldEncryption()  # conftest env: encryption disabled
    assert fe.enabled is False
    assert fe.encrypt_field("plain", TENANT_A) == "plain"
    assert fe.decrypt_field("plain", TENANT_A) == "plain"


def test_field_encryption_enabled_roundtrip():
    fe = _enabled_field_encryption()
    token = fe.encrypt_field("alice@example.com", TENANT_A)
    assert token is not None
    assert token != "alice@example.com"
    assert token.startswith("v2:")
    assert fe.decrypt_field(token, TENANT_A) == "alice@example.com"


def test_field_encryption_none_and_empty_passthrough():
    fe = _enabled_field_encryption()
    assert fe.encrypt_field(None, TENANT_A) is None
    assert fe.encrypt_field("", TENANT_A) == ""
    assert fe.decrypt_field(None, TENANT_A) is None


def test_decrypt_tolerates_legacy_plaintext_rows():
    """Rows written unencrypted by the old add_role bug must stay readable."""
    fe = _enabled_field_encryption()
    legacy = "Administrator role!"  # not base64/ciphertext
    assert fe.decrypt_field(legacy, TENANT_A) == legacy


def test_decrypt_field_fails_closed_on_tampered_ciphertext():
    fe = _enabled_field_encryption()
    token = fe.encrypt_field("alice@example.com", TENANT_A)
    assert token is not None
    raw = bytearray(base64.b64decode(token[len("v2:"):]))
    raw[-1] ^= 0x01
    tampered = "v2:" + base64.b64encode(bytes(raw)).decode()
    with pytest.raises(InvalidCiphertextError):
        fe.decrypt_field(tampered, TENANT_A)


def test_module_helpers_follow_singleton_state():
    # Under the test env the singleton is disabled -> passthrough.
    assert encryption_module.field_encryption.enabled is False
    assert encrypt_sensitive_data("value", TENANT_A) == "value"
    assert decrypt_sensitive_data("value", TENANT_A) == "value"


def test_module_helpers_with_enabled_singleton(monkeypatch):
    fe = _enabled_field_encryption()
    monkeypatch.setattr(encryption_module, "field_encryption", fe)
    token = encrypt_sensitive_data("alice@example.com", TENANT_A)
    assert token != "alice@example.com"
    assert decrypt_sensitive_data(token, TENANT_A) == "alice@example.com"
