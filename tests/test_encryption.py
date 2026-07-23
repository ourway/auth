"""
Tests for the deterministic field-encryption layer.

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


@pytest.fixture
def enc():
    return DeterministicEncryption(password=PASSWORD)


def test_roundtrip(enc):
    assert enc.decrypt(enc.encrypt("hello world")) == "hello world"


def test_roundtrip_unicode(enc):
    value = "うずまき ナルト 🍥 – ürlaub"
    assert enc.decrypt(enc.encrypt(value)) == value


def test_roundtrip_empty_string(enc):
    assert enc.decrypt(enc.encrypt("")) == ""


def test_deterministic_same_plaintext_same_ciphertext(enc):
    # Every DB lookup on encrypted columns relies on this property.
    assert enc.encrypt("alice@example.com") == enc.encrypt("alice@example.com")


def test_different_plaintexts_different_ciphertexts(enc):
    assert enc.encrypt("alice@example.com") != enc.encrypt("bob@example.com")


def test_ciphertext_is_not_plaintext(enc):
    assert enc.encrypt("secret-value") != "secret-value"


def test_different_keys_produce_different_ciphertexts(enc):
    other = DeterministicEncryption(password="another-password")
    assert enc.encrypt("same input") != other.encrypt("same input")


def test_wrong_key_does_not_recover_plaintext(enc):
    other = DeterministicEncryption(password="another-password")
    token = enc.encrypt("sensitive")
    try:
        recovered = other.decrypt(token)
    except (UnicodeDecodeError, ValueError):
        return  # garbage bytes failing to decode is acceptable
    assert recovered != "sensitive"


def test_missing_key_raises():
    with pytest.raises(ValueError):
        DeterministicEncryption(password="")


def _enabled_field_encryption(monkeypatch):
    """A FieldEncryption forced into enabled mode."""
    fe = FieldEncryption()
    fe.encryptor = DeterministicEncryption(password=PASSWORD)
    fe.enabled = True
    return fe


def test_field_encryption_disabled_is_passthrough():
    fe = FieldEncryption()  # conftest env: encryption disabled
    assert fe.enabled is False
    assert fe.encrypt_field("plain") == "plain"
    assert fe.decrypt_field("plain") == "plain"


def test_field_encryption_enabled_roundtrip(monkeypatch):
    fe = _enabled_field_encryption(monkeypatch)
    token = fe.encrypt_field("alice@example.com")
    assert token != "alice@example.com"
    assert fe.decrypt_field(token) == "alice@example.com"


def test_field_encryption_none_and_empty_passthrough(monkeypatch):
    fe = _enabled_field_encryption(monkeypatch)
    assert fe.encrypt_field(None) is None
    assert fe.encrypt_field("") == ""
    assert fe.decrypt_field(None) is None


def test_decrypt_tolerates_legacy_plaintext_rows(monkeypatch):
    """Rows written unencrypted by the old add_role bug must stay readable.

    decrypt_field fails open: values that are not valid ciphertext come back
    unchanged instead of raising.
    """
    fe = _enabled_field_encryption(monkeypatch)
    legacy = "Administrator role!"  # not base64/AES output
    assert fe.decrypt_field(legacy) == legacy


def test_module_helpers_follow_singleton_state():
    # Under the test env the singleton is disabled -> passthrough.
    assert encryption_module.field_encryption.enabled is False
    assert encrypt_sensitive_data("value") == "value"
    assert decrypt_sensitive_data("value") == "value"


def test_module_helpers_with_enabled_singleton(monkeypatch):
    fe = FieldEncryption()
    fe.encryptor = DeterministicEncryption(password=PASSWORD)
    fe.enabled = True
    monkeypatch.setattr(encryption_module, "field_encryption", fe)
    token = encrypt_sensitive_data("alice@example.com")
    assert token != "alice@example.com"
    assert decrypt_sensitive_data(token) == "alice@example.com"


def test_tampered_ciphertext_is_rejected(enc):
    token = enc.encrypt("sensitive-value")
    raw = bytearray(base64.b64decode(token))
    raw[-1] ^= 0x01  # flip a bit in the ciphertext body
    tampered = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(InvalidCiphertextError):
        enc.decrypt(tampered)


def test_wrong_key_raises_invalid_ciphertext(enc):
    other = DeterministicEncryption(password="a-different-password")
    with pytest.raises(InvalidCiphertextError):
        other.decrypt(enc.encrypt("sensitive-value"))


def test_decrypt_field_fails_closed_on_tampered_ciphertext(monkeypatch):
    fe = _enabled_field_encryption(monkeypatch)
    token = fe.encrypt_field("alice@example.com")
    raw = bytearray(base64.b64decode(token))
    raw[-1] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode()
    # Fail closed: must raise, not return the raw/garbage value.
    with pytest.raises(InvalidCiphertextError):
        fe.decrypt_field(tampered)
