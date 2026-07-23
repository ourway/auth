"""Unit tests for the per-tenant re-encryption transform.

The pure ``reencrypt_value`` transform is exercised here; the full database pass
(``run``) is validated against PostgreSQL in the integration run.
"""

import base64

import pytest

from auth.encryption import DeterministicEncryption, InvalidCiphertextError
from scripts.reencrypt_pertenant import reencrypt_value

PASSWORD = "test-encryption-password"
TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def enc():
    return DeterministicEncryption(password=PASSWORD)


def test_migrates_legacy_global_to_v2(enc):
    legacy = enc._seal(b"alice@example.com", *enc._global_keys)  # v1, unprefixed
    v2 = reencrypt_value(enc, legacy, TENANT_A)
    assert v2 is not None and v2.startswith("v2:")
    assert enc.decrypt(v2, TENANT_A) == "alice@example.com"


def test_migrates_legacy_plaintext_to_v2(enc):
    v2 = reencrypt_value(enc, "Administrator role!", TENANT_A)
    assert v2 is not None and v2.startswith("v2:")
    assert enc.decrypt(v2, TENANT_A) == "Administrator role!"


def test_already_v2_is_skipped(enc):
    assert reencrypt_value(enc, enc.encrypt("alice", TENANT_A), TENANT_A) is None


def test_empty_is_skipped(enc):
    assert reencrypt_value(enc, None, TENANT_A) is None
    assert reencrypt_value(enc, "", TENANT_A) is None


def test_corrupt_ciphertext_raises_rather_than_guessing(enc):
    corrupt = base64.b64encode(b"\x00" * 32).decode()  # base64, but not authentic
    with pytest.raises(InvalidCiphertextError):
        reencrypt_value(enc, corrupt, TENANT_A)


def test_migration_binds_row_to_its_own_tenant(enc):
    # Same legacy plaintext under two tenants must end up different after migrate.
    legacy = enc._seal(b"alice@example.com", *enc._global_keys)
    a = reencrypt_value(enc, legacy, TENANT_A)
    b = reencrypt_value(enc, legacy, TENANT_B)
    assert a != b
    assert enc.decrypt(a, TENANT_A) == "alice@example.com"
    assert enc.decrypt(b, TENANT_B) == "alice@example.com"
