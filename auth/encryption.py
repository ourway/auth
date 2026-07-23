"""
Deterministic, per-tenant, authenticated field encryption.

* Deterministic — the same (plaintext, tenant) always yields the same
  ciphertext, so encrypted columns stay queryable by equality.
* Authenticated — the IV is a synthetic IV, ``HMAC(hmac_key, plaintext)[:16]``,
  re-derived and constant-time checked on decrypt, so tampered / corrupted /
  wrong-key values are rejected rather than silently returned.
* Per-tenant — field keys are derived per ``creator`` (tenant) via HKDF from the
  master key, so identical plaintexts in different tenants encrypt to different
  ciphertext: no cross-tenant correlation. New ciphertext is tagged ``v2:``.

Legacy values written by earlier versions (global key, untagged) remain
decryptable, so a deployment can still read old rows until they are re-encrypted
by ``scripts/reencrypt_pertenant.py``.
"""

import base64
import hashlib
import hmac
from typing import Dict, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from auth.config import get_settings

# Tag on the current (per-tenant) ciphertext format, so it can be told apart from
# the legacy (global-key, untagged) format during migration.
_V2_PREFIX = "v2:"


class InvalidCiphertextError(ValueError):
    """A value shaped like ciphertext failed authentication.

    Raised on decrypt when the synthetic IV cannot be reproduced from the
    recovered plaintext — the value was tampered with, corrupted, or encrypted
    under a different key/tenant. It subclasses ``ValueError`` so pre-existing
    decode-error handlers keep working, and it is deliberately *never* swallowed
    by the field layer (fail closed).
    """


class DeterministicEncryption:
    """Per-tenant deterministic authenticated encryption (see module docstring)."""

    def __init__(self, password: Optional[str] = None):
        if password is None:
            password = get_settings().encryption_key
        if not password:
            raise ValueError("Encryption password/key is required")

        salt = b"auth_deterministic_encryption_salt_v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 for AES + 32 for HMAC
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        self._master = kdf.derive(password.encode())
        # Legacy (v1) global keys — used only to READ pre-per-tenant rows.
        self._global_keys: Tuple[bytes, bytes] = (self._master[:32], self._master[32:])
        self._tenant_keys: Dict[str, Tuple[bytes, bytes]] = {}

    def _keys_for(self, creator: str) -> Tuple[bytes, bytes]:
        """Per-tenant (aes_key, hmac_key), derived once per creator via HKDF."""
        keys = self._tenant_keys.get(creator)
        if keys is None:
            okm = HKDFExpand(
                algorithm=hashes.SHA256(),
                length=64,
                info=b"auth-fieldkey-v2|" + creator.encode(),
                backend=default_backend(),
            ).derive(self._master)
            keys = (okm[:32], okm[32:])
            self._tenant_keys[creator] = keys
        return keys

    @staticmethod
    def _seal(data: bytes, aes_key: bytes, hmac_key: bytes) -> str:
        iv = hmac.new(hmac_key, data, hashlib.sha256).digest()[:16]
        cipher = Cipher(
            algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def _open(payload: str, aes_key: bytes, hmac_key: bytes) -> str:
        try:
            raw = base64.b64decode(payload, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("not valid base64 ciphertext") from exc
        if len(raw) < 16:
            raise ValueError("ciphertext too short to contain an IV")
        iv, ciphertext = raw[:16], raw[16:]
        cipher = Cipher(
            algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        expected_iv = hmac.new(hmac_key, plaintext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected_iv, iv):
            raise InvalidCiphertextError("ciphertext failed authentication")
        return plaintext.decode()

    def encrypt(self, data: Union[str, bytes], creator: str) -> str:
        """Encrypt for a tenant, producing the current (v2, per-tenant) format."""
        if isinstance(data, str):
            data = data.encode()
        aes_key, hmac_key = self._keys_for(creator)
        return _V2_PREFIX + self._seal(data, aes_key, hmac_key)

    def decrypt(self, token: str, creator: str) -> str:
        """Decrypt and authenticate.

        Handles the current per-tenant (``v2:``) format and the legacy
        global-key format (untagged), so rows not yet re-encrypted still read.
        A value that is not our ciphertext at all raises a plain ``ValueError``.
        """
        if token.startswith(_V2_PREFIX):
            aes_key, hmac_key = self._keys_for(creator)
            return self._open(token[len(_V2_PREFIX):], aes_key, hmac_key)
        aes_key, hmac_key = self._global_keys  # legacy v1: global, no tenant split
        return self._open(token, aes_key, hmac_key)


class FieldEncryption:
    """Handles encryption of individual database fields."""

    encryptor: Optional[DeterministicEncryption]
    enabled: bool

    def __init__(self):
        config = get_settings()
        if config.enable_encryption and config.encryption_key:
            self.encryptor = DeterministicEncryption(config.encryption_key)
            self.enabled = True
        else:
            self.encryptor = None
            self.enabled = False

    def encrypt_field(self, field_value: Optional[str], creator: str) -> Optional[str]:
        """Encrypt a field for a tenant if encryption is enabled.

        Fails closed: if encryption is enabled but the operation errors, the
        exception propagates rather than silently persisting plaintext into an
        "encrypted" column.
        """
        if not self.enabled or not field_value or self.encryptor is None:
            return field_value
        return self.encryptor.encrypt(field_value, creator)

    def decrypt_field(
        self, encrypted_value: Optional[str], creator: str
    ) -> Optional[str]:
        """Decrypt a tenant field if encryption is enabled.

        Fails closed on authentication failure (tampered / wrong key or tenant);
        legacy rows that were never encrypted (not valid ciphertext) are returned
        unchanged.
        """
        if not self.enabled or not encrypted_value or self.encryptor is None:
            return encrypted_value
        try:
            return self.encryptor.decrypt(encrypted_value, creator)
        except InvalidCiphertextError:
            raise
        except ValueError:
            # Not our ciphertext (e.g. a legacy plaintext row) — leave as-is.
            return encrypted_value


# Global field encryption instance
field_encryption = FieldEncryption()


def encrypt_sensitive_data(data: Optional[str], creator: str) -> Optional[str]:
    """Encrypt sensitive data for a tenant if encryption is enabled."""
    return field_encryption.encrypt_field(data, creator)


def decrypt_sensitive_data(data: Optional[str], creator: str) -> Optional[str]:
    """Decrypt sensitive data for a tenant if encryption is enabled."""
    return field_encryption.decrypt_field(data, creator)
