"""
Encryption module for the authorization system with deterministic encryption support
"""

import base64
import hashlib
import hmac
from typing import Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from auth.config import get_settings


class DeterministicEncryption:
    """
    Deterministic encryption using AES-256 in SIV-like mode
    Same plaintext always produces the same ciphertext (queryable in database)
    """

    def __init__(self, password: Optional[str] = None):
        """Initialize with a password"""
        if password is None:
            config = get_settings()
            password = config.encryption_key

        if not password:
            raise ValueError("Encryption password/key is required")

        # Derive two keys from password: one for HMAC, one for AES
        password_bytes = password.encode()
        salt = b"auth_deterministic_encryption_salt_v1"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for AES + 32 bytes for HMAC
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(password_bytes)

        # Split into two keys
        self.aes_key = derived_key[:32]  # 256 bits for AES
        self.hmac_key = derived_key[32:]  # 256 bits for HMAC

    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data deterministically
        Same input always produces same output (required for database queries)
        """
        if isinstance(data, str):
            data = data.encode()

        # Use HMAC of the data as a deterministic IV
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        deterministic_iv = h.digest()[:16]  # AES block size is 16 bytes

        # Encrypt using AES-256-CTR with deterministic IV
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CTR(deterministic_iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Prepend IV and encode to base64
        encrypted_data = deterministic_iv + ciphertext
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data"""
        encrypted_bytes = base64.b64decode(encrypted_data.encode())

        # Extract IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]

        # Decrypt using AES-256-CTR
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_data.decode()


class FieldEncryption:
    """Handles encryption of individual database fields"""

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

    def encrypt_field(self, field_value: Optional[str]) -> Optional[str]:
        """Encrypt a field value if encryption is enabled (deterministic)"""
        if not self.enabled or not field_value or self.encryptor is None:
            return field_value

        try:
            return self.encryptor.encrypt(field_value)
        except Exception as e:
            # If encryption fails, return original value to avoid breaking functionality
            import logging
            logging.error(f"Encryption failed: {e}")
            return field_value

    def decrypt_field(self, encrypted_value: Optional[str]) -> Optional[str]:
        """Decrypt a field value if encryption is enabled"""
        if not self.enabled or not encrypted_value or self.encryptor is None:
            return encrypted_value

        try:
            return self.encryptor.decrypt(encrypted_value)
        except Exception as e:
            # If decryption fails, return encrypted value to avoid breaking functionality
            import logging
            logging.error(f"Decryption failed: {e}")
            return encrypted_value


# Global field encryption instance
field_encryption = FieldEncryption()


def encrypt_sensitive_data(data: Optional[str]) -> Optional[str]:
    """Encrypt sensitive data if encryption is enabled (deterministic for queryable fields)"""
    return field_encryption.encrypt_field(data)


def decrypt_sensitive_data(data: Optional[str]) -> Optional[str]:
    """Decrypt sensitive data if encryption is enabled"""
    return field_encryption.decrypt_field(data)
