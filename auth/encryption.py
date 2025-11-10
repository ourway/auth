"""
Encryption module for the authorization system
"""

import base64
from typing import Optional, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from auth.config import get_config


class DataEncryption:
    """Handles encryption and decryption of sensitive data"""

    def __init__(self, password: Optional[str] = None):
        """
        Initialize with a password. If no password is provided, uses the one from config
        """
        if password is None:
            config = get_config()
            password = config.encryption_key

        if not password:
            raise ValueError("Encryption password/key is required")

        # Derive key from password using PBKDF2
        password_bytes = password.encode()
        salt = b"static_salt_for_auth_system"  # In production, use random salt per item

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        self.cipher = Fernet(key)

    def encrypt(self, data: Union[str, bytes]) -> str:
        """Encrypt data and return as base64 string"""
        if isinstance(data, str):
            data = data.encode()

        encrypted_data = self.cipher.encrypt(data)
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data from base64 string"""
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted_data = self.cipher.decrypt(encrypted_bytes)
        return decrypted_data.decode()


class FieldEncryption:
    """Handles encryption of individual database fields"""

    def __init__(self):
        config = get_config()
        if config.enable_encryption and config.encryption_key:
            self.encryptor = DataEncryption(config.encryption_key)
            self.enabled = True
        else:
            self.encryptor = None
            self.enabled = False

    def encrypt_field(self, field_value: Optional[str]) -> Optional[str]:
        """Encrypt a field value if encryption is enabled"""
        if not self.enabled or not field_value:
            return field_value

        try:
            return self.encryptor.encrypt(field_value)
        except Exception:
            # If encryption fails, return original value to avoid breaking functionality
            return field_value

    def decrypt_field(self, encrypted_value: Optional[str]) -> Optional[str]:
        """Decrypt a field value if encryption is enabled"""
        if not self.enabled or not encrypted_value:
            return encrypted_value

        try:
            return self.encryptor.decrypt(encrypted_value)
        except Exception:
            # If decryption fails, return encrypted value to avoid breaking functionality
            return encrypted_value


# Global field encryption instance
field_encryption = FieldEncryption()


def encrypt_sensitive_data(data: Optional[str]) -> Optional[str]:
    """Encrypt sensitive data if encryption is enabled"""
    return field_encryption.encrypt_field(data)


def decrypt_sensitive_data(data: Optional[str]) -> Optional[str]:
    """Decrypt sensitive data if encryption is enabled"""
    return field_encryption.decrypt_field(data)
