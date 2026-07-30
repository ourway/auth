"""Per-user API key generation and hashing (SPEC 0004).

Secrets are ``rak_`` + 43 base62 characters carrying the full 256 bits of
``secrets.token_bytes(32)``. Only the SHA-256 hex digest is stored; the raw
secret is returned once at creation and never persisted, logged, or audited.
The digest deliberately excludes the tenant and any server pepper: at this
entropy an offline attack on a leaked hash is not a threat, and neither a
client-key rotation nor a pepper change may invalidate issued keys.
"""

import hashlib
import re
import secrets
import uuid
from typing import Tuple

API_KEY_PREFIX = "rak_"
API_KEY_PATTERN = re.compile(r"^rak_[0-9A-Za-z]{43}$")

# "rak_" + first 8 payload chars — safe to store and display in listings.
KEY_PREFIX_LEN = 12

_PAYLOAD_LEN = 43
_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    chars = []
    while number:
        number, rem = divmod(number, 62)
        chars.append(_ALPHABET[rem])
    return "".join(reversed(chars)) or _ALPHABET[0]


def generate_api_key() -> Tuple[str, str, str, str]:
    """Mint a fresh key: returns ``(secret, key_id, key_hash, key_prefix)``.

    ``secret`` is shown to the caller exactly once; ``key_id`` is the public
    UUID4 handle used in revoke paths; ``key_hash``/``key_prefix`` are what
    gets stored.
    """
    payload = _base62(secrets.token_bytes(32)).rjust(_PAYLOAD_LEN, _ALPHABET[0])
    secret = API_KEY_PREFIX + payload
    return secret, str(uuid.uuid4()), hash_api_key(secret), secret[:KEY_PREFIX_LEN]


def hash_api_key(secret: str) -> str:
    """SHA-256 hex digest of the full secret string (equality-queryable)."""
    return hashlib.sha256(secret.encode()).hexdigest()
