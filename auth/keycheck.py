"""Boot-time verification that the configured encryption key matches stored data.

Field encryption is deterministic and used for equality lookups, so
encrypt-to-store and encrypt-to-query share one key derivation. If the key
changes, both sides move together into a namespace where nothing matches: every
membership lookup misses, every authorization answer becomes "denied", and each
one is returned with HTTP 200. Nothing in the request path can notice, because
the query path never decrypts — it compares ciphertext.

This module samples rows that are actually encrypted and decrypts them. A wrong
key fails authentication in ``DeterministicEncryption._open`` (the IV is an HMAC
of the plaintext, re-derived and constant-time compared), so the failure is
loud here even though it is silent everywhere else.

The states are distinguished deliberately:

``ok``
    Encrypted rows exist and decrypt, or nothing is encrypted yet.
``mismatch``
    Encrypted rows exist and this key cannot read them. Serving would answer
    every authorization question wrongly, so ``/api`` is refused instead.
``unverified``
    The check could not run (database unavailable at boot). Not an assertion
    that the key is good — the service starts, because refusing to boot on a
    transient database problem turns a blip into a restart loop.
"""

import logging
from typing import List, Optional, Tuple

import auth.encryption as _encryption
from auth.encryption import InvalidCiphertextError

logger = logging.getLogger(__name__)

OK = "ok"
MISMATCH = "mismatch"
UNVERIFIED = "unverified"

_V2_PREFIX = "v2:"
_SAMPLE = 5

_state = OK
_detail = "not yet checked"


def state() -> str:
    """Current key-check verdict: ``ok``, ``mismatch`` or ``unverified``."""
    return _state


def detail() -> str:
    """Human-readable reason behind :func:`state`."""
    return _detail


def is_degraded() -> bool:
    """True when the configured key cannot read this deployment's own data."""
    return _state == MISMATCH


def _sample_rows(db) -> List[Tuple[str, str]]:
    """Up to ``_SAMPLE`` (creator, stored_value) pairs from encryption-bearing columns."""
    from auth.models.sql import AuthApiKey, AuthMembership

    rows: List[Tuple[str, str]] = []
    for model in (AuthMembership, AuthApiKey):
        for creator, stored in (
            db.query(model.creator, model._user).limit(_SAMPLE).all()
        ):
            if creator and stored:
                rows.append((str(creator), str(stored)))
        if rows:
            break
    return rows


def verify_encryption_key(db) -> str:
    """Check the configured key against stored ciphertext; record the verdict.

    Returns the resulting state. Never raises: a database problem yields
    ``unverified`` so that a transient outage cannot prevent startup.
    """
    global _state, _detail
    try:
        rows = _sample_rows(db)
    except Exception as exc:  # database unreachable / schema absent at boot
        _state, _detail = UNVERIFIED, f"could not read sample rows: {exc.__class__.__name__}"
        logger.warning("encryption key not verified: %s", _detail)
        return _state

    encrypted = [(c, v) for c, v in rows if v.startswith(_V2_PREFIX)]
    if not encrypted:
        _state, _detail = OK, "no encrypted rows to verify against"
        return _state

    fe = _encryption.field_encryption
    if not fe.enabled:
        _state = MISMATCH
        _detail = (
            "stored data is encrypted but field encryption is disabled "
            "(AUTH_ENABLE_ENCRYPTION/AUTH_ENCRYPTION_KEY) — every authorization "
            "lookup would miss and answer negatively"
        )
        logger.critical("ENCRYPTION KEY CHECK FAILED: %s", _detail)
        return _state

    for creator, value in encrypted:
        try:
            fe.encryptor.decrypt(value, creator)  # type: ignore[union-attr]
        except InvalidCiphertextError:
            _state = MISMATCH
            _detail = (
                "the configured AUTH_ENCRYPTION_KEY cannot decrypt this "
                "deployment's stored data — every authorization lookup would "
                "miss and answer negatively"
            )
            logger.critical("ENCRYPTION KEY CHECK FAILED: %s", _detail)
            return _state
        except Exception:
            continue  # not our ciphertext after all; try the next sample

    _state, _detail = OK, f"verified against {len(encrypted)} encrypted row(s)"
    logger.info("encryption key check: %s", _detail)
    return _state


def reset_for_tests(new_state: Optional[str] = None) -> None:
    """Test hook: force the recorded verdict."""
    global _state, _detail
    _state = new_state or OK
    _detail = "set by test"
