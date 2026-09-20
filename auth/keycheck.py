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
from typing import Optional

import auth.encryption as _encryption

logger = logging.getLogger(__name__)

OK = "ok"
MISMATCH = "mismatch"
UNVERIFIED = "unverified"

_V2_PREFIX = "v2:"

#: Reserved tenant for the canary row. The client-key validator requires a real
#: UUID4, so the nil UUID is refused at the door and can never be a caller's
#: namespace -- which is what makes it safe to reserve.
SENTINEL_TENANT = "00000000-0000-0000-0000-000000000000"
_CANARY_PLAINTEXT = "auth-encryption-canary-v1"

#: Tables that must be protected once the RLS migration has run.
_RLS_TABLES = (
    "auth_group",
    "auth_membership",
    "auth_permission",
    "auth_api_key",
    "auth_tenant_settings",
    "membership_groups",
    "permission_groups",
)

#: Checked the same way, but only when present. audit_log is created by
#: ``setup_audit_tables`` rather than by create_all, so a deployment with audit
#: logging switched off legitimately has no such table -- while one that DOES
#: have it is holding tenant data and must protect it like any other.
_RLS_OPTIONAL_TABLES = ("audit_log",)

_state = OK
_detail = "not yet checked"


def state() -> str:
    """Current verdict: ``ok``, ``mismatch`` or ``unverified``."""
    return _state


def detail() -> str:
    """Human-readable reason behind :func:`state`."""
    return _detail


def is_degraded() -> bool:
    """True when this deployment cannot safely answer authorization questions."""
    return _state == MISMATCH


def _set(new_state: str, why: str) -> str:
    global _state, _detail
    # A later OK must never clear an earlier failure. Boot runs several checks
    # in sequence and the last one would otherwise decide the verdict for all
    # of them -- which is how the RLS check silently stopped mattering the first
    # time this ran: it reported a problem and the encryption check overwrote it.
    if _state == MISMATCH and new_state != MISMATCH:
        return _state
    if _state == UNVERIFIED and new_state == OK:
        return _state
    _state, _detail = new_state, why
    if new_state == MISMATCH:
        logger.critical("STARTUP CHECK FAILED: %s", why)
    elif new_state == UNVERIFIED:
        logger.warning("startup check inconclusive: %s", why)
    else:
        logger.info("startup check: %s", why)
    return new_state


def verify_encryption_key(db) -> str:
    """Check the configured key against this deployment's canary.

    The canary lives under :data:`SENTINEL_TENANT` so it can be read with Row
    Level Security in force -- the previous implementation sampled rows across
    tenants, which RLS would reduce to "nothing to verify against", passing
    vacuously and silently disabling this check.

    Never raises: a database problem yields ``unverified`` rather than
    preventing startup, because refusing to boot on a transient outage turns a
    blip into a restart loop.
    """
    from auth.models.sql import AuthTenantSettings
    from auth.rls import bind_tenant

    fe = _encryption.field_encryption
    try:
        bind_tenant(db, SENTINEL_TENANT)
        row = (
            db.query(AuthTenantSettings)
            .filter(AuthTenantSettings.creator == SENTINEL_TENANT)
            .first()
        )
    except Exception as exc:
        return _set(UNVERIFIED, f"could not read the canary: {exc.__class__.__name__}")

    stored = getattr(row, "canary", None) if row is not None else None

    if not stored:
        if not fe.enabled or fe.encryptor is None:
            return _set(OK, "encryption disabled and no canary stored")
        try:
            value = fe.encryptor.encrypt(_CANARY_PLAINTEXT, SENTINEL_TENANT)
            if row is None:
                row = AuthTenantSettings(creator=SENTINEL_TENANT, strict_users=False)
                db.add(row)
            row.canary = value
            db.commit()
            return _set(OK, "canary written for this deployment")
        except Exception as exc:
            db.rollback()
            return _set(UNVERIFIED, f"could not write the canary: {exc.__class__.__name__}")

    if not fe.enabled:
        return _set(
            MISMATCH,
            "this deployment has an encryption canary but field encryption is "
            "disabled - every authorization lookup would miss and answer "
            "negatively",
        )
    try:
        recovered = fe.encryptor.decrypt(str(stored), SENTINEL_TENANT)  # type: ignore[union-attr]
    except Exception:
        return _set(
            MISMATCH,
            "the configured AUTH_ENCRYPTION_KEY cannot decrypt this "
            "deployment's canary - every authorization lookup would miss and "
            "answer negatively",
        )
    if recovered != _CANARY_PLAINTEXT:
        return _set(MISMATCH, "the canary decrypted to an unexpected value")
    return _set(OK, "encryption key verified against the deployment canary")


def verify_row_level_security(db) -> str:
    """Confirm RLS is actually in force, not merely enabled.

    The application owns these tables and PostgreSQL does not apply RLS to a
    table's owner, so ``ENABLE`` without ``FORCE`` protects nothing while every
    casual check looks correct. That is the one way this feature fails silently,
    so it is asserted at boot rather than assumed.

    Skipped on SQLite, which has no RLS.
    """
    from sqlalchemy import text

    try:
        if db.get_bind().dialect.name != "postgresql":
            return OK
        from auth.config import get_settings

        # The configured schema, NOT current_schema(): search_path rarely points
        # at it, so current_schema() matched no tables and the check reported
        # "nothing to check" -- passing while RLS was off.
        schema = get_settings().database_schema or "public"
        rows = db.execute(
            text(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                "(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.relname = ANY(:names) AND n.nspname = :schema"
            ),
            {"names": list(_RLS_TABLES + _RLS_OPTIONAL_TABLES), "schema": schema},
        ).fetchall()
    except Exception as exc:
        return _set(UNVERIFIED, f"could not read RLS state: {exc.__class__.__name__}")

    if not rows:
        return _set(UNVERIFIED, "no tenant tables found to check RLS on")

    # A table that is absent is not a table that is safe. The junction tables
    # are created by the ORM rather than by a migration, so on a fresh database
    # they appeared after the RLS migration had run -- and a check that only
    # inspects the rows it happens to find reports every remaining table forced
    # and calls that a pass.
    missing = sorted(set(_RLS_TABLES) - {r[0] for r in rows})
    if missing:
        return _set(
            MISMATCH,
            "expected tenant tables are absent, so nothing protects them: "
            + ", ".join(missing),
        )

    unprotected = [
        r[0] for r in rows if not (r[1] and r[2] and r[3] > 0)
    ]
    if unprotected:
        return _set(
            MISMATCH,
            "row level security is not in force on: "
            + ", ".join(sorted(unprotected))
            + " - tenant isolation would rest on query convention alone",
        )
    return _set(OK, f"row level security forced on {len(rows)} tables")


def reset_for_tests(new_state: Optional[str] = None) -> None:
    """Test hook: force the recorded verdict, bypassing the sticky rule."""
    global _state, _detail
    _state = new_state or OK
    _detail = "set by test"
