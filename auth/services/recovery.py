"""Recover a namespace whose client key has been lost (issuedb #19).

Rotation authenticates with the key it replaces, so it has never been able to
help someone who lost that key: the namespace simply became unreachable, and
because nothing is stored in plaintext nobody could even identify which one it
was.

The rotate key closes that. It is a second bearer credential, issued once and
stored only as a hash, and presenting it is sufficient to move the namespace
onto a fresh client key. Whoever holds it owns the tenant — which is the point,
and also why it is never disclosed twice, never logged, and its use audited.
"""

import logging
from typing import Any, Dict, Optional

from auth.api_keys import (
    generate_rotate_key,
    hash_api_key,
    validate_rotate_key_format,
)
from auth.models.sql import AuthTenantSettings
from auth.rls import RECOVER_GUC, bind_session
from auth.services.base import _utcnow

logger = logging.getLogger(__name__)


class RotateKeyRejected(Exception):
    """The presented rotate key is malformed or matches no tenant."""


class TargetNamespaceNotEmpty(Exception):
    """The requested new client key already owns data."""


def target_namespace_is_empty(db, client_key: str) -> bool:
    """True when ``client_key`` owns no rows in any tenant-scoped table.

    Counted with ``auth.rotating_to_fp`` bound to the target, because Row Level
    Security would otherwise hide exactly the rows this check exists to find --
    and an emptiness check that cannot see anything would always say "empty".
    """
    from auth.models.sql import (
        AuthApiKey,
        AuthGroup,
        AuthMembership,
        AuthPermission,
    )
    from auth.rls import ROTATING_TO_GUC, tenant_fingerprint

    bind_session(db, **{ROTATING_TO_GUC: tenant_fingerprint(client_key)})
    for model in (AuthGroup, AuthMembership, AuthPermission, AuthApiKey):
        if db.query(model).filter(model.creator == client_key).first() is not None:
            return False
    return True


def resolve_rotate_key(db, secret: str) -> Optional[str]:
    """Return the client key the rotate key belongs to, or ``None``.

    The caller has no tenant yet, so there is nothing for Row Level Security to
    match on. Binding ``auth.recover_fp`` opens exactly one row — the settings
    row whose stored hash equals the hash of what was presented — and nothing
    else. An attacker must therefore already hold a 256-bit secret; the policy
    is not widened, it is keyed differently for this one lookup.
    """
    if not validate_rotate_key_format(secret):
        return None
    secret_hash = hash_api_key(secret)
    bind_session(db, **{RECOVER_GUC: secret_hash})
    row = (
        db.query(AuthTenantSettings)
        .filter(AuthTenantSettings.rotate_key_hash == secret_hash)
        .first()
    )
    return str(row.creator) if row is not None else None


def recover_namespace(db, secret: str, new_client_key: str) -> Dict[str, Any]:
    """Move the namespace behind ``secret`` onto ``new_client_key``.

    Returns the new client key and a freshly minted rotate key. The old rotate
    key dies with the rotation: it is replaced in the same transaction, so a
    recovery cannot be replayed with the credential that performed it.
    """
    from auth.services.service import AuthorizationService

    old_client = resolve_rotate_key(db, secret)
    if old_client is None:
        raise RotateKeyRejected("unknown or malformed rotate key")

    if not target_namespace_is_empty(db, new_client_key):
        # The caller chooses new_client_key, so without this check a valid
        # rotate key for namespace X could name a VICTIM's client key as the
        # target and merge X into it -- gaining, in the same move, a credential
        # the victim also holds. The normal rotate path is safe because the
        # server generates the target; this one is not, so it is verified.
        raise TargetNamespaceNotEmpty(
            "new_client_key already identifies a namespace with data"
        )

    service = AuthorizationService(
        db, old_client, validate_client=True, manage_transaction=False
    )
    result = service.rotate_client_key(new_client_key)

    # The settings row moved with the namespace; re-key it in the same
    # transaction so the used credential cannot be presented again.
    row = (
        db.query(AuthTenantSettings)
        .filter(AuthTenantSettings.creator == new_client_key)
        .first()
    )
    new_secret, new_hash = generate_rotate_key()
    if row is None:
        row = AuthTenantSettings(creator=new_client_key, strict_users=False)
        db.add(row)
    row.rotate_key_hash = new_hash
    row.rotate_key_issued_at = _utcnow()
    db.flush()

    return {
        "client_key": new_client_key,
        "rotate_key": new_secret,
        "migrated": result.get("migrated", result),
    }
