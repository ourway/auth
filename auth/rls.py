"""Bind a tenant to every database transaction, for Row Level Security.

The policies added by the ``enable_rls`` migration compare a row's tenant
fingerprint against a session variable. This module is what sets that variable,
and it does so for *every* transaction on a bound session rather than once per
request.

Three things here are deliberate and each one is a bug if changed:

``set_config(..., is_local => true)``, never ``SET``
    A plain ``SET`` persists on the connection. Connections are pooled, so the
    next tenant to borrow that connection would inherit the previous tenant's
    identity and read their rows. ``is_local`` scopes the value to the current
    transaction, so it cannot outlive it.

An ``after_begin`` listener, not a single call at request start
    ``SET LOCAL`` dies with its transaction. Library callers construct the
    service with ``manage_transaction=True`` and commit inside each method, so a
    one-shot call would be silently lost after the first commit and every
    subsequent statement would see no tenant — which, under RLS, means no rows.

A plain SHA-256, not the audit pepper fingerprint
    The point is that the session variable, and anything that logs it, is not
    the credential. A hash of a UUID4 achieves that irreversibly. Deriving it
    from ``AUTH_AUDIT_PEPPER`` would make row visibility depend on a secret
    whose rotation already breaks audit reads, so changing that secret would
    lock every tenant out of their own data.

PostgreSQL only. SQLite has no RLS, so binding is skipped there exactly as
``ServiceBase._lock_tenant`` already skips its advisory lock.
"""

import hashlib
from typing import Optional

from sqlalchemy import event, text
from sqlalchemy.orm import Session

#: Session variable holding the tenant fingerprint for the RBAC tables.
TENANT_GUC = "auth.tenant_fp"
#: Session variable holding the audit fingerprint for ``audit_log``.
AUDIT_GUC = "auth.audit_fp"
#: Set only while a rotation is moving a namespace between two client keys.
ROTATING_TO_GUC = "auth.rotating_to_fp"
#: Set only while a recovery call resolves a rotate key to its tenant.
RECOVER_GUC = "auth.recover_fp"

_INFO_KEY = "auth_rls_bindings"


def tenant_fingerprint(client_key: str) -> str:
    """SHA-256 of the client key, as stored in ``creator_fp``.

    Not a secret: anyone holding the key can compute it, and they already hold
    the key. Its job is to keep the raw credential out of session variables and
    logs.
    """
    return hashlib.sha256(client_key.encode()).hexdigest()


def _is_postgresql(bind) -> bool:
    try:
        return bool(bind.dialect.name == "postgresql")
    except Exception:
        return False


def _apply(connection, bindings: dict) -> None:
    for name, value in bindings.items():
        if value is None:
            continue
        connection.execute(
            text("SELECT set_config(:n, :v, true)"), {"n": name, "v": value}
        )


def bind_session(session: Session, **bindings: Optional[str]) -> None:
    """Attach tenant bindings to ``session`` and apply them to its transaction.

    Stored on ``session.info`` so the ``after_begin`` listener can re-apply them
    to every subsequent transaction on the same session.
    """
    current = session.info.setdefault(_INFO_KEY, {})
    current.update({k: v for k, v in bindings.items() if v is not None})
    bind = session.get_bind()
    if not _is_postgresql(bind):
        return
    if session.in_transaction():
        _apply(session.connection(), current)


def bind_tenant(session: Session, client_key: str) -> None:
    """Bind the normal per-request tenant identity."""
    from auth.audit import client_fingerprint

    bind_session(
        session,
        **{
            TENANT_GUC: tenant_fingerprint(client_key),
            AUDIT_GUC: client_fingerprint(client_key),
        },
    )


def clear_session(session: Session) -> None:
    """Forget the bindings held for ``session`` (used between unit tests)."""
    session.info.pop(_INFO_KEY, None)


@event.listens_for(Session, "after_begin")
def _reapply_bindings(session, transaction, connection):  # pragma: no cover - event
    """Re-apply the tenant bindings whenever a new transaction starts.

    Without this a commit would silently drop the tenant and, under RLS, every
    following statement would see zero rows.
    """
    bindings = session.info.get(_INFO_KEY)
    if not bindings:
        return
    if connection.dialect.name != "postgresql":
        return
    _apply(connection, bindings)
