"""
Rotation vs concurrent writes must serialize (audit R1/R2/R3) — PostgreSQL only.

Rotation and the mutating writes take a transaction-scoped advisory lock keyed on
the tenant, so a rotation cannot interleave with a concurrent write (or another
rotation) for the same tenant: the scan-then-reassign pass sees a stable row set.
This test proves the primitive deterministically — the lock excludes the same
tenant and does NOT block a different tenant — using the exact key expression the
service uses (`pg_advisory_xact_lock(hashtext(:k))`).
"""

import os
import uuid

import pytest

pytestmark = pytest.mark.postgres

if os.environ.get("AUTH_DATABASE_TYPE") != "postgresql":
    pytest.skip(
        "AUTH_DATABASE_TYPE != postgresql — run via 'make test-postgres'",
        allow_module_level=True,
    )

from sqlalchemy import text  # noqa: E402

from auth.database import create_tables, engine  # noqa: E402

_LOCK = text("SELECT pg_advisory_xact_lock(hashtext(:k))")
_TRY = text("SELECT pg_try_advisory_xact_lock(hashtext(:k))")


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


def test_advisory_lock_excludes_same_tenant_not_others():
    tenant = str(uuid.uuid4())
    other = str(uuid.uuid4())

    holder = engine.connect()
    contender = engine.connect()
    try:
        ht = holder.begin()
        holder.execute(_LOCK, {"k": tenant})  # rotation holds the tenant lock

        ct = contender.begin()
        # A concurrent op on the SAME tenant cannot acquire it...
        assert contender.execute(_TRY, {"k": tenant}).scalar() is False
        # ...but a DIFFERENT tenant is unaffected (no global bottleneck).
        assert contender.execute(_TRY, {"k": other}).scalar() is True
        ct.rollback()

        ht.rollback()  # holder releases

        # Once released, the same tenant lock is acquirable again.
        ct2 = contender.begin()
        assert contender.execute(_TRY, {"k": tenant}).scalar() is True
        ct2.rollback()
    finally:
        holder.close()
        contender.close()
