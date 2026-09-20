#!/usr/bin/env python3
"""#19: the isolation mechanism must not itself become the cross-tenant leak.

`SET auth.tenant_fp = ...` persists for the life of the connection, and
connections are pooled. A plain SET would therefore hand the NEXT tenant to
borrow that connection the PREVIOUS tenant's identity -- a cross-tenant read
caused by the control that exists to prevent cross-tenant reads. Only
`set_config(..., is_local => true)` dies with its transaction.

The probe does not assume pool reuse, it proves it: it records the backend PID
that carried a bound tenant and waits until the pool hands that exact physical
connection back, then inspects it.

Both directions on that one reused connection:
  red half    unbound, it must report no tenant and see zero rows
  green half  re-bound, the same statement on the same connection must return
              the rows -- so "zero rows" above means RLS, not an empty table.

  AUTH_PG_URL=postgresql+psycopg://auth:...@host/db   (application role)
Without AUTH_PG_URL this reports SKIPPED, which is NOT a pass.
"""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe  # noqa: E402

MAX_BORROWS = 400


def main():
    pg = os.environ.get("AUTH_PG_URL")
    if not pg:
        print("== rls does not leak across pooled connections")
        print("   SKIPPED: AUTH_PG_URL is not set (needs a PostgreSQL deployment).")
        print("   This is NOT a pass - pool reuse was not checked.")
        return 0

    schema = os.environ.get("AUTH_PG_SCHEMA", "auth_rbac")
    import logging

    os.environ.update({
        "AUTH_DATABASE_TYPE": "postgresql", "AUTH_POSTGRESQL_URL": pg,
        "AUTH_DATABASE_URL": pg, "AUTH_DATABASE_SCHEMA": schema,
        "AUTH_ENABLE_ENCRYPTION": "false", "AUTH_ENCRYPTION_KEY": "",
        "AUTH_JWT_SECRET_KEY": "j" * 32, "AUTH_AUDIT_PEPPER": "p" * 32,
        "AUTH_ENABLE_RATE_LIMIT": "false", "AUTH_STRICT_USERS_DEFAULT": "false",
    })
    logging.disable(logging.CRITICAL)

    p = Probe(
        "rls does not leak across pooled connections",
        "that a tenant binding can outlive its transaction and reach the next borrower",
    )

    from sqlalchemy import text

    from auth.database import SessionLocal
    from auth.main import app
    from auth.rls import bind_tenant

    c = app.test_client()
    tenant = str(uuid.uuid4())
    role = f"pool_{tenant[:8]}"
    created = c.post(f"/api/role/{role}", headers={"Authorization": f"Bearer {tenant}"})
    p.check(
        "the tenant has a row to leak in the first place",
        created.status_code in (200, 201),
        f"POST /api/role/{role} -> {created.status_code}",
    )

    unscoped = text(f"SELECT count(*) FROM {schema}.auth_group")
    whoami = text("SELECT pg_backend_pid(), current_setting('auth.tenant_fp', true)")

    s = SessionLocal()
    try:
        bind_tenant(s, tenant)
        pid, fp = s.execute(whoami).one()
        bound_rows = s.execute(unscoped).scalar_one()
        s.commit()
    finally:
        s.close()

    p.check(
        "the binding was in effect on that connection",
        bool(fp) and bound_rows >= 1,
        f"backend pid={pid} tenant_fp={(fp or '')[:12]}... rows={bound_rows}",
    )

    borrows, reused = 0, None
    while borrows < MAX_BORROWS and reused is None:
        borrows += 1
        s = SessionLocal()
        try:
            again, leaked = s.execute(whoami).one()
            if again == pid:
                reused = (leaked, s.execute(unscoped).scalar_one())
            s.commit()
        finally:
            s.close()

    if reused is None:
        p.check(
            "the pool handed back the same physical connection",
            False,
            f"backend pid={pid} never reappeared in {borrows} borrows - "
            "the check could not be performed, so it proves nothing",
        )
        return p.done()

    leaked_fp, leaked_rows = reused
    p.check(
        "the pool handed back the same physical connection",
        True,
        f"backend pid={pid} reappeared after {borrows} borrows",
    )
    p.check(
        "the reused connection carries no tenant",
        not leaked_fp,
        f"current_setting('auth.tenant_fp') = {leaked_fp!r}",
    )
    p.check(
        "and the unbound borrower sees zero rows",
        leaked_rows == 0,
        f"unscoped count on the reused connection = {leaked_rows}",
    )

    s = SessionLocal()
    try:
        bind_tenant(s, tenant)
        control = s.execute(unscoped).scalar_one()
        s.commit()
    finally:
        s.close()
    p.check(
        "control: the same statement still returns rows when bound",
        control >= 1,
        f"bound count = {control} - so the zero above is RLS, not an empty table",
    )
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
