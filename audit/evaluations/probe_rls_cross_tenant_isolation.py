#!/usr/bin/env python3
"""#19: tenant isolation must be enforced by the DATABASE, not by the query.

Falsified state: every read path filtered on `creator` because the query said
so. One query that forgot was a cross-tenant leak with nothing underneath it.

The queries below carry NO WHERE CLAUSE, so any filtering is the database's
doing. A superuser runs the same statement as a known-positive: it proves the
rows exist and the statement can return them, so an empty or filtered result is
RLS working rather than an empty table.

Requires a real PostgreSQL deployment with the RLS migration applied:
  AUTH_PG_URL=postgresql+psycopg://auth:...@host/db  (as the APPLICATION role)
  AUTH_PG_SUPERUSER_URL=postgresql://pgadmin:...@host/db   (optional control)
Without AUTH_PG_URL this reports SKIPPED, which is NOT a pass.
"""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, raw_dsn  # noqa: E402

UNSCOPED = "SELECT role FROM {schema}.auth_group ORDER BY role"


def main():
    pg = os.environ.get("AUTH_PG_URL")
    if not pg:
        print("== rls cross-tenant isolation")
        print("   SKIPPED: AUTH_PG_URL is not set (needs a PostgreSQL deployment).")
        print("   This is NOT a pass - isolation was not checked.")
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
        "rls cross-tenant isolation",
        "that tenant isolation is a query convention rather than a database invariant",
    )
    from sqlalchemy import text

    from auth.database import SessionLocal
    from auth.main import app
    from auth.rls import bind_tenant

    c = app.test_client()
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    ra, rb = f"role_{a[:8]}", f"role_{b[:8]}"
    c.post(f"/api/role/{ra}", headers={"Authorization": f"Bearer {a}"})
    c.post(f"/api/role/{rb}", headers={"Authorization": f"Bearer {b}"})

    stmt = text(UNSCOPED.format(schema=schema))

    def unscoped(key):
        s = SessionLocal()
        try:
            if key:
                bind_tenant(s, key)
            return [r[0] for r in s.execute(stmt)]
        finally:
            s.close()

    seen_a, seen_b, seen_none = unscoped(a), unscoped(b), unscoped(None)
    p.check("an unscoped query returns only the bound tenant's rows (A)",
            ra in seen_a and rb not in seen_a, f"{seen_a[:6]}")
    p.check("an unscoped query returns only the bound tenant's rows (B)",
            rb in seen_b and ra not in seen_b, f"{seen_b[:6]}")
    p.check("with NO tenant bound the query returns nothing (fail-closed)",
            seen_none == [], repr(seen_none))

    su = raw_dsn(os.environ.get("AUTH_PG_SUPERUSER_URL"))
    if su:
        import psycopg

        with psycopg.connect(su) as conn:
            allrows = [r[0] for r in conn.execute(UNSCOPED.format(schema=schema))]
        p.check("CONTROL: a superuser sees both, so the rows exist and the query works",
                ra in allrows and rb in allrows, f"{len(allrows)} rows incl. both tenants")
    else:
        p.check("CONTROL: both tenants' rows were created",
                bool(seen_a) and bool(seen_b),
                "set AUTH_PG_SUPERUSER_URL for the stronger bypass-RLS control")
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
