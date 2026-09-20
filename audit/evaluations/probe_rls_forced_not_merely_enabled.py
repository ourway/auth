#!/usr/bin/env python3
"""#19: RLS that is ENABLEd but not FORCEd protects nothing from the app role.

The application connects as the role that OWNS these tables, and PostgreSQL
exempts a table's owner from its policies unless FORCE is set. So a deployment
can carry every policy this design specifies, report `relrowsecurity = true`,
and still serve every tenant's rows to every caller.

Two directions, because a check that cannot go red is not evidence:

  green  every protected table reports enabled AND forced AND >=1 policy, and
         the boot verifier says so.
  red    with FORCE removed from one table, the boot verifier must refuse to
         serve. This half rewrites DDL, so it needs AUDIT_ALLOW_DESTRUCTIVE=1
         and a superuser URL. Blast radius: tenant isolation is off on one
         table for the duration, so point it at a test database.

  AUTH_PG_URL=postgresql+psycopg://auth:...@host/db         (application role)
  AUTH_PG_SUPERUSER_URL=postgresql://pgadmin:...@host/db    (red half only)
Without AUTH_PG_URL this reports SKIPPED, which is NOT a pass.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe  # noqa: E402

STATE = """
SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = :schema AND c.relname = ANY(:names)
ORDER BY c.relname
"""


def main():
    pg = os.environ.get("AUTH_PG_URL")
    if not pg:
        print("== rls forced, not merely enabled")
        print("   SKIPPED: AUTH_PG_URL is not set (needs a PostgreSQL deployment).")
        print("   This is NOT a pass - owner bypass was not checked.")
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
        "rls forced, not merely enabled",
        "that ENABLE ROW LEVEL SECURITY is sufficient when the app owns the tables",
    )

    from sqlalchemy import text

    from auth import keycheck
    from auth.database import SessionLocal
    from auth.main import app  # noqa: F401

    names = list(keycheck._RLS_TABLES)
    s = SessionLocal()
    try:
        rows = s.execute(text(STATE), {"schema": schema, "names": names}).fetchall()
    finally:
        s.close()

    p.check(
        "every protected table is present",
        len(rows) == len(names),
        f"{len(rows)}/{len(names)} found in {schema}: {sorted(r[0] for r in rows)}",
    )
    for name, enabled, forced, policies in rows:
        p.check(
            f"{name} forced with policies",
            bool(enabled and forced and policies > 0),
            f"enabled={enabled} forced={forced} policies={policies}",
        )

    s = SessionLocal()
    try:
        keycheck.reset_for_tests()
        green = keycheck.verify_row_level_security(s)
    finally:
        s.close()
    p.check(
        "boot verifier accepts a correctly forced deployment",
        green == keycheck.OK,
        f"state={green} detail={keycheck.detail()!r}",
    )

    su = os.environ.get("AUTH_PG_SUPERUSER_URL")
    allow = os.environ.get("AUDIT_ALLOW_DESTRUCTIVE") == "1"
    if not (su and allow):
        print("   NOTE: the red half did not run (needs AUTH_PG_SUPERUSER_URL and")
        print("   AUDIT_ALLOW_DESTRUCTIVE=1). The verifier was not shown able to")
        print("   refuse, so the green result above is weaker than it looks.")
        return p.done()

    victim = names[0]
    import sqlalchemy as sa

    admin = sa.create_engine(su, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f"ALTER TABLE {schema}.{victim} NO FORCE ROW LEVEL SECURITY"))
        s = SessionLocal()
        try:
            keycheck.reset_for_tests()
            red = keycheck.verify_row_level_security(s)
            detail = keycheck.detail()
        finally:
            s.close()
        p.check(
            f"boot verifier refuses when {victim} is only ENABLEd",
            red == keycheck.MISMATCH,
            f"state={red} detail={detail!r}",
        )
        p.check(
            "and it names the offending table",
            victim in detail,
            f"detail={detail!r}",
        )
    finally:
        with admin.connect() as conn:
            conn.execute(text(f"ALTER TABLE {schema}.{victim} FORCE ROW LEVEL SECURITY"))
        admin.dispose()

    s = SessionLocal()
    try:
        keycheck.reset_for_tests()
        restored = keycheck.verify_row_level_security(s)
    finally:
        s.close()
    p.check(
        "and accepts again once FORCE is restored",
        restored == keycheck.OK,
        f"state={restored}",
    )
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
