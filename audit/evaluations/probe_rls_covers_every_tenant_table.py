#!/usr/bin/env python3
"""#19: a table added later must not be silently unprotected.

The other RLS probes assert today's tables, so they pass unchanged on the day
someone adds a sixth creator-bearing table and forgets the policy. This one
asks the DATABASE which tables carry tenant data and requires each to be
forced and policied -- so the list it checks grows by itself.

Three populations are discovered rather than listed:
  * every table in the schema with a `creator` column
  * every partition of `audit_log`. A partition needs ENABLE and FORCE but no
    policy of its own: read through the parent the parent's policy applies,
    read directly nothing matches and the answer is no rows. Provisioned
    without them -- which is what the monthly cron did until #19 -- a direct
    query against the partition returns every tenant's entries.
  * the junction tables, which carry no tenant column and so cannot be
    discovered by the first rule

  AUTH_PG_URL=postgresql+psycopg://auth:...@host/db   (application role)
Without AUTH_PG_URL this reports SKIPPED, which is NOT a pass.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe  # noqa: E402

CREATOR_TABLES = """
SELECT DISTINCT c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
WHERE n.nspname = :schema AND c.relkind IN ('r', 'p')
  AND a.attname = 'creator' AND a.attnum > 0 AND NOT a.attisdropped
"""

AUDIT_PARTITIONS = """
SELECT c.relname
FROM pg_class c
JOIN pg_inherits i ON i.inhrelid = c.oid
JOIN pg_class par ON par.oid = i.inhparent
JOIN pg_namespace n ON n.oid = par.relnamespace
WHERE n.nspname = :schema AND par.relname = 'audit_log'
"""

PROTECTION = """
SELECT c.relrowsecurity, c.relforcerowsecurity,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = :schema AND c.relname = :name
"""

JUNCTIONS = ("membership_groups", "permission_groups")


def main():
    pg = os.environ.get("AUTH_PG_URL")
    if not pg:
        print("== rls covers every tenant table")
        print("   SKIPPED: AUTH_PG_URL is not set (needs a PostgreSQL deployment).")
        print("   This is NOT a pass - coverage was not checked.")
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
        "rls covers every tenant table",
        "that the protected set is whatever the policies happen to name today",
    )

    from sqlalchemy import text

    from auth.database import SessionLocal

    s = SessionLocal()
    try:
        creators = sorted(r[0] for r in s.execute(text(CREATOR_TABLES), {"schema": schema}))
        partitions = sorted(r[0] for r in s.execute(text(AUDIT_PARTITIONS), {"schema": schema}))
        p.check(
            "discovery finds the known creator-bearing tables",
            {"auth_group", "auth_membership", "auth_permission", "auth_api_key",
             "auth_tenant_settings"}.issubset(set(creators)),
            f"{len(creators)} found: {creators}",
        )
        audit_log = s.execute(
            text(PROTECTION), {"schema": schema, "name": "audit_log"}
        ).first()
        if audit_log is not None:
            enabled, forced, policies = audit_log
            p.check(
                "audit_log is forced and policied",
                bool(enabled and forced and policies > 0),
                f"enabled={enabled} forced={forced} policies={policies}",
            )
        else:
            p.check(
                "audit_log is absent, so there is no audit data to protect",
                True,
                "no audit_log table in this deployment",
            )
        # Partitions are not required: audit_log is created by the ORM after
        # migrations run, so a fresh database has an unpartitioned one. What
        # matters here is that any partition that DOES exist is protected --
        # the parent's policy does not cover a query naming the partition.
        p.check(
            "partition discovery ran",
            True,
            f"{len(partitions)} partition(s) found: {partitions[:3] or 'none'}",
        )
        for name in creators + list(JUNCTIONS):
            row = s.execute(text(PROTECTION), {"schema": schema, "name": name}).first()
            if row is None:
                p.check(f"{name} exists", False, "not found in pg_class")
                continue
            enabled, forced, policies = row
            p.check(
                f"{name} is forced and policied",
                bool(enabled and forced and policies > 0),
                f"enabled={enabled} forced={forced} policies={policies}",
            )
        for name in partitions:
            row = s.execute(text(PROTECTION), {"schema": schema, "name": name}).first()
            if row is None:
                p.check(f"{name} exists", False, "not found in pg_class")
                continue
            enabled, forced, _ = row
            p.check(
                f"{name} is forced",
                bool(enabled and forced),
                f"enabled={enabled} forced={forced} - without both, a direct "
                "query on this partition bypasses the parent's policy",
            )
    finally:
        s.close()
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
