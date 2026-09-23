#!/usr/bin/env python3
"""Keep audit_log's monthly partitions provisioned ahead of time.

The partition migration created partitions covering existing data plus twelve
months, and nothing has extended them since. When they run out, rows do not
fail — they land in ``audit_log_default``, which ``drop_audit_log_partitions_
before`` deliberately skips, so retention can never reclaim them and the growth
problem the migration was written to solve returns silently.

Run from cron on the database-adjacent host, NOT from inside the application:
``create_app`` runs pre-fork under ``preload_app``, so an in-process scheduler
would multiply by worker count and hold threads that do not survive ``fork()``.

    0 4 * * 1  /opt/auth/venv/bin/python /opt/auth/app/scripts/provision_audit_partitions.py

Idempotent: ``provision_audit_log_partition`` returns "already exists" for a
month it has already created.

The DSN never reaches stdout or stderr, not even inside an exception. A psycopg
error raised while PARSING a conninfo string quotes that string back in full,
password included; one raised while CONNECTING names only the endpoint. Both
arrive here as the same exception class from the same call, so the type is
reported and the body is dropped -- which is the only rule that holds without
knowing which of the two you have.

Exit codes
    0  the requested runway exists and the default partition is empty
    1  rows are sitting in the default partition, or provisioning failed
    2  misconfigured (no DSN, or a DSN that cannot be parsed or reached)
"""

import argparse
import os
import sys
from datetime import date

DSN_VARS = ("AUDIT_DB_URL", "MG_DATABASE_URL", "AUTH_DATABASE_URL", "DATABASE_URL")


def _dsn():
    for var in DSN_VARS:
        value = os.environ.get(var)
        if value:
            return value.replace("+psycopg", ""), var
    return None, None


def _months_ahead(n):
    today = date.today().replace(day=1)
    out = []
    year, month = today.year, today.month
    for _ in range(n):
        out.append(date(year, month, 1))
        month += 1
        if month > 12:
            year, month = year + 1, 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--months", type=int, default=6, help="months of runway to guarantee")
    ap.add_argument("--schema", default=os.environ.get("AUTH_DATABASE_SCHEMA", "auth_rbac"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    dsn, var = _dsn()
    if not dsn:
        print(f"ERROR: no DSN; set one of {', '.join(DSN_VARS)}", file=sys.stderr)
        return 2

    import psycopg

    print(f"provisioning {args.months} month(s) of audit_log runway (DSN from {var})")
    try:
        conn = psycopg.connect(dsn, autocommit=True)
    except psycopg.Error as exc:
        print(
            f"ERROR: could not open a connection from {var}: "
            f"{type(exc).__name__} (body withheld: it may quote the DSN)",
            file=sys.stderr,
        )
        return 2

    with conn:
        for month in _months_ahead(args.months):
            if args.dry_run:
                print(f"  would provision {month}")
                continue
            row = conn.execute(
                f'SELECT {args.schema}.provision_audit_log_partition(%s)', (month,)
            ).fetchone()
            print(f"  {month}: {row[0] if row else 'no result'}")

        default_row = conn.execute(
            f"SELECT count(*) FROM {args.schema}.audit_log_default"
        ).fetchone()
        default_rows = default_row[0] if default_row else 0
        newest = conn.execute(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_inherits i ON i.inhrelid = c.oid
            WHERE c.relkind = 'r'
              AND i.inhparent = to_regclass(%s)
              AND c.relname <> 'audit_log_default'
            ORDER BY c.relname DESC LIMIT 1
            """,
            (f"{args.schema}.audit_log",),
        ).fetchone()

    print(f"  newest partition: {newest[0] if newest else 'NONE'}")
    print(f"  rows in default partition: {default_rows}")
    if default_rows:
        print(
            "FAIL: rows are in the DEFAULT partition. Retention cannot reclaim "
            "them (drop_audit_log_partitions_before skips DEFAULT) and the "
            "provisioner has fallen behind.",
            file=sys.stderr,
        )
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
