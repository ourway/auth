"""audit_log must be partitioned on any database, including a fresh one.

No migration created audit_log: the ORM did, at first boot, after migrations
had run. partition_audit_log therefore found nothing and skipped, and a
database built from migrations alone ended up with a PLAIN audit_log
(issuedb #20). Nothing failed -- rows were written, queries worked -- but
drop_audit_log_partitions_before can only drop partitions, so retention could
never reclaim anything and the growth the partitioning was introduced to solve
returned with no symptom.

CI builds exactly such a database, which is why these assertions belong here
rather than in the probe harness: the gap was reachable by the suite that ran
on every commit and invisible to it.
"""

import os

import pytest

pytestmark = pytest.mark.postgres

if os.environ.get("AUTH_DATABASE_TYPE") != "postgresql":
    pytest.skip(
        "AUTH_DATABASE_TYPE != postgresql — run via 'make test-postgres'",
        allow_module_level=True,
    )

from sqlalchemy import text  # noqa: E402

from auth.database import create_tables, engine  # noqa: E402

SCHEMA = os.environ.get("AUTH_DATABASE_SCHEMA") or "public"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


def _one(sql, **params):
    with engine.begin() as conn:
        return conn.execute(text(sql), params).scalar()


def test_audit_log_is_partitioned_not_a_plain_heap():
    kind = _one(
        "SELECT c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = :s AND c.relname = 'audit_log'",
        s=SCHEMA,
    )
    assert kind is not None, f"{SCHEMA}.audit_log does not exist"
    assert kind == "p", (
        f"audit_log is relkind {kind!r}, not 'p'. A plain heap cannot be "
        "reclaimed by drop_audit_log_partitions_before, which only drops "
        "partitions, so retention silently does nothing forever."
    )


def test_it_is_partitioned_by_timestamp():
    key = _one(
        "SELECT pg_get_partkeydef(c.oid) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = :s AND c.relname = 'audit_log'",
        s=SCHEMA,
    )
    assert key == 'RANGE ("timestamp")', (
        f"partition key is {key!r}. Retention drops whole months, so the key "
        "must be the timestamp."
    )


def test_a_default_partition_exists_as_a_trap():
    assert _one(
        "SELECT count(*) FROM pg_class c JOIN pg_inherits i ON i.inhrelid = c.oid "
        "WHERE i.inhparent = to_regclass(:p) AND c.relname = 'audit_log_default'",
        p=f"{SCHEMA}.audit_log",
    ) == 1, (
        "no DEFAULT partition: a row whose timestamp no partition covers would "
        "fail the INSERT and take the audit trail down with it"
    )


def test_there_is_future_runway():
    """Partitions are finite and nothing renewed them until #15."""
    ahead = _one(
        "SELECT count(*) FROM pg_class c JOIN pg_inherits i ON i.inhrelid = c.oid "
        "WHERE i.inhparent = to_regclass(:p) AND c.relname <> 'audit_log_default' "
        "AND c.relname > 'audit_log_' || to_char(now(), 'YYYY_MM')",
        p=f"{SCHEMA}.audit_log",
    )
    total = _one(
        "SELECT count(*) FROM pg_inherits WHERE inhparent = to_regclass(:p)",
        p=f"{SCHEMA}.audit_log",
    )
    assert total > 1, (
        f"only {total} partition(s) exist, so the discovery is not finding them "
        "and every assertion here is vacuous"
    )
    assert ahead >= 3, (
        f"only {ahead} partition(s) cover months after this one. When they run "
        "out rows land in audit_log_default, which retention skips, and nothing "
        "fails visibly."
    )


def test_the_default_partition_is_empty():
    stranded = _one(f'SELECT count(*) FROM "{SCHEMA}".audit_log_default')  # noqa: S608
    assert stranded == 0, (
        f"{stranded} row(s) are in audit_log_default. Retention skips that "
        "partition, so they can never be reclaimed; they must be moved into a "
        "real partition by hand."
    )
