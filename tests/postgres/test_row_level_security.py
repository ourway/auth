"""Row level security must be in force in the database, not merely intended.

The rest of this suite passes with RLS stripped out entirely -- measured, by
dropping every policy and re-running it: 15 passed. That is expected, because
those tests drive the application, and the application filters on `creator`
whether or not the database also does. So nothing here would notice if the
policies went away, which is exactly how a control disappears quietly.

These tests fail when it does. They also fail if the suite is pointed at a
superuser, because such a role bypasses RLS and could not tell the difference
either -- a loud failure being the right answer to "this environment cannot
verify the thing you are asking about".

WHAT THEY DO AND DO NOT GUARD, measured rather than assumed. The bootstrap here
calls create_tables(), which calls auth_rbac.apply_tenant_rls(), which repairs
RLS. So stripping every policy and running this file still passes -- verified,
and it is why the first version of these tests could not go red. What they
guard is that the MECHANISM produces a correctly protected database: a policy
that stops matching, a table nobody added to the set, a migration that did not
run, apply_tenant_rls() itself breaking. Dropping that function and then
stripping the policies fails every assertion below, which is the red control
for this file.
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

from auth import Authorization  # noqa: E402
from auth.database import SessionLocal, create_tables, engine  # noqa: E402
from auth.keycheck import _RLS_TABLES  # noqa: E402
from auth.rls import bind_tenant  # noqa: E402

SCHEMA = os.environ.get("AUTH_DATABASE_SCHEMA") or "public"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


def _is_exempt(conn):
    """Whether row level security is skipped outright for the current role.

    The two columns are read separately and each is required to be a real
    boolean. `rolsuper OR rolbypassrls` collapses to NULL if either is NULL and
    to no row at all if current_user is absent from pg_roles, and bool(None) is
    False -- so the unhardened version answers "not exempt" to every question it
    cannot actually answer, which is the direction that lets an exempt
    connection through as if it were safe.
    """
    row = conn.execute(
        text(
            "SELECT rolsuper, rolbypassrls FROM pg_roles "
            "WHERE rolname = current_user"
        )
    ).first()
    assert row is not None, (
        "current_user has no pg_roles row, so exemption from row level security "
        "cannot be determined; refusing to assume it is absent"
    )
    superuser, bypassrls = row
    assert isinstance(superuser, bool) and isinstance(bypassrls, bool), (
        f"pg_roles returned non-boolean privilege flags "
        f"(rolsuper={superuser!r}, rolbypassrls={bypassrls!r}); refusing to "
        "treat an unreadable answer as 'not exempt'"
    )
    return superuser or bypassrls


@pytest.fixture(scope="module")
def unprivileged_sessions():
    """A session factory whose role row level security actually applies to.

    `make test-postgres` connects as a non-superuser that owns the tables, so
    the app's own sessions are already subject to policies and are used as-is.
    CI's postgres job connects as the container superuser, which bypasses RLS
    outright -- there, this creates a throwaway unprivileged role and hands back
    sessions bound to that instead, so the behavioural check below verifies
    policies rather than quietly verifying nothing.

    Skipping in the privileged case was the other option and is the wrong one:
    the environment that cannot check is exactly the environment where nobody
    finds out.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    with engine.begin() as conn:
        if not _is_exempt(conn):
            yield SessionLocal
            return

    name = f"rls_probe_{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        conn.execute(text(f"CREATE ROLE {name} LOGIN PASSWORD '{name}' NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text(f'GRANT USAGE ON SCHEMA "{SCHEMA}" TO {name}'))
        conn.execute(
            text(f'GRANT SELECT ON ALL TABLES IN SCHEMA "{SCHEMA}" TO {name}')
        )
    probe_engine = create_engine(engine.url.set(username=name, password=name))
    try:
        with probe_engine.begin() as conn:
            assert not _is_exempt(conn), f"{name} was created exempt from RLS"
        yield sessionmaker(bind=probe_engine)
    finally:
        probe_engine.dispose()
        with engine.begin() as conn:
            conn.execute(
                text(f'REVOKE ALL ON ALL TABLES IN SCHEMA "{SCHEMA}" FROM {name}')
            )
            conn.execute(text(f'REVOKE USAGE ON SCHEMA "{SCHEMA}" FROM {name}'))
            conn.execute(text(f"DROP ROLE {name}"))


@pytest.mark.parametrize("table", _RLS_TABLES)
def test_every_tenant_table_is_enabled_forced_and_policied(table):
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, "
                "(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = :t"
            ),
            {"s": SCHEMA, "t": table},
        ).first()
    assert row is not None, f"{SCHEMA}.{table} does not exist"
    enabled, forced, policies = row
    assert enabled, f"{table}: row level security is not enabled"
    assert forced, (
        f"{table}: ENABLE without FORCE. The application owns this table and "
        "PostgreSQL exempts a table's owner, so this protects nothing while "
        "every other test still passes."
    )
    assert policies > 0, f"{table}: no policy, so the table is deny-all or open"


def test_an_unscoped_query_returns_only_the_bound_tenant(unprivileged_sessions):
    """No WHERE clause, so any filtering here is the database's doing."""
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    role_a, role_b = f"rls_{a[:8]}", f"rls_{b[:8]}"
    for key, role in ((a, role_a), (b, role_b)):
        s = SessionLocal()
        try:
            Authorization(client=key, db_session=s).add_role(role)
        finally:
            s.close()

    stmt = text(f'SELECT role FROM "{SCHEMA}".auth_group')  # noqa: S608

    def unscoped(key):
        s = unprivileged_sessions()
        try:
            if key:
                bind_tenant(s, key)
            return {r[0] for r in s.execute(stmt)}
        finally:
            s.close()

    seen_a, seen_b, seen_none = unscoped(a), unscoped(b), unscoped(None)

    assert role_a in seen_a, (
        "the bound tenant cannot see its own row, so this test proves nothing "
        "about isolation -- it would 'pass' against an empty table"
    )
    assert role_b not in seen_a, f"{role_b} leaked into tenant A's unscoped read"
    assert role_b in seen_b and role_a not in seen_b
    assert seen_none == set(), (
        "an unbound session read rows; with no tenant set the policy must match "
        "nothing"
    )
