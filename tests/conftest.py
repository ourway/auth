"""Shared pytest configuration: isolate every test from any real database.

These environment variables MUST be set at conftest import time, before any
test module executes ``import auth``: ``auth.database`` builds its engine
singleton on first import, and pydantic-settings gives OS environment
variables precedence over the repo's ``.env`` file (which may point at a
real PostgreSQL instance).

``setdefault`` is used so an explicitly exported environment (e.g.
``make test-postgres`` pointing at a disposable Docker PostgreSQL) still
wins; only the silent ``.env`` fallback is neutralized.
"""

import os
import tempfile

_TEST_DB_DIR = tempfile.mkdtemp(prefix="auth-test-")
TEST_SQLITE_PATH = os.path.join(_TEST_DB_DIR, "auth_test.sqlite3")

os.environ.setdefault("AUTH_DATABASE_TYPE", "sqlite")
os.environ.setdefault("AUTH_DATABASE_URL", "")
os.environ.setdefault("AUTH_SQLITE_PATH", TEST_SQLITE_PATH)
os.environ.setdefault("AUTH_POSTGRESQL_URL", "")
os.environ.setdefault("AUTH_DATABASE_SCHEMA", "")
os.environ.setdefault("AUTH_ENABLE_ENCRYPTION", "false")
os.environ.setdefault("AUTH_ENCRYPTION_KEY", "")
os.environ.setdefault("AUTH_JWT_SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("AUTH_ENABLE_AUDIT_LOGGING", "true")
os.environ.setdefault("AUTH_AUDIT_PEPPER", "test-pepper-not-for-production")
os.environ.setdefault("AUTH_ENABLE_RATE_LIMIT", "false")
os.environ.setdefault("AUTH_DEBUG_MODE", "false")
# The legacy suites model GRANDFATHERED tenants (explicit-false reality of
# every pre-3.0 consumer). The 3.0.0 strict default for no-row tenants is
# covered explicitly in tests/test_strict_default.py.
os.environ.setdefault("AUTH_STRICT_USERS_DEFAULT", "false")

import pytest  # noqa: E402


class TestDatabaseIsolationError(AssertionError):
    """Raised when the suite is pointed at something that is not a test database."""


# Databases a postgres test run may legitimately reach. Override for a
# differently-named disposable instance; it is deliberately NOT open-ended.
ALLOWED_TEST_DATABASES = set(
    filter(None, os.environ.get("AUTH_TEST_DB_ALLOWLIST", "auth_test,postgres_test").split(","))
)


def assert_test_database(engine) -> str:
    """Refuse to run against anything that is not a disposable test database.

    Asks the SERVER which database it actually reached rather than comparing a
    connection string against a value derived from the same input. The previous
    version did the latter and could not fail: ``expected`` was built from
    ``AUTH_SQLITE_PATH`` and ``actual`` was the engine built from that same
    variable, so the two moved together for any value — pointing the suite at a
    decoy path left the whole run green. The postgres branch only asserted the
    URL scheme, which a production DSN satisfies just as well as a container's.

    Returns a description of what was reached, so a caller can show its
    evidence. Raises :class:`TestDatabaseIsolationError` otherwise.
    """
    url = engine.url
    if url.get_backend_name() == "sqlite":
        path = os.path.realpath(url.database or "")
        root = os.path.realpath(_TEST_DB_DIR)
        if not path.startswith(root + os.sep):
            raise TestDatabaseIsolationError(
                f"Test isolation broken: the SQLite database is {path!r}, which is "
                f"not inside this run's temporary directory {root!r}. Tests must "
                "never touch a database that outlives the run."
            )
        return f"sqlite at {path}"

    with engine.connect() as conn:
        row = conn.exec_driver_sql(
            "SELECT current_database(), inet_server_addr()::text, current_user"
        ).fetchone()
    database, host, user = (row[0], row[1], row[2]) if row else (None, None, None)
    if database not in ALLOWED_TEST_DATABASES:
        raise TestDatabaseIsolationError(
            f"Refusing to run the test suite against database {database!r} on "
            f"host {host!r} as {user!r}. Allowed: {sorted(ALLOWED_TEST_DATABASES)}. "
            "Set AUTH_TEST_DB_ALLOWLIST only for a genuinely disposable instance."
        )
    return f"postgresql database {database!r} on {host!r} as {user!r}"


@pytest.fixture(scope="session", autouse=True)
def _verify_test_db_isolation():
    """Fail the whole run loudly if the engine points at a non-test database."""
    from auth.database import engine

    print(f"\ntest database isolation verified: {assert_test_database(engine)}")
    yield


@pytest.fixture(autouse=True)
def _isolate_encrypted_rows():
    """Keep the deployment-wide encryption-key verdict meaningful across tests.

    The suite shares ONE SQLite database for the whole session, and several
    modules deliberately enable field encryption and write ``v2:`` ciphertext
    into it (test_api_keys_encryption, test_encryption_integration,
    test_key_rotation...). Those rows outlive the test that wrote them, so the
    next module's ``create_app()`` — running with encryption off, per the
    defaults at the top of this file — correctly reports that the database is
    encrypted with a key it does not have, and refuses /api.

    That verdict is true, and it is about a database state no deployment would
    ever be in. Rather than weaken the check, clear the ciphertext between
    tests. Production behaviour is covered out of process by
    ``audit/evaluations/probe_encryption_key_canary.py``, which asserts all
    three states (ok / mismatch / fresh) against databases of its own.
    """
    from auth import keycheck

    keycheck.reset_for_tests()
    yield
    keycheck.reset_for_tests()
    try:
        from sqlalchemy import text

        from auth.database import SessionLocal

        db = SessionLocal()
        try:
            for table in ("auth_api_key", "auth_membership"):
                db.execute(text(f'DELETE FROM {table} WHERE "user" LIKE :p'), {"p": "v2:%"})
            db.commit()
        finally:
            db.close()
    except Exception:  # pragma: no cover - the table may not exist yet
        pass
