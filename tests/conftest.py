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
os.environ.setdefault("AUTH_DEBUG_MODE", "false")

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _verify_test_db_isolation():
    """Fail the whole run loudly if the engine ever points at a non-test DB."""
    from auth.database import engine

    url = str(engine.url)
    if os.environ["AUTH_DATABASE_TYPE"] == "postgresql":
        assert url.startswith("postgresql+psycopg://"), (
            f"Postgres test run resolved an unexpected engine URL: {url!r}"
        )
    else:
        expected = f"sqlite:///{os.environ['AUTH_SQLITE_PATH']}"
        assert url == expected, (
            f"Test isolation broken: engine URL is {url!r}, expected {expected!r}. "
            "Check that no module imported `auth` before tests/conftest.py ran."
        )
    yield
