import os
import time

import pytest

pytestmark = pytest.mark.postgres

if os.environ.get("AUTH_DATABASE_TYPE") != "postgresql":
    pytest.skip(
        "AUTH_DATABASE_TYPE != postgresql — run via 'make test-postgres'",
        allow_module_level=True,
    )

from sqlalchemy import exc, text  # noqa: E402

from auth.config import Settings  # noqa: E402
from auth.database import DatabaseEngine  # noqa: E402


@pytest.fixture
def capped_engine(monkeypatch):
    monkeypatch.setenv("AUTH_DATABASE_POOL_SIZE", "1")
    monkeypatch.setenv("AUTH_DATABASE_MAX_OVERFLOW", "1")
    monkeypatch.setenv("AUTH_DATABASE_POOL_TIMEOUT", "1")
    monkeypatch.setattr(
        "auth.database.get_settings", lambda: Settings()  # type: ignore[call-arg]
    )
    settings = Settings()  # type: ignore[call-arg]
    engine = object.__new__(DatabaseEngine)._create_postgresql_engine(
        settings.database_url
    )
    yield engine
    engine.dispose()


def _backend_pid(conn):
    return conn.execute(text("SELECT pg_backend_pid()")).scalar()


def test_real_server_cap_blocks_then_resumes(capped_engine):
    first = capped_engine.connect()
    second = capped_engine.connect()
    pids = {_backend_pid(first), _backend_pid(second)}
    assert len(pids) == 2

    started = time.monotonic()
    with pytest.raises(exc.TimeoutError):
        capped_engine.connect()
    waited = time.monotonic() - started
    assert 0.9 <= waited <= 2.5, waited

    second.close()
    with capped_engine.connect() as third:
        assert _backend_pid(third) in pids
    first.close()
    assert capped_engine.pool.checkedout() == 0
