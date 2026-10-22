import logging
import os
import subprocess
import sys
import threading
import time

import pytest
from pydantic import ValidationError
from sqlalchemy import exc, text

import auth
from auth.config import Settings
from auth.database import DatabaseEngine, PoolSettings, resolve_pool_settings

PG_URL = "postgresql+psycopg://app:s3cr3t-pw@db.example:5432/x"
POOL_ENV = (
    "AUTH_DATABASE_POOL_SIZE",
    "AUTH_DATABASE_MAX_OVERFLOW",
    "AUTH_DATABASE_POOL_TIMEOUT",
    "AUTH_DATABASE_POOL_RECYCLE",
)


@pytest.fixture(autouse=True)
def _clean_pool_env(monkeypatch):
    for name in POOL_ENV:
        monkeypatch.delenv(name, raising=False)


def _bare_engine_manager():
    return object.__new__(DatabaseEngine)


def _use_settings(monkeypatch, **env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        "auth.database.get_settings", lambda: Settings()  # type: ignore[call-arg]
    )


def test_unset_postgresql_pool_keeps_3_3_0_values():
    settings = Settings(database_url=PG_URL)
    assert resolve_pool_settings(settings) == PoolSettings(2, 2, 10, 3600)


def test_unset_sqlite_pool_keeps_3_3_0_values(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/a.db")
    assert resolve_pool_settings(settings) == PoolSettings(5, 10, 30, 300)


def test_env_overrides_every_pool_parameter(monkeypatch):
    _use_settings(
        monkeypatch,
        AUTH_DATABASE_URL=PG_URL,
        AUTH_DATABASE_POOL_SIZE="1",
        AUTH_DATABASE_MAX_OVERFLOW="0",
        AUTH_DATABASE_POOL_TIMEOUT="3.5",
        AUTH_DATABASE_POOL_RECYCLE="120",
    )
    engine = _bare_engine_manager()._create_postgresql_engine(PG_URL)
    try:
        assert engine.pool.size() == 1
        assert engine.pool._max_overflow == 0
        assert engine.pool._timeout == 3.5
        assert engine.pool._recycle == 120
    finally:
        engine.dispose()


def test_partial_override_keeps_remaining_defaults(monkeypatch):
    _use_settings(
        monkeypatch, AUTH_DATABASE_URL=PG_URL, AUTH_DATABASE_POOL_SIZE="1"
    )
    engine = _bare_engine_manager()._create_postgresql_engine(PG_URL)
    try:
        assert engine.pool.size() == 1
        assert engine.pool._max_overflow == 2
        assert engine.pool._timeout == 10
        assert engine.pool._recycle == 3600
    finally:
        engine.dispose()


def test_recycle_minus_one_is_accepted_as_never():
    settings = Settings(
        database_url=PG_URL, database_pool_recycle=-1
    )
    assert resolve_pool_settings(settings).pool_recycle == -1


@pytest.mark.parametrize(
    "name,value",
    [
        ("AUTH_DATABASE_POOL_SIZE", "0"),
        ("AUTH_DATABASE_POOL_SIZE", "-1"),
        ("AUTH_DATABASE_MAX_OVERFLOW", "-1"),
        ("AUTH_DATABASE_POOL_TIMEOUT", "0"),
        ("AUTH_DATABASE_POOL_TIMEOUT", "-5"),
        ("AUTH_DATABASE_POOL_RECYCLE", "0"),
        ("AUTH_DATABASE_POOL_RECYCLE", "-2"),
        ("AUTH_DATABASE_POOL_SIZE", "two"),
    ],
)
def test_invalid_pool_value_is_refused_without_echoing_dsn(monkeypatch, name, value):
    monkeypatch.setenv("AUTH_DATABASE_URL", PG_URL)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError) as caught:
        Settings()  # type: ignore[call-arg]
    message = str(caught.value)
    field = name.removeprefix("AUTH_").lower()
    assert field in message
    assert "s3cr3t-pw" not in message


def test_valid_boundary_values_are_accepted(monkeypatch):
    monkeypatch.setenv("AUTH_DATABASE_URL", PG_URL)
    monkeypatch.setenv("AUTH_DATABASE_POOL_SIZE", "1")
    monkeypatch.setenv("AUTH_DATABASE_MAX_OVERFLOW", "0")
    monkeypatch.setenv("AUTH_DATABASE_POOL_TIMEOUT", "0.1")
    monkeypatch.setenv("AUTH_DATABASE_POOL_RECYCLE", "1")
    settings = Settings()  # type: ignore[call-arg]
    assert resolve_pool_settings(settings) == PoolSettings(1, 0, 0.1, 1)


def _import_auth_database(tmp_path, **pool_env):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AUTH_") and key != "PGSSLMODE"
    }
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(auth.__file__)))
    env.update(
        PYTHONPATH=package_root,
        AUTH_DATABASE_URL=f"sqlite:///{tmp_path}/start.db",
        AUTH_JWT_SECRET_KEY="pool-settings-test-secret-0001",
        **pool_env,
    )
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import auth, auth.database; print(auth.__file__)",
        ],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_process_refuses_to_start_on_invalid_pool_size(tmp_path):
    good = _import_auth_database(tmp_path, AUTH_DATABASE_POOL_SIZE="1")
    assert good.returncode == 0, good.stderr
    assert good.stdout.strip() == os.path.abspath(auth.__file__)
    bad = _import_auth_database(tmp_path, AUTH_DATABASE_POOL_SIZE="0")
    assert bad.returncode != 0
    assert "database_pool_size" in bad.stderr
    assert "ValidationError" in bad.stderr


def test_effective_values_are_logged(monkeypatch, tmp_path, caplog):
    url = f"sqlite:///{tmp_path}/log.db"
    _use_settings(
        monkeypatch,
        AUTH_DATABASE_URL=url,
        AUTH_DATABASE_POOL_SIZE="3",
        AUTH_DATABASE_MAX_OVERFLOW="1",
        AUTH_DATABASE_POOL_TIMEOUT="7",
        AUTH_DATABASE_POOL_RECYCLE="90",
    )
    manager = _bare_engine_manager()
    with caplog.at_level(logging.INFO, logger="auth.database"):
        manager._initialize_engine()
    try:
        logged = " ".join(r.getMessage() for r in caplog.records)
        assert "pool_size=3" in logged
        assert "max_overflow=1" in logged
        assert "max_connections=4" in logged
        assert "pool_timeout=7.0" in logged
        assert "pool_recycle=90" in logged
    finally:
        manager.engine.dispose()


def test_exhausted_pool_times_out_then_resumes_on_release(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path}/cap.db"
    _use_settings(
        monkeypatch,
        AUTH_DATABASE_URL=url,
        AUTH_DATABASE_POOL_SIZE="1",
        AUTH_DATABASE_MAX_OVERFLOW="0",
        AUTH_DATABASE_POOL_TIMEOUT="0.5",
    )
    engine = _bare_engine_manager()._create_sqlite_engine(url)
    try:
        held = engine.connect()
        assert held.execute(text("SELECT 1")).scalar() == 1
        started = time.monotonic()
        with pytest.raises(exc.TimeoutError):
            engine.connect()
        waited = time.monotonic() - started
        assert 0.4 <= waited <= 1.5, waited

        result = {}

        def waiter():
            with engine.connect() as conn:
                result["value"] = conn.execute(text("SELECT 2")).scalar()

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.1)
        held.close()
        thread.join(timeout=5)
        assert result == {"value": 2}
    finally:
        engine.dispose()


def test_tls_url_parameters_reach_psycopg_unchanged(monkeypatch):
    monkeypatch.delenv("PGSSLMODE", raising=False)
    tls_url = (
        PG_URL
        + "?sslmode=verify-full&sslrootcert=/etc/tls/root.crt"
        + "&sslcert=/etc/tls/client.crt&sslkey=/etc/tls/client.key"
    )
    _use_settings(monkeypatch, AUTH_DATABASE_URL=tls_url)
    captured = {}

    def fake_connect(*args, **kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop before network")

    engine = _bare_engine_manager()._create_postgresql_engine(tls_url)
    monkeypatch.setattr(engine.dialect.loaded_dbapi, "connect", fake_connect)
    try:
        with pytest.raises(RuntimeError, match="stop before network"):
            engine.connect()
    finally:
        engine.dispose()
    assert captured["sslmode"] == "verify-full"
    assert captured["sslrootcert"] == "/etc/tls/root.crt"
    assert captured["sslcert"] == "/etc/tls/client.crt"
    assert captured["sslkey"] == "/etc/tls/client.key"


def test_capture_sees_forced_sslmode_when_url_has_none(monkeypatch):
    monkeypatch.delenv("PGSSLMODE", raising=False)
    _use_settings(monkeypatch, AUTH_DATABASE_URL=PG_URL)
    captured = {}

    def fake_connect(*args, **kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop before network")

    engine = _bare_engine_manager()._create_postgresql_engine(PG_URL)
    monkeypatch.setattr(engine.dialect.loaded_dbapi, "connect", fake_connect)
    try:
        with pytest.raises(RuntimeError, match="stop before network"):
            engine.connect()
    finally:
        engine.dispose()
    assert captured["sslmode"] == "require"
    assert "sslrootcert" not in captured


def _embedded_env(tmp_path):
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(auth.__file__)))
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AUTH_") and key != "PGSSLMODE"
    }
    env.update(
        PYTHONPATH=package_root,
        AUTH_DATABASE_URL=f"sqlite:///{tmp_path}/embedded.db",
        AUTH_JWT_SECRET_KEY="pool-settings-test-secret-0001",
        AUTH_STRICT_USERS_DEFAULT="false",
        AUTH_DATABASE_POOL_SIZE="1",
        AUTH_DATABASE_MAX_OVERFLOW="0",
        AUTH_DATABASE_POOL_TIMEOUT="0.5",
    )
    return env


EMBEDDED_SCRIPT = """
import logging, sys
logging.disable(logging.CRITICAL)
import auth
from sqlalchemy import exc
from auth.database import create_tables, engine, SessionLocal
create_tables(raise_on_error=True)
tenant = "11111111-1111-4111-8111-111111111111"
seed = auth.Authorization(tenant)
seed.add_role("viewer"); seed.add_permission("viewer", "read")
seed.add_membership("alice", "viewer")
seed.close()

held = auth.Authorization(tenant)
assert held.user_has_permission("alice", "read") is True
assert engine.pool.checkedout() == 1
try:
    auth.Authorization(tenant).user_has_permission("alice", "read")
    print("UNBLOCKED")
    sys.exit(3)
except exc.TimeoutError:
    pass
held.close()
assert engine.pool.checkedout() == 0

with auth.Authorization(tenant) as scoped:
    assert scoped.user_has_permission("alice", "read") is True
    assert engine.pool.checkedout() == 1
assert engine.pool.checkedout() == 0

caller_session = SessionLocal()
borrowed = auth.Authorization(tenant, db_session=caller_session)
assert borrowed.user_has_permission("alice", "read") is True
borrowed.close()
assert engine.pool.checkedout() == 1
caller_session.close()
assert engine.pool.checkedout() == 0
print("OK", auth.__file__)
"""


def test_embedded_read_holds_one_connection_until_close(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", EMBEDDED_SCRIPT],
        env=_embedded_env(tmp_path),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == f"OK {os.path.abspath(auth.__file__)}"
