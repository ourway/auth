import logging

import pytest
from sqlalchemy import MetaData, create_engine, event, text

import auth
import auth.audit  # noqa: F401
import auth.database
from auth.models.sql import Base
from auth.schema_check import SchemaMismatchError, check_schema, find_schema_drift

V310_TENANT_SETTINGS = (
    "CREATE TABLE auth_tenant_settings ("
    "id INTEGER PRIMARY KEY, creator VARCHAR(64) NOT NULL, "
    "strict_users BOOLEAN NOT NULL, date_created DATETIME, modified DATETIME)"
)
V340_ADDED = [
    "auth_tenant_settings.rotate_key_hash",
    "auth_tenant_settings.rotate_key_issued_at",
    "auth_tenant_settings.canary",
]

pytestmark = pytest.mark.skipif(
    any(t.schema for t in Base.metadata.tables.values()),
    reason="SQLite drift tests build unqualified tables",
)


@pytest.fixture
def current_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'current.sqlite3'}")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def v310_engine(current_engine):
    with current_engine.begin() as conn:
        conn.execute(text("DROP TABLE auth_tenant_settings"))
        conn.execute(text(V310_TENANT_SETTINGS))
    return current_engine


def _statements(engine):
    seen = []
    event.listen(
        engine,
        "before_cursor_execute",
        lambda conn, cursor, statement, *a: seen.append(statement),
    )
    return seen


def test_current_schema_passes(current_engine):
    assert find_schema_drift(current_engine) == ([], [])
    check_schema(current_engine)


def test_v310_tenant_settings_names_the_three_missing_columns(v310_engine):
    assert find_schema_drift(v310_engine) == ([], V340_ADDED)
    with pytest.raises(SchemaMismatchError) as caught:
        check_schema(v310_engine)
    assert caught.value.missing_columns == V340_ADDED
    assert caught.value.missing_tables == []
    for name in V340_ADDED:
        assert name in str(caught.value)


def test_missing_table_is_named(current_engine):
    with current_engine.begin() as conn:
        conn.execute(text("DROP TABLE auth_tenant_settings"))
    with pytest.raises(SchemaMismatchError) as caught:
        check_schema(current_engine)
    assert caught.value.missing_tables == ["auth_tenant_settings"]
    assert caught.value.missing_columns == []
    assert "missing tables: auth_tenant_settings" in str(caught.value)


def test_extra_live_columns_are_allowed(current_engine):
    with current_engine.begin() as conn:
        conn.execute(text("ALTER TABLE auth_tenant_settings ADD COLUMN creator_fp TEXT"))
    check_schema(current_engine)


def test_check_issues_no_ddl_or_writes(v310_engine):
    seen = _statements(v310_engine)
    with v310_engine.begin() as conn:
        conn.execute(text("ALTER TABLE auth_tenant_settings ADD COLUMN probe TEXT"))
    assert any(s.startswith("ALTER TABLE") for s in seen)
    seen.clear()
    with pytest.raises(SchemaMismatchError):
        check_schema(v310_engine)
    assert seen
    writes = ("CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE")
    assert [s for s in seen if s.lstrip().upper().startswith(writes)] == []


def test_message_does_not_carry_the_database_location(v310_engine):
    with pytest.raises(SchemaMismatchError) as caught:
        check_schema(v310_engine)
    assert str(v310_engine.url.database) not in str(caught.value)
    assert "sqlite" not in str(caught.value)


def test_create_tables_raises_on_drift_when_asked(v310_engine, monkeypatch):
    monkeypatch.setattr(auth.database, "engine", v310_engine)
    with pytest.raises(SchemaMismatchError) as caught:
        auth.database.create_tables(raise_on_error=True)
    assert caught.value.missing_columns == V340_ADDED


def test_create_tables_logs_drift_by_default(v310_engine, monkeypatch, caplog):
    monkeypatch.setattr(auth.database, "engine", v310_engine)
    with caplog.at_level(logging.ERROR, logger=auth.database.logger.name):
        auth.database.create_tables()
    logged = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    assert "create_tables failed" in logged
    for name in V340_ADDED:
        assert name in logged
    assert "Tables created successfully." not in caplog.text


def test_create_tables_on_current_schema_reports_success(current_engine, monkeypatch, caplog):
    monkeypatch.setattr(auth.database, "engine", current_engine)
    with caplog.at_level(logging.INFO, logger=auth.database.logger.name):
        auth.database.create_tables(raise_on_error=True)
    assert "Tables created successfully." in caplog.text


def test_empty_model_metadata_refuses_instead_of_passing(current_engine, monkeypatch):
    seen = _statements(current_engine)
    monkeypatch.setattr(Base, "metadata", MetaData())
    with pytest.raises(SchemaMismatchError) as caught:
        check_schema(current_engine)
    assert "register no tables" in str(caught.value)
    assert caught.value.missing_tables == []
    assert caught.value.missing_columns == []
    with pytest.raises(SchemaMismatchError):
        find_schema_drift(current_engine)
    assert seen == []


def test_public_exports():
    assert auth.check_schema is check_schema
    assert auth.SchemaMismatchError is SchemaMismatchError
    assert {"check_schema", "SchemaMismatchError"} <= set(auth.__all__)
