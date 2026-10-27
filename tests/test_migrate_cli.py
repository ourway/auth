import os
import subprocess
import sys
from pathlib import Path

import pytest

from auth import migrate
from auth.keycheck import RLS_SCHEMA, _schema_hint

ROOT = Path(__file__).resolve().parent.parent


def _sql_names(directory):
    return sorted(p.name for p in Path(directory).glob("*.sql"))


def test_packaged_directory_holds_every_migration():
    packaged = _sql_names(migrate.migrations_root() / "migrations")
    assert len(packaged) >= 12
    assert "01M2Y9WFEY32ZWDP161SHR1B2M_add_apply_tenant_rls_function.sql" in packaged


def test_root_migrations_path_is_the_packaged_directory():
    assert (ROOT / "migrations").resolve() == (ROOT / "auth" / "migrations").resolve()
    assert _sql_names(ROOT / "migrations") == _sql_names(ROOT / "auth" / "migrations")


@pytest.mark.parametrize(
    "environ,expected",
    [
        ({"MG_DATABASE_URL": "postgresql://a@h/d"}, "postgresql://a@h/d"),
        ({"AUTH_DATABASE_URL": "postgresql+psycopg://a@h/d"}, "postgresql://a@h/d"),
        ({"AUTH_POSTGRESQL_URL": "postgres+psycopg://a@h/d"}, "postgresql://a@h/d"),
        (
            {"MG_DATABASE_URL": "postgresql://mg@h/d", "AUTH_DATABASE_URL": "postgresql://app@h/d"},
            "postgresql://mg@h/d",
        ),
        ({"MG_DATABASE_URL": "  ", "AUTH_DATABASE_URL": "postgresql://app@h/d"}, "postgresql://app@h/d"),
        ({}, None),
    ],
)
def test_database_url_precedence_and_driver_prefix(environ, expected):
    assert migrate.database_url(environ) == expected


def test_unknown_or_missing_command_is_refused(capsys):
    assert migrate.main([]) == 2
    assert migrate.main(["create", "x"]) == 2
    assert migrate.main(["rollback"]) == 2
    assert "usage: auth-migrate" in capsys.readouterr().err


def test_missing_url_is_refused(monkeypatch, capsys):
    for name in migrate.URL_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    assert migrate.main(["status"]) == 2
    assert "set MG_DATABASE_URL" in capsys.readouterr().err


def test_non_postgres_url_is_refused_without_echoing_it(monkeypatch, capsys):
    for name in migrate.URL_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AUTH_DATABASE_URL", "sqlite:////tmp/secret-path.sqlite3")
    assert migrate.main(["apply"]) == 2
    err = capsys.readouterr().err
    assert "PostgreSQL only" in err
    assert "secret-path" not in err


def test_runs_migretti_in_the_packaged_directory(monkeypatch):
    calls = []

    def fake_call(command, cwd, env):
        calls.append((command, cwd, env["MG_DATABASE_URL"]))
        return 0

    for name in migrate.URL_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AUTH_DATABASE_URL", "postgresql+psycopg://u:p@h:5432/d")
    monkeypatch.setattr(migrate.subprocess, "call", fake_call)
    assert migrate.main(["apply", "--yes"]) == 0
    command, cwd, url = calls[0]
    assert command == [sys.executable, "-m", "migretti", "apply", "--yes"]
    assert Path(cwd) == migrate.migrations_root()
    assert url == "postgresql://u:p@h:5432/d"


def test_module_entry_point_prints_usage():
    result = subprocess.run(
        [sys.executable, "-m", "auth.migrate"],
        capture_output=True,
        text=True,
        env={**os.environ, "MG_DATABASE_URL": ""},
    )
    assert result.returncode == 2
    assert "usage: auth-migrate" in result.stderr


def test_schema_hint_names_the_setting_only_when_it_is_wrong():
    assert _schema_hint(RLS_SCHEMA) == ""
    hint = _schema_hint("public")
    assert "AUTH_DATABASE_SCHEMA is 'public'" in hint
    assert "'auth_rbac'" in hint
