"""The RETIRED Alembic migration stack still loads, applies, and reverses.

Alembic is frozen at its single legacy revision (0001_widen_text, applied in
production) and lives in migrations_legacy_alembic/; NEW migrations are
migretti SQL files in migrations/ (see MIGRATIONS.md). These tests keep the
legacy tree loadable so the recorded history stays reproducible.

On SQLite the widening migration is a no-op (SQLite ignores varchar length), so
these assert the framework wiring — env.py resolves the app's database, the
revision imports, and upgrade/downgrade run without error. The real varchar->TEXT
behaviour is exercised against PostgreSQL in the integration run.
"""

import os

import pytest

pytest.importorskip("alembic")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

from auth.database import create_tables  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _config() -> Config:
    cfg = Config(os.path.join(_ROOT, "alembic.ini"))
    cfg.set_main_option(
        "script_location", os.path.join(_ROOT, "migrations_legacy_alembic")
    )
    return cfg


def test_upgrade_head_runs():
    # Alembic owns changes; create_tables owns creation. Tables must exist first.
    create_tables(raise_on_error=True)
    command.upgrade(_config(), "head")  # must not raise


def test_downgrade_then_upgrade_roundtrips():
    cfg = _config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
