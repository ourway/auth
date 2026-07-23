"""The Alembic migration stack loads, applies, and reverses cleanly.

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
    cfg.set_main_option("script_location", os.path.join(_ROOT, "migrations"))
    return cfg


def test_upgrade_head_runs():
    # Alembic owns changes; create_tables owns creation. Tables must exist first.
    create_tables(raise_on_error=True)
    command.upgrade(_config(), "head")  # must not raise


def test_downgrade_then_upgrade_roundtrips():
    cfg = _config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
