import os
import time

import pytest

pytestmark = pytest.mark.postgres

if os.environ.get("AUTH_DATABASE_TYPE") != "postgresql":
    pytest.skip(
        "AUTH_DATABASE_TYPE != postgresql — run via 'make test-postgres'",
        allow_module_level=True,
    )

from sqlalchemy import text  # noqa: E402

from auth.database import create_tables, engine  # noqa: E402
from auth.schema_check import (  # noqa: E402
    SchemaMismatchError,
    check_schema,
    find_schema_drift,
)

SCHEMA = os.environ.get("AUTH_DATABASE_SCHEMA") or None


def _name(column):
    table = "auth_tenant_settings"
    return f"{SCHEMA}.{table}.{column}" if SCHEMA else f"{table}.{column}"


@pytest.fixture(scope="module", autouse=True)
def _tables():
    create_tables(raise_on_error=True)


def test_migrated_database_passes_within_budget():
    started = time.monotonic()
    check_schema(engine)
    elapsed = time.monotonic() - started
    assert elapsed < 0.5, elapsed


def test_v310_shape_names_the_three_columns_then_passes_after_ddl():
    qualified = f"{SCHEMA}.auth_tenant_settings" if SCHEMA else "auth_tenant_settings"
    with engine.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(
                text(
                    f"ALTER TABLE {qualified} DROP COLUMN rotate_key_hash CASCADE, "
                    "DROP COLUMN rotate_key_issued_at, DROP COLUMN canary"
                )
            )
            with pytest.raises(SchemaMismatchError) as caught:
                check_schema(conn)
            assert caught.value.missing_tables == []
            assert caught.value.missing_columns == [
                _name("rotate_key_hash"),
                _name("rotate_key_issued_at"),
                _name("canary"),
            ]
            password = engine.url.password
            assert not password or password not in str(caught.value)
            assert str(engine.url.host) not in str(caught.value)
            assert str(engine.url.database) not in str(caught.value)

            conn.execute(
                text(
                    f"ALTER TABLE {qualified} "
                    "ADD COLUMN IF NOT EXISTS rotate_key_hash varchar(64), "
                    "ADD COLUMN IF NOT EXISTS rotate_key_issued_at timestamp without time zone, "
                    "ADD COLUMN IF NOT EXISTS canary text"
                )
            )
            assert find_schema_drift(conn) == ([], [])
        finally:
            transaction.rollback()
    assert find_schema_drift(engine) == ([], [])
