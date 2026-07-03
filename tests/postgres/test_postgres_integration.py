"""
PostgreSQL integration tests — the deployment shape the Highway engine runs
(schema=auth_rbac, deterministic encryption ON).

Run via `make test-postgres`: it starts a disposable Docker PostgreSQL and
invokes pytest in a SEPARATE process with AUTH_* env pointing at it (the
engine singleton binds at import, so this suite cannot share a process with
the SQLite suite).
"""

import concurrent.futures
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


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    # Must create the auth_rbac schema itself on a fresh database
    create_tables(raise_on_error=True)


@pytest.fixture
def auth_client():
    session = SessionLocal()
    client = Authorization(client=str(uuid.uuid4()), db_session=session)
    yield client
    session.close()


def test_schema_bootstrap_created_tables_in_configured_schema():
    schema = os.environ["AUTH_DATABASE_SCHEMA"]
    assert schema, "suite requires AUTH_DATABASE_SCHEMA (Highway uses auth_rbac)"
    with engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = :schema"
                ),
                {"schema": schema},
            )
        }
    assert {
        "auth_group",
        "auth_membership",
        "auth_permission",
        "membership_groups",
        "permission_groups",
        "audit_log",
    } <= tables


def test_full_lifecycle_with_encryption(auth_client):
    assert os.environ.get("AUTH_ENABLE_ENCRYPTION") == "true"
    assert auth_client.add_role("admin", description="Administrators") is True
    assert auth_client.add_permission("admin", "manage_users") is True
    assert auth_client.add_membership("alice@example.com", "admin") is True

    assert auth_client.user_has_permission("alice@example.com", "manage_users") is True
    assert auth_client.get_user_roles("alice@example.com") == [
        {"user": "alice@example.com", "role": "admin"}
    ]
    assert auth_client.roles[0]["description"] == "Administrators"


def test_values_are_stored_encrypted(auth_client):
    auth_client.add_role("secure", description="Secret desc")
    auth_client.add_membership("carol@example.com", "secure")
    schema = os.environ["AUTH_DATABASE_SCHEMA"]
    with engine.connect() as conn:
        stored_desc = conn.execute(
            text(
                f'SELECT description FROM "{schema}".auth_group '  # noqa: S608
                "WHERE creator = :creator AND role = 'secure'"
            ),
            {"creator": auth_client.client},
        ).scalar()
        stored_user = conn.execute(
            text(
                f'SELECT "user" FROM "{schema}".auth_membership '  # noqa: S608
                "WHERE creator = :creator"
            ),
            {"creator": auth_client.client},
        ).scalar()
    assert stored_desc != "Secret desc"  # encrypted at rest (add_role bug fixed)
    assert stored_user != "carol@example.com"


def test_legacy_plaintext_description_stays_readable(auth_client):
    """Rows written unencrypted by the pre-1.4 add_role bug must still render."""
    auth_client.add_role("legacy")
    schema = os.environ["AUTH_DATABASE_SCHEMA"]
    with engine.begin() as conn:
        conn.execute(
            text(
                f'UPDATE "{schema}".auth_group '  # noqa: S608
                "SET description = 'plain old text!' "
                "WHERE creator = :creator AND role = 'legacy'"
            ),
            {"creator": auth_client.client},
        )
    roles = {r["role"]: r for r in auth_client.roles}
    assert roles["legacy"]["description"] == "plain old text!"


def test_upsert_idempotency_under_concurrency():
    """Concurrent add_role for the same (creator, role) must not raise or
    duplicate — the ON CONFLICT upsert is the whole point of the write path."""
    client_key = str(uuid.uuid4())

    def add(_):
        session = SessionLocal()
        try:
            return Authorization(client=client_key, db_session=session).add_role(
                "hot-role", description="contended"
            )
        finally:
            session.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(add, range(16)))
    assert all(results)

    session = SessionLocal()
    try:
        roles = Authorization(client=client_key, db_session=session).roles
        assert [r["role"] for r in roles] == ["hot-role"]
    finally:
        session.close()


def test_tenant_isolation_on_postgres():
    session_a, session_b = SessionLocal(), SessionLocal()
    a = Authorization(client=str(uuid.uuid4()), db_session=session_a)
    b = Authorization(client=str(uuid.uuid4()), db_session=session_b)
    try:
        assert a.add_role("shared-name") is True
        assert b.add_role("shared-name") is True
        a.add_membership("alice@example.com", "shared-name")
        assert b.get_role_members("shared-name") == []
    finally:
        session_a.close()
        session_b.close()
