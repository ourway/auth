"""
Reconciliation of pre-2.x varchar columns to TEXT (issuedb #21).

``create_all(checkfirst=True)`` creates missing tables but never ALTERs an
existing one, so an embedded database created by a pre-2.x version keeps the
narrow ``varchar`` widths that version declared. Encryption made those columns
hold ciphertext much longer than the plaintext they used to, so the mismatch
surfaces as ``StringDataRightTruncation`` on write — highway hit it on
``auth_membership.user`` inside ``add_membership`` (agent-mail
thr-d99bb6c79b894ff69f16).

This suite recreates a pre-2.x database shape on a real PostgreSQL and asserts
BOTH directions: the narrow column genuinely breaks the write first (otherwise
the fix would be proving nothing), and reconciliation both widens it and lets
the same write through afterwards.

Run via `make test-postgres`.
"""

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
from sqlalchemy.exc import DataError  # noqa: E402

from auth import Authorization  # noqa: E402
from auth.database import (  # noqa: E402
    SessionLocal,
    _reconcile_text_columns,
    create_tables,
    engine,
)

SCHEMA = os.environ.get("AUTH_DATABASE_SCHEMA") or "public"

# Long enough that its encrypted form overflows varchar(64) — the shape of the
# identifier highway was storing when add_membership started failing.
LONG_USER = (
    "a-rather-long-user-identifier-for-overflow@some-customer-domain.example.com"
)


def _column_type(table: str, column: str):
    """(data_type, character_maximum_length) as PostgreSQL actually has it."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT data_type, character_maximum_length "
                "FROM information_schema.columns "
                "WHERE table_schema = :s AND table_name = :t AND column_name = :c"
            ),
            {"s": SCHEMA, "t": table, "c": column},
        ).one()


@pytest.fixture(scope="module", autouse=True)
def _bootstrap():
    create_tables(raise_on_error=True)


@pytest.fixture
def narrowed_membership_user():
    """Put auth_membership.user back to the pre-2.x varchar(64), then restore."""
    with engine.begin() as conn:
        conn.execute(
            text(
                f'ALTER TABLE "{SCHEMA}".auth_membership '
                'ALTER COLUMN "user" TYPE VARCHAR(64)'
            )
        )
    yield
    with engine.begin() as conn:
        conn.execute(
            text(
                f'ALTER TABLE "{SCHEMA}".auth_membership '
                'ALTER COLUMN "user" TYPE TEXT'
            )
        )


def test_narrow_column_genuinely_breaks_the_write(narrowed_membership_user):
    """Known-positive: without this, the fix below would prove nothing.

    The pre-2.x width must actually reject the encrypted value, or a green
    'it works after reconciliation' is vacuous.
    """
    assert _column_type("auth_membership", "user") == ("character varying", 64)

    session = SessionLocal()
    try:
        client = Authorization(client=str(uuid.uuid4()), db_session=session)
        client.add_role("member")
        with pytest.raises(DataError):
            client.add_membership(LONG_USER, "member")
    finally:
        session.rollback()
        session.close()


def test_reconciliation_widens_the_column_and_unblocks_the_write(
    narrowed_membership_user,
):
    assert _column_type("auth_membership", "user") == ("character varying", 64)

    _reconcile_text_columns(engine)

    assert _column_type("auth_membership", "user") == ("text", None)

    session = SessionLocal()
    try:
        client = Authorization(client=str(uuid.uuid4()), db_session=session)
        client.add_role("member")
        assert client.add_membership(LONG_USER, "member") is True
        # Round-trip through the widened, encrypted column — the write landing
        # is not enough; the value has to come back intact.
        assert client.has_membership(LONG_USER, "member") is True
        assert LONG_USER in [m["user"] for m in client.get_role_members("member")]
    finally:
        session.close()


def test_reconciliation_is_a_no_op_when_the_database_already_matches():
    """Second run must issue no ALTERs — the pass has to be idempotent, since
    create_tables runs on every boot."""
    before = _column_type("auth_membership", "user")
    assert before == ("text", None)

    _reconcile_text_columns(engine)
    _reconcile_text_columns(engine)

    assert _column_type("auth_membership", "user") == ("text", None)


def test_bounded_string_columns_are_left_alone():
    """audit_log.user is a 64-char fingerprint by design, not an identifier.

    A blanket 'widen everything' pass would destroy that deliberate bound, so
    the rule is strictly 'only where the model declares Text'.
    """
    assert _column_type("audit_log", "user") == ("character varying", 64)
    _reconcile_text_columns(engine)
    assert _column_type("audit_log", "user") == ("character varying", 64)
