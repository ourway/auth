"""widen variable/encrypted columns to TEXT

Reconciles the code(varchar)-vs-prod(text) drift and removes the varchar limits
that encrypted values (user, permission name, description) can overflow, plus the
audit columns that attacker-controlled input can overflow.

Only alters on PostgreSQL — SQLite ignores varchar length, so the change is a
no-op there. ``ALTER ... TYPE text`` on a column that is already ``text`` is a
safe no-op, so this migration is idempotent for deployments whose columns were
manually altered. Tables that do not yet exist are skipped.

Revision ID: 0001_widen_text
Revises:
Create Date: 2026-07-23
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_widen_text"
down_revision = None
branch_labels = None
depends_on = None

# (table, column) pairs to widen to TEXT.
_COLUMNS = [
    ("auth_group", "role"),
    ("auth_group", "description"),
    ("auth_membership", "user"),
    ("auth_permission", "name"),
    ("audit_log", "client_id"),
    ("audit_log", "resource"),
    ("audit_log", "user_agent"),
]

# Previous varchar widths, for downgrade().
_PREVIOUS = {
    ("auth_group", "role"): sa.String(255),
    ("auth_group", "description"): sa.String(512),
    ("auth_membership", "user"): sa.String(255),
    ("auth_permission", "name"): sa.String(255),
    ("audit_log", "client_id"): sa.String(64),
    ("audit_log", "resource"): sa.String(100),
    ("audit_log", "user_agent"): sa.String(500),
}


def _schema():
    from auth.config import get_settings

    return get_settings().database_schema or None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    schema = _schema()
    existing = set(sa.inspect(bind).get_table_names(schema=schema))
    for table, column in _COLUMNS:
        if table in existing:
            op.alter_column(table, column, type_=sa.Text(), schema=schema)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    schema = _schema()
    existing = set(sa.inspect(bind).get_table_names(schema=schema))
    for (table, column), type_ in _PREVIOUS.items():
        if table in existing:
            op.alter_column(
                table,
                column,
                type_=type_,
                schema=schema,
                postgresql_using=f"{column}::text",
            )
