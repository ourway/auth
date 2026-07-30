"""Alembic environment for the auth service.

Resolves the database URL and optional schema from the application's own
settings (``auth.config``) and uses the app's SQLAlchemy metadata as the target,
so migrations follow whatever database the deployment is configured for.

Alembic owns schema *changes*; initial table creation is still handled by
``auth.database.create_tables`` (``Base.metadata.create_all``). Migrations here
are written to be safe when a table does not yet exist.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

# Import the modules that register tables on Base.metadata.
import auth.audit  # noqa: F401  (registers AuditLog)
from auth.config import get_settings
from auth.models.sql import Base

config = context.config

if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:  # logging config is best-effort, never fatal
        pass

target_metadata = Base.metadata

_settings = get_settings()
_schema = _settings.database_schema or None


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live connection (``alembic upgrade --sql``)."""
    context.configure(
        url=_settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table_schema=_schema,
        include_schemas=bool(_schema),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _settings.database_url
    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        if _schema:
            connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{_schema}"'))
            connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=_schema,
            include_schemas=bool(_schema),
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
