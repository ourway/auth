"""
SQLAlchemy database session management with enterprise-grade connection pooling
"""

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Generator, NamedTuple, Optional

from sqlalchemy import create_engine, event, pool
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import Pool

from auth.config import DatabaseType, Settings, get_settings, warn_on_weak_secrets
from auth.schema_reconcile import (
    GRANDFATHER_MARKER,  # noqa: F401  - re-exported; tests and embedded callers import it from here
    _apply_tenant_rls,
    _ensure_audit_partition_runway,
    _grandfather_strict_users,
    _reconcile_text_columns,
)


def _forced_sslmode(database_url: str) -> Optional[str]:
    """The sslmode to force via connect_args, or None to leave it alone.

    Secure-by-default SSL for remote hosts — but never overriding an explicit
    caller choice. connect_args beat URL conninfo in psycopg, so forcing
    sslmode here would silently discard a ``?sslmode=...`` the caller wrote
    (highway report, agent-mail thr-7745c815fd0a425cabac). Precedence:
    URL sslmode param > PGSSLMODE env > require-for-remote. The host is
    decided by component comparison, not URL substring — a URL carrying
    ``?fallback_application_name=localhost`` must not skip SSL.
    """
    url = make_url(database_url)
    if "sslmode" in url.query or os.environ.get("PGSSLMODE"):
        return None
    host = (url.host or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return None
    return "require"


logger = logging.getLogger(__name__)


class PoolSettings(NamedTuple):
    pool_size: int
    max_overflow: int
    pool_timeout: float
    pool_recycle: int


_POSTGRESQL_POOL_DEFAULTS = PoolSettings(2, 2, 10.0, 3600)
_SQLITE_POOL_DEFAULTS = PoolSettings(5, 10, 30.0, 300)


def resolve_pool_settings(settings: Settings) -> PoolSettings:
    defaults = (
        _POSTGRESQL_POOL_DEFAULTS
        if settings.database_type == DatabaseType.POSTGRESQL
        else _SQLITE_POOL_DEFAULTS
    )
    return PoolSettings(
        pool_size=(
            defaults.pool_size
            if settings.database_pool_size is None
            else settings.database_pool_size
        ),
        max_overflow=(
            defaults.max_overflow
            if settings.database_max_overflow is None
            else settings.database_max_overflow
        ),
        pool_timeout=(
            defaults.pool_timeout
            if settings.database_pool_timeout is None
            else settings.database_pool_timeout
        ),
        pool_recycle=(
            defaults.pool_recycle
            if settings.database_pool_recycle is None
            else settings.database_pool_recycle
        ),
    )


class SingletonMeta(type):
    """
    Thread-safe Singleton metaclass for database engine
    Ensures only one engine instance exists per process (Gunicorn worker)
    """

    _instances: dict[type, object] = {}
    _lock: threading.Lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]


class DatabaseEngine(metaclass=SingletonMeta):
    """
    Singleton database engine manager for enterprise-grade connection pooling

    Features:
    - Thread-safe singleton pattern
    - Optimized connection pooling for Gunicorn workers
    - Connection pool monitoring and statistics
    - Automatic stale connection handling
    - Connection pool event logging
    """

    def __init__(self):
        """Initialize the database engine with optimized pooling"""
        self._engine: Optional[Engine] = None
        self._session_factory: Optional[sessionmaker] = None
        self._initialize_engine()
        self._setup_pool_monitoring()

    def _pool_settings(self) -> PoolSettings:
        return resolve_pool_settings(get_settings())

    def _calculate_pool_size(self) -> tuple[int, int]:
        pool_settings = self._pool_settings()
        return (pool_settings.pool_size, pool_settings.max_overflow)

    def _create_postgresql_engine(self, database_url: str) -> Engine:
        """Create optimized PostgreSQL engine with enterprise pooling"""
        pool_settings = self._pool_settings()

        connect_args = {
            "connect_timeout": 30,
            "application_name": "auth_server",
            # Set statement timeout to prevent long-running queries
            # 10s: the slowest legitimate operation is a key rotation, measured
            # at ~0.12 ms/row (~1s for the largest namespace on this deployment),
            # so this leaves 10x headroom.
            #
            # NOTE: statement_timeout does NOT bound COMMIT. A commit stall is
            # therefore unaffected by this value, which is why worker
            # concurrency -- not this timeout -- is the mitigation for a stalled
            # database. tcp_user_timeout would bound it at the socket, but
            # dropping a connection mid-COMMIT leaves the outcome ambiguous, and
            # an ambiguous permission grant is a worse failure than a slow one.
            "options": "-c statement_timeout=10000",  # 10 seconds
        }

        forced = _forced_sslmode(database_url)
        if forced:
            connect_args["sslmode"] = forced

        return create_engine(
            database_url,
            # Connection pool settings
            poolclass=pool.QueuePool,  # Explicitly use QueuePool
            pool_size=pool_settings.pool_size,
            max_overflow=pool_settings.max_overflow,
            pool_timeout=pool_settings.pool_timeout,
            pool_recycle=pool_settings.pool_recycle,
            pool_pre_ping=True,  # Verify connections before using them
            # Performance settings
            echo=False,  # Disable SQL logging in production
            echo_pool=False,  # Disable pool logging (we use events instead)
            isolation_level="READ COMMITTED",  # PostgreSQL default
            connect_args=connect_args,
        )

    def _create_sqlite_engine(self, database_url: str) -> Engine:
        """Create SQLite engine with connection pooling"""
        if ":memory:" in database_url:
            # A QueuePool would hand out a different empty in-memory database
            # per pooled connection; share a single connection instead.
            return create_engine(
                database_url,
                poolclass=pool.StaticPool,
                connect_args={"check_same_thread": False},
            )

        pool_settings = self._pool_settings()

        return create_engine(
            database_url,
            poolclass=pool.QueuePool,
            pool_size=pool_settings.pool_size,
            max_overflow=pool_settings.max_overflow,
            pool_pre_ping=True,
            pool_recycle=pool_settings.pool_recycle,
            pool_timeout=pool_settings.pool_timeout,
            connect_args={
                "check_same_thread": False,
                "timeout": 60,
                "detect_types": sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            },
        )

    def _initialize_engine(self):
        """Initialize the database engine based on configuration"""
        settings = get_settings()

        logger.info(
            f"Initializing database engine: type={settings.database_type.value}, "
            f"worker_pid={threading.get_ident()}"
        )

        if settings.database_type == DatabaseType.POSTGRESQL:
            self._engine = self._create_postgresql_engine(settings.database_url)
        else:
            self._engine = self._create_sqlite_engine(settings.database_url)

        # Create session factory
        self._session_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self._engine,
            expire_on_commit=False,  # Prevent unnecessary queries
        )

        pool_settings = self._pool_settings()
        logger.info(
            f"Database engine initialized: pool_size={pool_settings.pool_size}, "
            f"max_overflow={pool_settings.max_overflow}, "
            f"max_connections={pool_settings.pool_size + pool_settings.max_overflow}, "
            f"pool_timeout={pool_settings.pool_timeout}, "
            f"pool_recycle={pool_settings.pool_recycle}"
        )

    def _setup_pool_monitoring(self):
        """Set up connection pool event monitoring for debugging and statistics"""
        if not self._engine:
            return

        @event.listens_for(self._engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            """Log new connections"""
            logger.debug(f"New database connection established: {id(dbapi_conn)}")

        @event.listens_for(self._engine, "checkout")
        def receive_checkout(dbapi_conn, connection_record, connection_proxy):
            """Log connection checkout from pool"""
            logger.debug(f"Connection checked out from pool: {id(dbapi_conn)}")

        @event.listens_for(self._engine, "checkin")
        def receive_checkin(dbapi_conn, connection_record):
            """Log connection checkin to pool"""
            logger.debug(f"Connection returned to pool: {id(dbapi_conn)}")

        @event.listens_for(Pool, "invalidate")
        def receive_invalidate(dbapi_conn, connection_record, exception):
            """Log connection invalidation"""
            logger.warning(
                f"Connection invalidated: {id(dbapi_conn)}, reason: {exception}"
            )

        @event.listens_for(Pool, "soft_invalidate")
        def receive_soft_invalidate(dbapi_conn, connection_record):
            """Log soft connection invalidation"""
            logger.info(f"Connection soft invalidated: {id(dbapi_conn)}")

    def get_pool_status(self) -> dict:
        """
        Get current connection pool status and statistics

        Returns:
            dict: Pool statistics including size, checked out connections, overflow
        """
        if not self._engine:
            return {}

        pool = self._engine.pool
        return {
            "pool_size": pool.size(),  # type: ignore[attr-defined]
            "checked_out": pool.checkedout(),  # type: ignore[attr-defined]
            "overflow": pool.overflow(),  # type: ignore[attr-defined]
            "total_connections": pool.size() + pool.overflow(),  # type: ignore[attr-defined]
            "available": pool.size() - pool.checkedout(),  # type: ignore[attr-defined]
        }

    @property
    def engine(self) -> Engine:
        """Get the database engine"""
        if not self._engine:
            raise RuntimeError("Database engine not initialized")
        return self._engine

    @property
    def session_factory(self) -> sessionmaker:
        """Get the session factory"""
        if not self._session_factory:
            raise RuntimeError("Session factory not initialized")
        return self._session_factory

    def dispose(self):
        """Dispose of the connection pool (useful for cleanup)"""
        if self._engine:
            logger.info("Disposing database engine and connection pool")
            self._engine.dispose()


# Global singleton instance
_db_engine = DatabaseEngine()

# Module-level convenience accessors
engine = _db_engine.engine
SessionLocal = _db_engine.session_factory


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of operations.

    This is the recommended way to get database sessions.
    The session is automatically closed when the context exits.

    Usage:
        with get_db() as db:
            # Use db here
            pass
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_pool_status() -> dict:
    """
    Get current connection pool status

    Returns:
        dict: Pool statistics
    """
    return _db_engine.get_pool_status()


def create_tables(raise_on_error: bool = False):
    """Create database tables (and the configured schema on PostgreSQL).

    Non-raising by default: this runs at import time via auth.main, and
    existing deployments rely on the app starting even when the runtime DB
    role has no DDL rights. Failures are logged with the real exception.
    """
    from sqlalchemy import text

    import auth.audit  # noqa: F401  (registers AuditLog in Base.metadata)
    from auth.models.sql import Base

    settings = get_settings()
    # An embedded consumer reaching create_tables *is* running the server side
    # of auth, so weak server secrets are actionable for them here (they are
    # not for a client-only consumer, which never gets this far).
    warn_on_weak_secrets(settings)
    try:
        if (
            settings.database_type == DatabaseType.POSTGRESQL
            and settings.database_schema
        ):
            with engine.begin() as conn:
                conn.execute(
                    text(f'CREATE SCHEMA IF NOT EXISTS "{settings.database_schema}"')
                )
        Base.metadata.create_all(bind=engine, checkfirst=True)
        # Row level security first, and each step separately: these are
        # independent reconciliations, and letting one exception abort the rest
        # is how a fresh database came up with the junction tables unprotected
        # -- grandfathering raised, and the RLS step below it never ran.
        _apply_tenant_rls(engine)
        _ensure_audit_partition_runway(engine)
        _reconcile_text_columns(engine)
        _grandfather_strict_users(engine)
        logger.info("Tables created successfully.")
    except Exception:
        logger.exception("create_tables failed")
        if raise_on_error:
            raise


def log_pool_stats():
    """Log current connection pool statistics"""
    stats = get_pool_status()
    logger.info(f"Connection pool stats: {stats}")
