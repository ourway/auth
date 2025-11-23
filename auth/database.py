
"""
SQLAlchemy database session management with enterprise-grade connection pooling
"""
import logging
import sqlite3
import threading
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, event, pool
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import Pool

from auth.config import DatabaseType, get_settings

logger = logging.getLogger(__name__)


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

    def _calculate_pool_size(self) -> tuple[int, int]:
        """
        Calculate optimal pool size for Gunicorn workers

        For 8 workers with PostgreSQL:
        - pool_size=5 per worker = 40 base connections
        - max_overflow=5 per worker = 80 total max connections
        - Leaves headroom for PostgreSQL default max_connections (100)
        - Also accounts for other services using the database

        Returns:
            tuple: (pool_size, max_overflow)
        """
        settings = get_settings()

        if settings.database_type == DatabaseType.POSTGRESQL:
            # Conservative sizing for production with multiple workers
            return (5, 5)  # 10 max connections per worker
        else:
            # SQLite - smaller pool since it's file-based
            return (5, 10)

    def _create_postgresql_engine(self, database_url: str) -> Engine:
        """Create optimized PostgreSQL engine with enterprise pooling"""
        pool_size, max_overflow = self._calculate_pool_size()

        connect_args = {
            "connect_timeout": 30,
            "application_name": "auth_server",
            # Set statement timeout to prevent long-running queries
            "options": "-c statement_timeout=30000",  # 30 seconds
        }

        # Enable SSL for remote connections
        if "localhost" not in database_url and "127.0.0.1" not in database_url:
            connect_args["sslmode"] = "require"

        return create_engine(
            database_url,
            # Connection pool settings
            poolclass=pool.QueuePool,  # Explicitly use QueuePool
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=30,  # Wait up to 30s for a connection
            pool_recycle=3600,  # Recycle connections after 1 hour
            pool_pre_ping=True,  # Verify connections before using them

            # Performance settings
            echo=False,  # Disable SQL logging in production
            echo_pool=False,  # Disable pool logging (we use events instead)
            isolation_level="READ COMMITTED",  # PostgreSQL default

            connect_args=connect_args,
        )

    def _create_sqlite_engine(self, database_url: str) -> Engine:
        """Create SQLite engine with connection pooling"""
        pool_size, max_overflow = self._calculate_pool_size()

        return create_engine(
            database_url,
            poolclass=pool.QueuePool,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,
            pool_recycle=300,  # 5 minutes for SQLite
            pool_timeout=30,
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

        pool_size, max_overflow = self._calculate_pool_size()
        logger.info(
            f"Database engine initialized: pool_size={pool_size}, "
            f"max_overflow={max_overflow}, max_connections={pool_size + max_overflow}"
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


def create_tables():
    """Create database tables"""
    from sqlalchemy.exc import OperationalError

    from auth.models.sql import Base

    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        logger.info("Tables created successfully.")
    except (OperationalError, sqlite3.OperationalError):
        logger.info("Tables already exist.")


def log_pool_stats():
    """Log current connection pool statistics"""
    stats = get_pool_status()
    logger.info(f"Connection pool stats: {stats}")
