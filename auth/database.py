
"""
SQLAlchemy database session management
"""
import sqlite3
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from auth.config import DatabaseType, get_settings


def get_db_engine():
    """Create and return a new database engine"""
    settings = get_settings()

    if settings.database_type == DatabaseType.POSTGRESQL:
        connect_args = {
            "connect_timeout": 30,
            "application_name": "auth_server",
        }
        if "localhost" not in settings.database_url and "127.0.0.1" not in settings.database_url:
            connect_args["sslmode"] = "require"

        return create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_recycle=300,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            echo=False,
            isolation_level="READ_COMMITTED",
            connect_args=connect_args,
        )
    else:
        return create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_recycle=300,
            pool_size=5,
            max_overflow=10,
            connect_args={
                "check_same_thread": False,
                "timeout": 60,
                "detect_types": sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            },
        )

engine = get_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create database tables"""
    import logging

    from sqlalchemy.exc import OperationalError

    from auth.models.sql import Base

    logger = logging.getLogger(__name__)
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        logger.info("Tables created successfully.")
    except (OperationalError, sqlite3.OperationalError):
        logger.info("Tables already exist.")


