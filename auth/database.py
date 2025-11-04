"""
SQLAlchemy database models and session management
"""

import os
import sqlite3
from contextlib import contextmanager
from typing import TYPE_CHECKING, Generator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

if TYPE_CHECKING:
    pass

from sqlalchemy.sql import func

# Create base class for SQLAlchemy models
Base = declarative_base()

# Default database path - can be overridden by AUTH_DB_PATH environment variable
default_db_path = os.path.expanduser("~/.auth.sqlite3")
DB_PATH = os.environ.get("AUTH_DB_PATH", default_db_path)

# Create engine with connection pooling and SQLite optimizations
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    pool_pre_ping=True,
    pool_recycle=300,  # Recycle connections after 5 minutes
    pool_size=1,  # Connection pool size
    max_overflow=0,  # Maximum overflow connections
    isolation_level="SERIALIZABLE",  # Set serializable isolation level (highest for SQLite)
    connect_args={
        "check_same_thread": False,
        "timeout": 30,  # Connection timeout in seconds
        "detect_types": sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
    },
)


# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Association tables
membership_groups = Table(
    "membership_groups",
    Base.metadata,
    Column(
        "membership_id", Integer, ForeignKey("auth_membership.id"), primary_key=True
    ),
    Column("group_id", Integer, ForeignKey("auth_group.id"), primary_key=True),
)

permission_groups = Table(
    "permission_groups",
    Base.metadata,
    Column(
        "permission_id", Integer, ForeignKey("auth_permission.id"), primary_key=True
    ),
    Column("group_id", Integer, ForeignKey("auth_group.id"), primary_key=True),
)


class AuthGroup(Base):
    """AuthGroup model for SQLAlchemy"""

    __tablename__ = "auth_group"

    id = Column(Integer, primary_key=True, index=True)
    creator = Column(String(64), nullable=False, index=True)
    role = Column(String(32), nullable=False, index=True)
    description = Column(String(256))
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    memberships = relationship(
        "AuthMembership", secondary=membership_groups, back_populates="groups"
    )
    permissions = relationship(
        "AuthPermission", secondary=permission_groups, back_populates="groups"
    )

    __table_args__ = (
        UniqueConstraint("creator", "role", name="uq_auth_group_creator_role"),
        {
            "sqlite_autoincrement": True,
        },
    )


class AuthMembership(Base):
    """AuthMembership model for SQLAlchemy"""

    __tablename__ = "auth_membership"

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String(64), nullable=False, index=True)
    creator = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    groups = relationship(
        "AuthGroup", secondary=membership_groups, back_populates="memberships"
    )

    __table_args__ = (
        UniqueConstraint("creator", "user", name="uq_auth_membership_creator_user"),
        {
            "sqlite_autoincrement": True,
        },
    )


class AuthPermission(Base):
    """AuthPermission model for SQLAlchemy"""

    __tablename__ = "auth_permission"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), nullable=False, index=True)
    creator = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    groups = relationship(
        "AuthGroup", secondary=permission_groups, back_populates="permissions"
    )

    __table_args__ = (
        UniqueConstraint("creator", "name", name="uq_auth_permission_creator_name"),
        {
            "sqlite_autoincrement": True,
        },
    )


def create_tables():
    """Create all tables if they don't exist and apply SQLite optimizations"""
    import sqlite3

    from sqlalchemy.exc import OperationalError

    # Apply SQLite optimizations
    try:
        with engine.connect() as conn:
            # Enable WAL mode for better concurrency
            conn.execute(text("PRAGMA journal_mode=WAL"))
            # Enable synchronous NORMAL for better performance
            conn.execute(text("PRAGMA synchronous=ON"))
            # Increase cache size (64MB)
            conn.execute(
                text("PRAGMA cache_size=-65536")
            )  # Negative value indicates KB
            # Enable foreign key constraints
            conn.execute(text("PRAGMA foreign_keys=ON"))
            # Optimize query planner
            conn.execute(text("PRAGMA optimize"))
            conn.commit()
    except (OperationalError, sqlite3.OperationalError):
        # It's ok if optimizations fail due to concurrent access
        pass

    # Create tables
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
    except (OperationalError, sqlite3.OperationalError) as e:
        # Check if it's a table exists error (can happen with multiple workers)
        if (
            "already exists" not in str(e).lower()
            and "such table" not in str(e).lower()
        ):
            raise
        # Otherwise, ignore the error as tables already exist


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Dependency to get database session with proper cleanup"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
