"""
SQLAlchemy database models and session management
"""

import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from sqlalchemy.sql import func
from contextlib import contextmanager
from typing import Generator

# Default database path - can be overridden by AUTH_DB_PATH environment variable
default_db_path = os.path.expanduser("~/.auth.sqlite3")
DB_PATH = os.environ.get('AUTH_DB_PATH', default_db_path)

# Create engine with connection pooling
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    pool_pre_ping=True,
    pool_recycle=300,  # Recycle connections after 5 minutes
    connect_args={"check_same_thread": False}
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Association tables
membership_groups = Table(
    'membership_groups', Base.metadata,
    Column('membership_id', Integer, ForeignKey('auth_membership.id'), primary_key=True),
    Column('group_id', Integer, ForeignKey('auth_group.id'), primary_key=True)
)

permission_groups = Table(
    'permission_groups', Base.metadata,
    Column('permission_id', Integer, ForeignKey('auth_permission.id'), primary_key=True),
    Column('group_id', Integer, ForeignKey('auth_group.id'), primary_key=True)
)


class AuthGroup(Base):
    """AuthGroup model for SQLAlchemy"""
    __tablename__ = 'auth_group'
    
    id = Column(Integer, primary_key=True, index=True)
    creator = Column(String(64), nullable=False, index=True)
    role = Column(String(32), nullable=False, index=True)
    description = Column(String(256))
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    memberships = relationship("AuthMembership", secondary=membership_groups, back_populates="groups")
    permissions = relationship("AuthPermission", secondary=permission_groups, back_populates="groups")
    
    __table_args__ = ({
        'sqlite_autoincrement': True,
    },)


class AuthMembership(Base):
    """AuthMembership model for SQLAlchemy"""
    __tablename__ = 'auth_membership'
    
    id = Column(Integer, primary_key=True, index=True)
    user = Column(String(64), nullable=False, index=True)
    creator = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    groups = relationship("AuthGroup", secondary=membership_groups, back_populates="memberships")
    
    __table_args__ = ({
        'sqlite_autoincrement': True,
    },)


class AuthPermission(Base):
    """AuthPermission model for SQLAlchemy"""
    __tablename__ = 'auth_permission'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), nullable=False, index=True)
    creator = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    groups = relationship("AuthGroup", secondary=permission_groups, back_populates="permissions")
    
    __table_args__ = ({
        'sqlite_autoincrement': True,
    },)


def create_tables():
    """Create all tables"""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Dependency to get database session with proper cleanup"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()