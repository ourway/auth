
"""
SQLAlchemy database models
"""
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func

from auth.encryption import decrypt_sensitive_data, encrypt_sensitive_data


# Get schema configuration
def _get_schema():
    """Get configured schema name (e.g., 'auth_rbac' for Highway)"""
    try:
        from auth.config import get_settings
        settings = get_settings()
        return settings.database_schema or None
    except Exception:
        return None


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models"""
    pass



# Get schema for table definitions
_SCHEMA = _get_schema()

membership_groups = Table(
    "membership_groups",
    Base.metadata,
    Column(
        "membership_id", Integer, ForeignKey(f"{_SCHEMA + '.' if _SCHEMA else ''}auth_membership.id"), primary_key=True
    ),
    Column("group_id", Integer, ForeignKey(f"{_SCHEMA + '.' if _SCHEMA else ''}auth_group.id"), primary_key=True),
    schema=_SCHEMA,
)

permission_groups = Table(
    "permission_groups",
    Base.metadata,
    Column(
        "permission_id", Integer, ForeignKey(f"{_SCHEMA + '.' if _SCHEMA else ''}auth_permission.id"), primary_key=True
    ),
    Column("group_id", Integer, ForeignKey(f"{_SCHEMA + '.' if _SCHEMA else ''}auth_group.id"), primary_key=True),
    schema=_SCHEMA,
)


class AuthGroup(Base):
    """AuthGroup model for SQLAlchemy"""

    __tablename__ = "auth_group"
    __table_args__ = (
        UniqueConstraint("creator", "role", name="uq_auth_group_creator_role"),
        {
            "sqlite_autoincrement": True,
            "schema": _SCHEMA,
        },
    )

    id = Column(Integer, primary_key=True, index=True)
    creator = Column(String(64), nullable=False, index=True)
    # Unbounded TEXT: encrypted values expand ~4/3 + IV and could otherwise
    # overflow a varchar. Fresh installs get TEXT directly; existing deployments
    # converge via migration 0001 (see migrations/versions/).
    role = Column(Text, nullable=False, index=True)
    _description = Column("description", Text)  # Encrypted description field
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

    @property
    def description(self) -> Optional[str]:
        """Decrypt description when accessed"""
        if self._description:
            return decrypt_sensitive_data(str(self._description), str(self.creator))
        return None

    @description.setter
    def description(self, value: Optional[str]) -> None:
        """Encrypt description when set"""
        if value:
            self._description = encrypt_sensitive_data(  # type: ignore[assignment]
                value, str(self.creator)
            )
        else:
            self._description = value  # type: ignore[assignment]


class AuthMembership(Base):
    """AuthMembership model for SQLAlchemy"""

    __tablename__ = "auth_membership"
    __table_args__ = (
        UniqueConstraint("creator", "user", name="uq_auth_membership_creator_user"),
        {
            "sqlite_autoincrement": True,
            "schema": _SCHEMA,
        },
    )

    id = Column(Integer, primary_key=True, index=True)
    _user = Column(
        "user", Text, nullable=False, index=True
    )  # Potentially encrypted user field (TEXT: see AuthGroup.role)
    creator = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    groups = relationship(
        "AuthGroup", secondary=membership_groups, back_populates="memberships"
    )

    @property
    def user(self) -> Optional[str]:
        """Decrypt user when accessed"""
        if self._user:
            return decrypt_sensitive_data(str(self._user), str(self.creator))
        return None

    @user.setter
    def user(self, value: Optional[str]) -> None:
        """Encrypt user when set"""
        if value:
            self._user = encrypt_sensitive_data(  # type: ignore[assignment]
                value, str(self.creator)
            )
        else:
            self._user = value  # type: ignore[assignment]


class AuthPermission(Base):
    """AuthPermission model for SQLAlchemy"""

    __tablename__ = "auth_permission"
    __table_args__ = (
        UniqueConstraint("creator", "name", name="uq_auth_permission_creator_name"),
        {
            "sqlite_autoincrement": True,
            "schema": _SCHEMA,
        },
    )

    id = Column(Integer, primary_key=True, index=True)
    _name = Column(
        "name", Text, nullable=False, index=True
    )  # Potentially encrypted name field (TEXT: see AuthGroup.role)
    creator = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    date_created = Column(DateTime, default=func.now())
    modified = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    groups = relationship(
        "AuthGroup", secondary=permission_groups, back_populates="permissions"
    )

    @property
    def name(self) -> Optional[str]:
        """Decrypt name when accessed"""
        if self._name:
            return decrypt_sensitive_data(str(self._name), str(self.creator))
        return None

    @name.setter
    def name(self, value: Optional[str]) -> None:
        """Encrypt name when set"""
        if value:
            self._name = encrypt_sensitive_data(  # type: ignore[assignment]
                value, str(self.creator)
            )
        else:
            self._name = value  # type: ignore[assignment]
