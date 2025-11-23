
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
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func

from auth.encryption import decrypt_sensitive_data, encrypt_sensitive_data


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models"""
    pass



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
    _description = Column("description", String(256))  # Encrypted description field
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

    @property
    def description(self) -> Optional[str]:
        """Decrypt description when accessed"""
        if self._description:
            decrypted = decrypt_sensitive_data(str(self._description))
            return decrypted
        return None

    @description.setter
    def description(self, value: Optional[str]) -> None:
        """Encrypt description when set"""
        if value:
            encrypted = encrypt_sensitive_data(value)
            self._description = encrypted  # type: ignore[assignment]
        else:
            self._description = value  # type: ignore[assignment]


class AuthMembership(Base):
    """AuthMembership model for SQLAlchemy"""

    __tablename__ = "auth_membership"

    id = Column(Integer, primary_key=True, index=True)
    _user = Column(
        "user", String(64), nullable=False, index=True
    )  # Potentially encrypted user field
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

    @property
    def user(self) -> Optional[str]:
        """Decrypt user when accessed"""
        if self._user:
            decrypted = decrypt_sensitive_data(str(self._user))
            return decrypted
        return None

    @user.setter
    def user(self, value: Optional[str]) -> None:
        """Encrypt user when set"""
        if value:
            encrypted = encrypt_sensitive_data(value)
            self._user = encrypted  # type: ignore[assignment]
        else:
            self._user = value  # type: ignore[assignment]


class AuthPermission(Base):
    """AuthPermission model for SQLAlchemy"""

    __tablename__ = "auth_permission"

    id = Column(Integer, primary_key=True, index=True)
    _name = Column(
        "name", String(64), nullable=False, index=True
    )  # Potentially encrypted name field
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

    @property
    def name(self) -> Optional[str]:
        """Decrypt name when accessed"""
        if self._name:
            decrypted = decrypt_sensitive_data(str(self._name))
            return decrypted
        return None

    @name.setter
    def name(self, value: Optional[str]) -> None:
        """Encrypt name when set"""
        if value:
            encrypted = encrypt_sensitive_data(value)
            self._name = encrypted  # type: ignore[assignment]
        else:
            self._name = value  # type: ignore[assignment]
