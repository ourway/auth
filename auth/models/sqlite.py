#!/usr/bin/env python

"""
SQLite3-based database models for authorization system
"""

__all__ = ["make_db_connection", "AuthMembership", "AuthGroup", "AuthPermission"]

import os
import sqlite3
from typing import Any, Dict, List, Optional

from auth.config import get_settings


def make_db_connection():
    """Create SQLite3 database connection and initialize tables"""
    settings = get_settings()
    db_path = os.path.expanduser(settings.sqlite_path)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _create_tables(conn)
    return conn


def _create_tables(conn):
    """Create all necessary tables in the database"""
    cursor = conn.cursor()

    # AuthGroup table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_group (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creator TEXT NOT NULL,
            role TEXT NOT NULL,
            description TEXT,
            is_active BOOLEAN DEFAULT 1,
            date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(creator, role)
        )
    """
    )

    # AuthMembership table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_membership (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            creator TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(creator, user)
        )
    """
    )

    # AuthPermission table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_permission (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(creator, name)
        )
    """
    )

    # Junction table for membership groups
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS membership_groups (
            membership_id INTEGER,
            group_id INTEGER,
            FOREIGN KEY(membership_id) REFERENCES auth_membership(id),
            FOREIGN KEY(group_id) REFERENCES auth_group(id),
            UNIQUE(membership_id, group_id)
        )
    """
    )

    # Junction table for permission groups
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS permission_groups (
            permission_id INTEGER,
            group_id INTEGER,
            FOREIGN KEY(permission_id) REFERENCES auth_permission(id),
            FOREIGN KEY(group_id) REFERENCES auth_group(id),
            UNIQUE(permission_id, group_id)
        )
    """
    )

    conn.commit()


def make_test_db_connection():
    """Create an in-memory SQLite3 database connection with tables for testing"""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _create_tables(conn)
    return conn


class BaseModel:
    """Base model class for common database operations"""

    def __init__(self, conn):
        self.conn = conn

    def _execute(self, query: str, params: tuple = ()):
        """Execute SQL query and return cursor"""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor

    def _fetch_one(self, query: str, params: tuple = ()):
        """Fetch single row"""
        cursor = self._execute(query, params)
        row = cursor.fetchone()
        if row is None:
            return None
        # Convert Row object to dictionary if possible
        if hasattr(row, "keys"):
            return dict(row)
        else:
            # For compatibility when row_factory is not set (e.g., in tests)
            # Get column names from cursor description
            columns = [description[0] for description in cursor.description]
            return dict(zip(columns, row))

    def _fetch_all(self, query: str, params: tuple = ()):
        """Fetch all rows"""
        cursor = self._execute(query, params)
        rows = cursor.fetchall()
        # Convert Row objects to dictionaries if possible
        if not rows:
            return []

        # Check if the first row has keys method (i.e., is a Row object)
        if len(rows) > 0 and hasattr(rows[0], "keys"):
            return [dict(row) for row in rows]
        else:
            # For compatibility when row_factory is not set (e.g., in tests)
            # Get column names from cursor description
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def _update_modified(self, table: str, record_id: int):
        """Update modified timestamp"""
        self._execute(
            f"UPDATE {table} SET modified = CURRENT_TIMESTAMP WHERE id = ?",
            (record_id,),
        )
        self.conn.commit()


class AuthGroup(BaseModel):
    """AuthGroup model for SQLite3"""

    def __init__(self, conn):
        super().__init__(conn)

    def create(
        self, creator: str, role: str, description: Optional[str] = None
    ) -> bool:
        """Create a new group"""
        try:
            self._execute(
                "INSERT INTO auth_group (creator, role, description) VALUES (?, ?, ?)",
                (creator, role, description),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Role already exists
            return False

    def get_by_role(self, creator: str, role: str) -> Optional[Dict[str, Any]]:
        """Get group by role and creator"""
        row = self._fetch_one(
            "SELECT * FROM auth_group WHERE creator = ? AND role = ? AND is_active = 1",
            (creator, role),
        )
        return dict(row) if row else None

    def get_all_by_creator(self, creator: str) -> List[Dict[str, Any]]:
        """Get all groups for a creator"""
        rows = self._fetch_all(
            "SELECT * FROM auth_group WHERE creator = ? AND is_active = 1", (creator,)
        )
        return [dict(row) for row in rows]

    def delete(self, creator: str, role: str) -> bool:
        """Delete a group"""
        cursor = self._execute(
            "UPDATE auth_group SET is_active = 0 WHERE creator = ? AND role = ?",
            (creator, role),
        )
        self.conn.commit()
        rowcount: int = cursor.rowcount
        return rowcount > 0

    def __repr__(self):
        return "AuthGroup: <SQLite3 Model>"


class AuthMembership(BaseModel):
    """AuthMembership model for SQLite3"""

    def __init__(self, conn):
        super().__init__(conn)

    def create_or_get(self, creator: str, user: str) -> int:
        """Create or get membership ID"""
        # Try to get existing membership
        row = self._fetch_one(
            "SELECT id FROM auth_membership WHERE creator = ? AND user = ?",
            (creator, user),
        )

        if row:
            return int(row["id"])

        # Create new membership
        cursor = self._execute(
            "INSERT INTO auth_membership (creator, user) VALUES (?, ?)", (creator, user)
        )
        self.conn.commit()
        lastrowid: int = cursor.lastrowid
        return lastrowid

    def add_group(self, membership_id: int, group_id: int) -> bool:
        """Add group to membership"""
        try:
            self._execute(
                "INSERT INTO membership_groups (membership_id, group_id) VALUES (?, ?)",
                (membership_id, group_id),
            )
            self.conn.commit()
            self._update_modified("auth_membership", membership_id)
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_group(self, membership_id: int, group_id: int) -> bool:
        """Remove group from membership"""
        cursor = self._execute(
            "DELETE FROM membership_groups WHERE membership_id = ? AND group_id = ?",
            (membership_id, group_id),
        )
        self.conn.commit()
        rowcount: int = cursor.rowcount
        if rowcount > 0:
            self._update_modified("auth_membership", membership_id)
        return rowcount > 0

    def get_groups(self, creator: str, user: str) -> List[Dict[str, Any]]:
        """Get all groups for a user"""
        rows = self._fetch_all(
            """
            SELECT ag.* FROM auth_group ag
            JOIN membership_groups mg ON ag.id = mg.group_id
            JOIN auth_membership am ON am.id = mg.membership_id
            WHERE am.creator = ? AND am.user = ? AND am.is_active = 1 AND ag.is_active = 1
        """,
            (creator, user),
        )
        return [dict(row) for row in rows]

    def get_by_user(self, creator: str, user: str) -> Optional[Dict[str, Any]]:
        """Get membership by user and creator"""
        row = self._fetch_one(
            "SELECT * FROM auth_membership WHERE creator = ? AND user = ? AND is_active = 1",
            (creator, user),
        )
        return dict(row) if row else None

    def delete(self, creator: str, user: str) -> bool:
        """Delete membership"""
        cursor = self._execute(
            "UPDATE auth_membership SET is_active = 0 WHERE creator = ? AND user = ?",
            (creator, user),
        )
        self.conn.commit()
        rowcount: int = cursor.rowcount
        return rowcount > 0

    def __repr__(self):
        return "AuthMembership: <SQLite3 Model>"


class AuthPermission(BaseModel):
    """AuthPermission model for SQLite3"""

    def __init__(self, conn):
        super().__init__(conn)

    def create_or_get(self, creator: str, name: str) -> int:
        """Create or get permission ID"""
        # Try to get existing permission
        row = self._fetch_one(
            "SELECT id FROM auth_permission WHERE creator = ? AND name = ?",
            (creator, name),
        )

        if row:
            return int(row["id"])

        # Create new permission
        cursor = self._execute(
            "INSERT INTO auth_permission (creator, name) VALUES (?, ?)", (creator, name)
        )
        self.conn.commit()
        lastrowid: int = cursor.lastrowid
        return lastrowid

    def add_group(self, permission_id: int, group_id: int) -> bool:
        """Add group to permission"""
        try:
            self._execute(
                "INSERT INTO permission_groups (permission_id, group_id) VALUES (?, ?)",
                (permission_id, group_id),
            )
            self.conn.commit()
            self._update_modified("auth_permission", permission_id)
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_group(self, permission_id: int, group_id: int) -> bool:
        """Remove group from permission"""
        cursor = self._execute(
            "DELETE FROM permission_groups WHERE permission_id = ? AND group_id = ?",
            (permission_id, group_id),
        )
        self.conn.commit()
        rowcount: int = cursor.rowcount
        if rowcount > 0:
            self._update_modified("auth_permission", permission_id)
        return rowcount > 0

    def get_by_name(self, creator: str, name: str) -> Optional[Dict[str, Any]]:
        """Get permission by name and creator"""
        row = self._fetch_one(
            "SELECT * FROM auth_permission WHERE creator = ? AND name = ? AND is_active = 1",
            (creator, name),
        )
        return dict(row) if row else None

    def get_groups(self, creator: str, name: str) -> List[Dict[str, Any]]:
        """Get all groups for a permission"""
        rows = self._fetch_all(
            """
            SELECT ag.* FROM auth_group ag
            JOIN permission_groups pg ON ag.id = pg.group_id
            JOIN auth_permission ap ON ap.id = pg.permission_id
            WHERE ap.creator = ? AND ap.name = ? AND ap.is_active = 1 AND ag.is_active = 1
        """,
            (creator, name),
        )
        return [dict(row) for row in rows]

    def get_all_by_group(self, creator: str, group_id: int) -> List[Dict[str, Any]]:
        """Get all permissions for a group"""
        rows = self._fetch_all(
            """
            SELECT ap.* FROM auth_permission ap
            JOIN permission_groups pg ON ap.id = pg.permission_id
            WHERE ap.creator = ? AND pg.group_id = ? AND ap.is_active = 1
        """,
            (creator, group_id),
        )
        return [dict(row) for row in rows]

    def delete(self, creator: str, name: str) -> bool:
        """Delete permission"""
        cursor = self._execute(
            "UPDATE auth_permission SET is_active = 0 WHERE creator = ? AND name = ?",
            (creator, name),
        )
        self.conn.commit()
        rowcount: int = cursor.rowcount
        return rowcount > 0

    def __repr__(self):
        return "AuthPermission: <SQLite3 Model>"
