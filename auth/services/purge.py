from typing import Any, Dict, cast

from sqlalchemy import Table, delete, func, or_, select
from sqlalchemy.engine import CursorResult

from auth.models.sql import (
    AuthApiKey,
    AuthGroup,
    AuthMembership,
    AuthPermission,
    AuthTenantSettings,
    membership_groups,
    permission_groups,
)
from auth.rls import tenant_fingerprint
from auth.services.rotation import RotationMixin

FINGERPRINT_LENGTH = 12

_groups = cast(Table, AuthGroup.__table__)
_memberships = cast(Table, AuthMembership.__table__)
_permissions = cast(Table, AuthPermission.__table__)
_api_keys = cast(Table, AuthApiKey.__table__)
_settings = cast(Table, AuthTenantSettings.__table__)


def namespace_fingerprint(client_key: str) -> str:
    return tenant_fingerprint(client_key.lower())[:FINGERPRINT_LENGTH]


class PurgeMixin(RotationMixin):
    def _delete(self, statement) -> int:
        return int(cast(CursorResult, self.db.execute(statement)).rowcount or 0)

    def _count(self, table: Table) -> int:
        return int(
            self.db.execute(
                select(func.count()).select_from(table).where(table.c.creator == self.client)
            ).scalar()
            or 0
        )

    def namespace_summary(self) -> Dict[str, Any]:
        settings_row = self.db.execute(
            select(_settings.c.rotate_key_hash).where(_settings.c.creator == self.client)
        ).first()
        return {
            "fingerprint": namespace_fingerprint(self.client),
            "roles": self._count(_groups),
            "permissions": self._count(_permissions),
            "memberships": self._count(_memberships),
            "api_keys": self._count(_api_keys),
            "settings": settings_row is not None,
            "recovery_key": bool(settings_row and settings_row[0]),
        }

    def purge_namespace(self) -> Dict[str, Any]:
        self._lock_tenant()
        group_ids = select(_groups.c.id).where(_groups.c.creator == self.client)
        member_ids = select(_memberships.c.id).where(_memberships.c.creator == self.client)
        permission_ids = select(_permissions.c.id).where(_permissions.c.creator == self.client)
        summary = self.namespace_summary()
        role_links = self._delete(
            delete(membership_groups).where(
                or_(
                    membership_groups.c.membership_id.in_(member_ids),
                    membership_groups.c.group_id.in_(group_ids),
                )
            )
        )
        permission_links = self._delete(
            delete(permission_groups).where(
                or_(
                    permission_groups.c.permission_id.in_(permission_ids),
                    permission_groups.c.group_id.in_(group_ids),
                )
            )
        )
        deleted: Dict[str, Any] = {"fingerprint": summary["fingerprint"]}
        for name, table in (
            ("memberships", _memberships),
            ("permissions", _permissions),
            ("roles", _groups),
            ("api_keys", _api_keys),
        ):
            deleted[name] = self._delete(delete(table).where(table.c.creator == self.client))
        deleted["settings"] = bool(
            self._delete(delete(_settings).where(_settings.c.creator == self.client))
        )
        deleted["recovery_key"] = summary["recovery_key"]
        deleted["role_links"] = role_links + permission_links
        self._strict_cache = None
        self._commit()
        return deleted
