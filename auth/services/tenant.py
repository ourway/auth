"""Tenant settings, strict user identity, and the tenant audit trail."""

import json
from typing import Any, Dict, List, Optional, Tuple, cast

from auth.audit import AuditLog, client_fingerprint
from auth.models.sql import (
    AuthApiKey,
    AuthTenantSettings,
)
from auth.services.base import ServiceBase, _utcnow


class TenantMixin(ServiceBase):
    """Per-tenant settings, strict-identity checks and audit reads."""

    # --- Tenant settings & strict user identity (SPEC 0008/0010) ---------

    def strict_users_enabled(self) -> bool:
        """Whether strict user identity applies to this tenant.

        Explicit constructor override wins; otherwise the tenant's stored
        setting is read once per service instance (one PK-adjacent lookup,
        cached for the request).
        """
        if self._strict_override is not None:
            return self._strict_override
        if self._strict_cache is None:
            row = (
                self.db.query(AuthTenantSettings)
                .filter(AuthTenantSettings.creator == self.client)
                .first()
            )
            if row is not None:
                self._strict_cache = bool(row.strict_users)
            else:
                # 3.0.0: tenants with no stored setting follow the server
                # default (strict). Pre-3.0 tenants never reach this branch —
                # grandfathering wrote them explicit false rows.
                from auth.config import get_settings

                self._strict_cache = bool(get_settings().strict_users_default)
        return self._strict_cache

    def get_settings(self) -> Dict[str, Any]:
        """This tenant's settings (defaults when no row exists)."""
        return {"strict_users": self.strict_users_enabled()}

    def set_strict_users(self, enabled: bool) -> Dict[str, Any]:
        """Upsert this tenant's strict_users flag (serialized vs rotation)."""
        self._lock_tenant()
        row = (
            self.db.query(AuthTenantSettings)
            .filter(AuthTenantSettings.creator == self.client)
            .first()
        )
        if row is None:
            row = AuthTenantSettings(creator=self.client, strict_users=enabled)
            self.db.add(row)
        else:
            row.strict_users = enabled  # type: ignore[assignment]
        self._strict_cache = enabled
        self._commit()
        return {"strict_users": enabled}

    def get_audit(
        self, limit: int = 50, offset: int = 0, action: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Return THIS tenant's own audit trail, newest first.

        Scoped by ``client_fingerprint(self.client)`` so a caller can never read
        another namespace's entries. ``action`` is matched on the stored action
        string (case-insensitive). ``details`` is decoded from its stored JSON.
        Client and user fields are already non-reversible fingerprints — the
        endpoint must never surface a raw key, user, or the audit pepper.
        """
        query = self.db.query(AuditLog).filter(
            AuditLog.client_id == client_fingerprint(self.client)
        )
        if action:
            query = query.filter(AuditLog.action == action.upper())
        total = query.count()
        rows = query.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()
        entries = [
            {
                "id": row.id,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "action": row.action,
                "resource": row.resource,
                "details": json.loads(cast(str, row.details)) if row.details else None,
                "success": bool(row.success),
                "user": row.user,
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
            }
            for row in rows
        ]
        return entries, total

    def user_is_key_backed(self, user: str) -> bool:
        """True when the user holds ≥1 active, unexpired API key here."""
        row = (
            self.db.query(AuthApiKey.id)
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey._user == self._get_encrypted_user(user),
                AuthApiKey.is_active,
            )
            .filter(
                (AuthApiKey.expires_at.is_(None)) | (AuthApiKey.expires_at > _utcnow())
            )
            .first()
        )
        return row is not None

    def _strict_blocks(self, user: str) -> bool:
        """Strict mode on AND the user has no live key → decision is negative."""
        return self.strict_users_enabled() and not self.user_is_key_backed(user)
