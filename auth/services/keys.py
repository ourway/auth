"""Per-user API keys (SPEC 0004): minting, listing, revocation, validation."""

from typing import Any, Dict, List, Optional, cast

from sqlalchemy import func

from auth.api_keys import generate_api_key, hash_api_key
from auth.models.sql import (
    AuthApiKey,
)
from auth.services.base import _utcnow
from auth.services.rbac import RbacMixin

# Active per-user API keys allowed per (tenant, user) — bounds namespace abuse
# while staying far above any legitimate "one key per device/CI job" usage.
API_KEYS_PER_USER_CAP = 25

# A validate only rewrites last_used_at when it is at least this stale, so the
# hot path does at most one row-update per key per window.
_LAST_USED_THROTTLE_SECONDS = 60


class ApiKeyMixin(RbacMixin):
    """The per-user API key lifecycle."""

    def check_api_key_permission(self, api_key: str, permission: str) -> Dict[str, Any]:
        """Validate a secret and answer its subject's permission in one call.

        An invalid key returns the validate result unchanged; a valid key adds
        the effective-permission answer. The subject is key-backed by
        construction (this very key just validated), so strict mode never
        blocks the second half.
        """
        validated = self.validate_api_key(api_key)
        if not validated["valid"]:
            return validated
        user = cast(str, validated["user"])
        return {
            "valid": True,
            "user": user,
            "key_id": validated["key_id"],
            "has_permission": self.user_has_permission(user, permission),
        }

    # --- Per-user API keys (SPEC 0004) -----------------------------------

    @staticmethod
    def _api_key_meta(row: AuthApiKey) -> Dict[str, Any]:
        """Listing/metadata view of a key row — never the hash or secret."""

        def iso(dt: Any) -> Optional[str]:
            return dt.isoformat() if dt else None

        return {
            "key_id": row.key_id,
            "key_prefix": row.key_prefix,
            "label": row.label,
            "is_active": bool(row.is_active),
            "created": iso(row.date_created),
            "revoked_at": iso(row.revoked_at),
            "expires_at": iso(row.expires_at),
            "last_used_at": iso(row.last_used_at),
        }

    def create_api_key(
        self, user: str, label: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Mint and store an API key for ``user`` in this tenant's namespace.

        Returns the one-time secret plus metadata, or ``None`` when the user
        already holds ``API_KEYS_PER_USER_CAP`` active keys. The tenant lock
        serializes against key rotation so the new row cannot strand under a
        creator that is being moved.
        """
        self._lock_tenant()
        active = (
            self.db.query(func.count(AuthApiKey.id))
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey._user == self._get_encrypted_user(user),
                AuthApiKey.is_active,
            )
            .scalar()
            or 0
        )
        if active >= API_KEYS_PER_USER_CAP:
            return None

        secret, key_id, key_hash, key_prefix = generate_api_key()
        row = AuthApiKey(
            key_id=key_id,
            creator=self.client,
            key_hash=key_hash,
            key_prefix=key_prefix,
            is_active=True,
        )
        row.user = user
        if label:
            row.label = label
        self.db.add(row)
        self.db.flush()
        self._commit()
        return {
            "api_key": secret,
            "key_id": key_id,
            "user": user,
            "label": label,
            "key_prefix": key_prefix,
            "created": row.date_created.isoformat() if row.date_created else None,
            "expires_at": None,
        }

    def list_api_keys(self, user: str) -> List[Dict[str, Any]]:
        """All of ``user``'s keys in this namespace, revoked ones included."""
        rows = (
            self.db.query(AuthApiKey)
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey._user == self._get_encrypted_user(user),
            )
            .order_by(AuthApiKey.id)
            .all()
        )
        return [self._api_key_meta(row) for row in rows]

    def revoke_api_key(self, user: str, key_id: str) -> Optional[str]:
        """Revoke ``key_id`` for ``user``.

        Returns ``"revoked"``, ``"already_revoked"`` (idempotent repeat), or
        ``None`` when no such row exists in this namespace — the route maps
        that to 404 without revealing whether the id exists elsewhere.
        """
        self._lock_tenant()
        row = (
            self.db.query(AuthApiKey)
            .filter(
                AuthApiKey.creator == self.client,
                AuthApiKey.key_id == key_id.lower(),
                AuthApiKey._user == self._get_encrypted_user(user),
            )
            .first()
        )
        if row is None:
            return None
        if not row.is_active and row.revoked_at is not None:
            return "already_revoked"
        row.is_active = False  # type: ignore[assignment]
        row.revoked_at = _utcnow()  # type: ignore[assignment]
        self._commit()
        return "revoked"

    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """Resolve a presented secret within THIS tenant's namespace.

        Single unique-index probe on the hash. A key that exists under a
        different tenant answers exactly like one that does not exist, so a
        foreign tenant cannot probe key existence. Touches ``last_used_at``
        at most once per throttle window.
        """
        row = (
            self.db.query(AuthApiKey)
            .filter(AuthApiKey.key_hash == hash_api_key(api_key))
            .first()
        )
        if row is None or row.creator != self.client:
            return {"valid": False, "reason": "unknown_key"}
        if not row.is_active:
            return {"valid": False, "reason": "revoked"}
        now = _utcnow()
        if row.expires_at is not None and row.expires_at <= now:
            return {"valid": False, "reason": "expired"}
        if (
            row.last_used_at is None
            or (now - row.last_used_at).total_seconds() >= _LAST_USED_THROTTLE_SECONDS
        ):
            row.last_used_at = now  # type: ignore[assignment]
            self._commit()
        return {
            "valid": True,
            "user": row.user,
            "key_id": row.key_id,
            "label": row.label,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        }
