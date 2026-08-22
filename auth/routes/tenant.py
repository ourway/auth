"""Tenant-level routes: client key rotation, settings, and the audit trail."""

import logging
import uuid

from flask import g, request

from auth.audit import (
    AuditAction,
    client_fingerprint,
    log_audit_event,
    record_audit,
)
from auth.config import get_settings
from auth.decorators import audit_log
from auth.response_format import (
    APIResponse,
)
from auth.routes._common import (
    _get_auth_service,
    with_db_session,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the tenant routes on ``app``."""

    # API-key management
    @app.route("/api/keys/rotate", methods=["POST"])
    @with_db_session
    def rotate_key(db):
        """Rotate the caller's client key (atomic cutover).

        Authenticated by the *current* key (the before-request gate already put
        it on ``g.client_key``). The server mints a fresh UUID4, atomically moves
        the caller's whole namespace onto it (re-encrypting bound fields when
        encryption is on), and returns the new key. The old key immediately owns
        nothing. The returned key is the only copy — the caller must persist it.

        Audited explicitly (not via the ``@audit_log`` decorator) so the record
        can link the old key's fingerprint to the *new* key's fingerprint, which
        the decorator — seeing only ``g.client_key`` — cannot capture. Neither
        raw key is ever written to the audit trail.
        """
        old_key = g.client_key
        new_key = str(uuid.uuid4())
        audit_on = get_settings().enable_audit_logging

        auth_service = _get_auth_service(db)
        try:
            result = auth_service.rotate_client_key(new_key)
        except Exception as e:
            # rotate_client_key rolled its work back; record the failed attempt
            # on a separate session so it is not lost with the request rollback.
            if audit_on:
                log_audit_event(
                    client_id=client_fingerprint(old_key),
                    user=None,
                    action=AuditAction.ROTATE_KEY,
                    resource=client_fingerprint(new_key),
                    details={"error": str(e)},
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                    success=False,
                )
            raise

        if audit_on:
            # Same session as the rotation (manage_transaction=False), so the
            # ROTATE_KEY row commits atomically with the key move.
            record_audit(
                db,
                client_id=client_fingerprint(old_key),
                user=None,
                action=AuditAction.ROTATE_KEY,
                resource=client_fingerprint(new_key),
                details={"migrated": result["migrated"]},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

        return APIResponse.success(data=result, message="Client key rotated")

    # Tenant settings (SPEC 0010)
    @app.route("/api/settings", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.GET_SETTINGS, resource_extractor=lambda kwargs: "settings")
    def get_tenant_settings(db):
        """This tenant's settings; defaults when nothing was ever set."""
        auth_service = _get_auth_service(db)
        return APIResponse.success(
            data=auth_service.get_settings(), message="Tenant settings"
        )

    @app.route("/api/settings", methods=["PUT"])
    @with_db_session
    @audit_log(
        AuditAction.UPDATE_SETTINGS,
        resource_extractor=lambda kwargs: "strict_users",
    )
    def update_tenant_settings(db):
        """Update tenant settings. Body: ``{"strict_users": true|false}``.

        Enabling strict_users makes authorization decisions answer negatively
        for users with no live API key (SPEC 0008); disabling restores 2.4.x
        behavior. Idempotent upsert, audited.
        """
        body = request.get_json(silent=True, force=True)
        if not isinstance(body, dict) or not isinstance(body.get("strict_users"), bool):
            return APIResponse.bad_request(
                'JSON body required: {"strict_users": true|false}'
            )

        auth_service = _get_auth_service(db)
        result = auth_service.set_strict_users(body["strict_users"])
        return APIResponse.success(data=result, message="Tenant settings updated")

    @app.route("/api/audit", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.GET_AUDIT, resource_extractor=lambda kwargs: "all")
    def get_audit(db):
        """Return THIS namespace's own audit trail, newest first.

        Read-only, self-service diagnosis: who granted/revoked what, when, and
        whether it took effect. Strictly scoped to the calling namespace's
        fingerprint — never another tenant's entries, and never a raw key or
        user (client/user fields are already non-reversible fingerprints).
        """
        try:
            limit = int(request.args.get("limit", 50))
            offset = int(request.args.get("offset", 0))
        except ValueError:
            return APIResponse.bad_request("limit and offset must be integers")
        if limit < 1 or limit > 500:
            return APIResponse.bad_request("limit must be between 1 and 500")
        if offset < 0:
            return APIResponse.bad_request("offset must be >= 0")

        auth_service = _get_auth_service(db)
        entries, total = auth_service.get_audit(
            limit=limit,
            offset=offset,
            action=request.args.get("action"),
        )
        return APIResponse.success(
            data={
                "total": total,
                "limit": limit,
                "offset": offset,
                "entries": entries,
            },
            message="Audit trail retrieved",
        )
