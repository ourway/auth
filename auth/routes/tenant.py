"""Tenant-level routes: client key rotation, settings, and the audit trail."""

import logging
import uuid

from flask import g, jsonify, request

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
from auth.services.base import validate_client_key
from auth.services.recovery import (
    RotateKeyRejected,
    TargetNamespaceNotEmpty,
    recover_namespace,
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

    @app.route("/api/keys/get_rotate_key", methods=["POST"])
    @with_db_session
    @audit_log(AuditAction.GET_ROTATE_KEY, resource_extractor=lambda kwargs: "self")
    def get_rotate_key(db):
        """Issue this namespace's recovery key — once, and never again.

        A client key is self-chosen and nothing about it is stored in plaintext,
        so losing it has always meant losing the namespace outright. This is the
        way back: keep the returned secret somewhere the client key is not, and
        present it to ``POST /api/keys/recover`` if the client key is ever lost.

        It is disclosed exactly once because only its hash is kept — there is
        nothing left to re-read, for anyone. A second call answers 409.

        POST rather than GET: it mints and records a secret, and a GET that can
        only ever succeed once would be cached and retried into a false failure.
        """
        auth_service = _get_auth_service(db)
        secret = auth_service.issue_rotate_key()
        if secret is None:
            return (
                jsonify(
                    {
                        "result": False,
                        "reason": "rotate_key_already_issued",
                        "hint": (
                            "A rotate key was already issued for this namespace and "
                            "only its hash is stored, so it cannot be shown again. "
                            "If it has been lost, rotate the client key with "
                            "POST /api/keys/rotate — that namespace keeps its "
                            "existing rotate key — or recover with the one you hold."
                        ),
                    }
                ),
                409,
            )
        return APIResponse.success(
            data={"rotate_key": secret},
            message=(
                "Rotate key issued. This is the only time it is shown; store it "
                "separately from the client key."
            ),
        )

    @app.route("/api/keys/recover", methods=["POST"])
    @with_db_session
    def recover_key(db):
        """Move a namespace to a new client key using its rotate key.

        Body: ``{"rotate_key": "rrk_...", "new_client_key": "<uuid4>"}`` —
        ``new_client_key`` optional, generated when absent.

        Deliberately outside the ``/api/*`` Bearer gate: the caller has lost the
        credential that gate demands. The rotate key is the authentication.

        Returns the new client key and a NEW rotate key; the presented one dies
        with the rotation, so a recovery cannot be replayed with the credential
        that performed it.
        """
        body = request.get_json(silent=True, force=True)
        if not isinstance(body, dict) or not isinstance(body.get("rotate_key"), str):
            return APIResponse.bad_request('JSON body required: {"rotate_key": "rrk_..."}')

        new_key = body.get("new_client_key") or str(uuid.uuid4())
        if not isinstance(new_key, str) or not validate_client_key(new_key):
            return APIResponse.bad_request("new_client_key must be a valid UUID4")

        try:
            result = recover_namespace(db, body["rotate_key"], new_key)
        except TargetNamespaceNotEmpty:
            return APIResponse.bad_request(
                "new_client_key already identifies a namespace that owns data; "
                "omit it to have one generated, or choose an unused key"
            )
        except RotateKeyRejected:
            # One message for malformed and for unknown alike: distinguishing
            # them would turn this into an oracle for which secrets exist.
            log_audit_event(
                client_id="fpr_unknown",
                user=None,
                action=AuditAction.RECOVER_KEY,
                resource="rejected",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.unauthorized("Invalid rotate key")

        record_audit(
            db,
            client_id=client_fingerprint(result["client_key"]),
            user=None,
            action=AuditAction.RECOVER_KEY,
            resource="recovered",
            details={"migrated": result.get("migrated")},
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            success=True,
        )
        return APIResponse.success(
            data={"client_key": result["client_key"], "rotate_key": result["rotate_key"]},
            message=(
                "Namespace recovered. Both values are shown only once; the "
                "previous rotate key is now invalid."
            ),
        )

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
