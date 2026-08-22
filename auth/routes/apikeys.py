"""Per-user API key routes (SPEC 0004)."""

import logging

from flask import request

from auth.api_keys import API_KEY_PATTERN
from auth.audit import (
    AuditAction,
    client_fingerprint,
)
from auth.decorators import audit_log
from auth.response_format import (
    APIResponse,
)
from auth.routes._common import (
    _get_auth_service,
    with_db_session,
)
from auth.services.service import API_KEYS_PER_USER_CAP
from auth.validation import (
    validate_api_key_label,
    validate_key_id,
    validate_permission_name,
    validate_user_name,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the apikeys routes on ``app``."""

    # Per-user API keys (SPEC 0004). User routes nest under the static /user/
    # segment so a user literally named "validate" can never collide with the
    # validate route. Secrets travel only in JSON bodies — request lines are
    # logged by gunicorn/nginx, so they must never appear in a URL.
    @app.route("/api/apikeys/user/<user>", methods=["POST"])
    @with_db_session
    @audit_log(
        AuditAction.CREATE_API_KEY,
        resource_extractor=lambda kwargs: client_fingerprint(kwargs["user"]),
    )
    def create_user_api_key(db, user):
        """Mint an API key for a user in the caller's namespace.

        Optional JSON body ``{"label": "..."}``. The response's ``api_key`` is
        shown exactly once and cannot be retrieved again.
        """
        if not validate_user_name(user):
            return APIResponse.bad_request(f"Invalid user name: {user}")

        label = None
        if request.get_data(cache=True):
            body = request.get_json(silent=True, force=True)
            if not isinstance(body, dict):
                return APIResponse.bad_request(
                    "Request body, when present, must be a JSON object."
                )
            label = body.get("label")
            if label is not None and (
                not isinstance(label, str) or not validate_api_key_label(label)
            ):
                return APIResponse.bad_request(
                    "Invalid label: 1-64 characters of letters, digits, "
                    "space, underscore, dot, or hyphen."
                )

        auth_service = _get_auth_service(db)
        result = auth_service.create_api_key(user, label)
        if result is None:
            return APIResponse.bad_request(
                f"Active API-key limit reached for user '{user}' "
                f"({API_KEYS_PER_USER_CAP}). Revoke an existing key first."
            )
        return APIResponse.success(
            data=result,
            message=(
                f"API key created for user '{user}'. "
                "The api_key value is shown only once — store it now."
            ),
        )

    @app.route("/api/apikeys/user/<user>", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.LIST_API_KEYS,
        resource_extractor=lambda kwargs: client_fingerprint(kwargs["user"]),
    )
    def list_user_api_keys(db, user):
        """List a user's API keys (metadata only — never hashes or secrets).

        Revoked keys are included with ``is_active: false`` so a UI can show
        history; an unknown user simply yields ``count: 0``.
        """
        if not validate_user_name(user):
            return APIResponse.bad_request(f"Invalid user name: {user}")

        auth_service = _get_auth_service(db)
        keys = auth_service.list_api_keys(user)
        return APIResponse.success(
            data={"count": len(keys), "keys": keys},
            message=f"API keys for user '{user}'",
        )

    @app.route("/api/apikeys/user/<user>/<key_id>", methods=["DELETE"])
    @with_db_session
    @audit_log(
        AuditAction.REVOKE_API_KEY,
        resource_extractor=lambda kwargs: (
            f"{client_fingerprint(kwargs['user'])}:{kwargs['key_id']}"
        ),
    )
    def revoke_user_api_key(db, user, key_id):
        """Revoke one API key by its public key_id (idempotent).

        404 covers unknown ids, ids under a different user, and ids owned by a
        different tenant — indistinguishable by design.
        """
        if not validate_user_name(user):
            return APIResponse.bad_request(f"Invalid user name: {user}")
        if not validate_key_id(key_id):
            return APIResponse.bad_request(
                f"Invalid key id: {key_id}. Must be a UUID4."
            )

        auth_service = _get_auth_service(db)
        outcome = auth_service.revoke_api_key(user, key_id)
        if outcome is None:
            return APIResponse.not_found("API key", key_id)
        return APIResponse.success(
            data={
                "revoked": True,
                "already_revoked": outcome == "already_revoked",
            },
            message=f"API key {key_id} revoked for user '{user}'",
        )

    @app.route("/api/apikeys/validate", methods=["POST"])
    @with_db_session
    @audit_log(
        AuditAction.VALIDATE_API_KEY,
        resource_extractor=lambda kwargs: "api_key",
    )
    def validate_user_api_key(db):
        """Validate a presented API-key secret within the caller's namespace.

        Body: ``{"api_key": "rak_..."}``. Resolvable questions get 200 with
        ``valid`` true/false (reason: revoked | expired | unknown_key); only a
        missing/malformed body or a string that cannot be a key is a 400. A
        key belonging to another tenant answers ``unknown_key``.
        """
        body = request.get_json(silent=True, force=True)
        if not isinstance(body, dict):
            return APIResponse.bad_request('JSON body required: {"api_key": "rak_..."}')
        api_key = body.get("api_key")
        if not isinstance(api_key, str) or not API_KEY_PATTERN.match(api_key):
            return APIResponse.bad_request(
                "api_key must be a string matching rak_[0-9A-Za-z]{43}"
            )

        auth_service = _get_auth_service(db)
        result = auth_service.validate_api_key(api_key)
        return APIResponse.success(data=result, message="API key validation completed")

    @app.route("/api/apikeys/check_permission", methods=["POST"])
    @with_db_session
    @audit_log(
        AuditAction.CHECK_API_KEY_PERMISSION,
        resource_extractor=lambda kwargs: "api_key",
    )
    def check_api_key_permission(db):
        """Validate a secret AND answer its subject's permission in one call.

        Body: ``{"api_key": "rak_...", "permission": "<name>"}``. An invalid
        key answers like validate (``valid: false`` + reason, no permission
        evaluation); a valid key adds ``has_permission`` for the key's user.
        The recommended backend pattern under strict user identity.
        """
        body = request.get_json(silent=True, force=True)
        if not isinstance(body, dict):
            return APIResponse.bad_request(
                'JSON body required: {"api_key": "rak_...", "permission": "<name>"}'
            )
        api_key = body.get("api_key")
        permission = body.get("permission")
        if not isinstance(api_key, str) or not API_KEY_PATTERN.match(api_key):
            return APIResponse.bad_request(
                "api_key must be a string matching rak_[0-9A-Za-z]{43}"
            )
        if not isinstance(permission, str) or not validate_permission_name(permission):
            return APIResponse.bad_request(f"Invalid permission name: {permission!r}")

        auth_service = _get_auth_service(db)
        result = auth_service.check_api_key_permission(api_key, permission)
        return APIResponse.success(
            data=result, message="API-key permission check completed"
        )
