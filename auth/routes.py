"""
Flask routes for authorization service
"""

import logging
import uuid
from functools import wraps

from flask import abort, g, jsonify, request
from sqlalchemy import text

from auth.api_keys import API_KEY_PATTERN
from auth.audit import (
    AuditAction,
    client_fingerprint,
    log_audit_event,
    record_audit,
)
from auth.config import get_settings
from auth.database import engine, get_db
from auth.decorators import audit_log
from auth.response_format import (
    APIResponse,
    format_permission_response,
    format_role_members_response,
    format_user_permissions_response,
)
from auth.sanitizer import sanitize_input
from auth.services.service import API_KEYS_PER_USER_CAP, AuthorizationService
from auth.validation import (
    validate_api_key_label,
    validate_client_key,
    validate_key_id,
    validate_permission_name,
    validate_role_name,
    validate_user_name,
    validate_user_role_combination,
)

logger = logging.getLogger(__name__)


def with_db_session(route_func):
    """Provide a request-scoped DB session and own its single transaction.

    The route (and the ``@audit_log`` decorator it wraps) do their work on this
    session WITHOUT committing; this wrapper commits once at the end, so a
    mutation and its audit row land in the same transaction — either both commit
    or both roll back. Any exception rolls the whole thing back.
    """

    @wraps(route_func)  # Preserve function metadata to avoid Flask endpoint conflicts
    def wrapper(*args, **kwargs):
        with get_db() as db:
            try:
                result = route_func(db, *args, **kwargs)
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    return wrapper


def _get_auth_service(db):
    """Return a tenant-scoped auth service for the current request.

    Authentication (Bearer header parsing + UUID4 validation) is performed once,
    up front, by the ``_authenticate_api`` ``before_request`` hook registered in
    ``register_routes``, which stores the validated client key on ``g``. This
    helper only binds that key to the request's database session.
    """
    client_key = getattr(g, "client_key", None)
    if not client_key:
        # Reached only if a route outside the /api/* gate calls this helper.
        abort(401, description="Authorization required.")
    # manage_transaction=False: the mutation is committed once by
    # ``with_db_session``, together with the audit row (see that wrapper).
    return AuthorizationService(
        db, client_key, validate_client=True, manage_transaction=False
    )


def register_routes(app):
    """Register all routes with the Flask app"""

    @app.before_request
    def _authenticate_api():
        """Authenticate every /api/* request before any audit or DB work.

        Runs ahead of each route's ``@with_db_session``/``@audit_log`` chain so
        that unauthenticated or malformed requests are rejected without opening a
        database session or writing an audit row. Public routes (/ping, /health,
        the docs pages) and CORS preflight are exempt.
        """
        if request.method == "OPTIONS":
            return None
        if not request.path.startswith("/api/"):
            return None

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            abort(401, description="Authorization header is missing.")

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            abort(
                401,
                description="Invalid Authorization header format. Must be 'Bearer <token>'.",
            )

        client_key = parts[1]
        if not validate_client_key(client_key):
            abort(400, description="Invalid client key. Must be a valid UUID4.")

        # Canonicalize to lowercase: a UUID4 is case-insensitive, but the raw
        # string is used verbatim as the tenant identifier AND the encryption KDF
        # input, so `3F6B...` and `3f6b...` would otherwise be two disjoint
        # namespaces with different keys. Store one canonical form.
        g.client_key = client_key.lower()
        return None

    @app.route("/ping", methods=["GET"])
    def ping():
        """Health check endpoint"""
        return jsonify({"message": "PONG"})

    @app.route("/health", methods=["GET"])
    def health():
        """Public liveness + database-readiness probe.

        Actually round-trips the database (``SELECT 1``) so it reports unhealthy
        when the DB is unreachable, instead of always claiming healthy. Returns
        no internal pool details — those are not the public probe's business.
        """
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            logger.exception("health check failed: database unreachable")
            return jsonify({"status": "unhealthy"}), 503
        return jsonify({"status": "healthy"})

    def _strict_reason(auth_service, user):
        """Additive reason for negative answers under strict user identity.

        Computed only on negative paths; None whenever strict mode is off or
        the user is key-backed (i.e. the negative is a genuine denial).
        """
        if auth_service.strict_users_enabled() and not auth_service.user_is_key_backed(
            user
        ):
            return "user_not_key_backed"
        return None

    @app.route("/api/membership/<user>/<group>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.CHECK_MEMBERSHIP, resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['group']}")
    def check_membership(db, user, group):
        """Check if user is member of a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        auth_service = _get_auth_service(db)  # Use helper
        # Strict gate lives here (not in the service) so del_membership's
        # internal has_membership call keeps working — revocation must never
        # be blocked by strict mode.
        reason = _strict_reason(auth_service, user)
        result = False if reason else auth_service.has_membership(user, group)
        data = format_permission_response(result)
        if reason:
            data["reason"] = reason

        return APIResponse.success(
            data=data,
            message=f"Membership check for user '{user}' and group '{group}' completed",
        )

    @app.route("/api/membership/<user>/<group>", methods=["POST"])
    @with_db_session
    @audit_log(AuditAction.ADD_MEMBERSHIP, resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['group']}")
    def add_membership(db, user, group):
        """Add user to a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            abort(400, description=error_msg)

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.add_membership(user, group)
        if not result:
            reason = _strict_reason(auth_service, user)
            if reason:
                # 409, not 200-with-false: two consumers independently showed
                # that a refused grant answering 200 gets written past
                # (raise_for_status passes, result goes unchecked) and turns
                # strict mode into silent dead-key provisioning. Strict mode is
                # opt-in, so the shape may differ there; the documented
                # missing-role 200-false below is untouched.
                return jsonify({"result": False, "reason": reason}), 409

        return jsonify({"result": result})

    @app.route("/api/membership/<user>/<group>", methods=["DELETE"])
    @with_db_session
    @audit_log(AuditAction.REMOVE_MEMBERSHIP, resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['group']}")
    def remove_membership(db, user, group):
        """Remove user from a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            abort(400, description=error_msg)

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.del_membership(user, group)

        return jsonify({"result": result})

    @app.route("/api/permission/<group>/<name>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.CHECK_PERMISSION, resource_extractor=lambda kwargs: f"{kwargs['group']}:{kwargs['name']}")
    @sanitize_input
    def check_permission(db, group, name):
        """Check if group has permission"""
        # Validate input parameters
        if not validate_role_name(group):
            abort(400, description=f"Invalid group name: {group}")

        if not validate_permission_name(name):
            abort(400, description=f"Invalid permission name: {name}")

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.has_permission(group, name)

        return jsonify({"result": result})

    @app.route("/api/permission/<group>/<name>", methods=["POST"])
    @with_db_session
    @audit_log(AuditAction.ADD_PERMISSION, resource_extractor=lambda kwargs: f"{kwargs['group']}:{kwargs['name']}")
    @sanitize_input
    def add_permission(db, group, name):
        """Add permission to a group"""
        # Validate input parameters
        if not validate_role_name(group):
            abort(400, description=f"Invalid group name: {group}")

        if not validate_permission_name(name):
            abort(400, description=f"Invalid permission name: {name}")

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.add_permission(group, name)

        return jsonify({"result": result})

    @app.route("/api/permission/<group>/<name>", methods=["DELETE"])
    @with_db_session
    @audit_log(AuditAction.REMOVE_PERMISSION, resource_extractor=lambda kwargs: f"{kwargs['group']}:{kwargs['name']}")
    @sanitize_input
    def remove_permission(db, group, name):
        """Remove permission from a group"""
        # Validate input parameters
        if not validate_role_name(group):
            abort(400, description=f"Invalid group name: {group}")

        if not validate_permission_name(name):
            abort(400, description=f"Invalid permission name: {name}")

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.del_permission(group, name)

        return jsonify({"result": result})

    @app.route("/api/has_permission/<user>/<name>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.CHECK_PERMISSION, resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['name']}")
    @sanitize_input
    def check_user_permission(db, user, name):
        """Check if user has permission"""
        # Validate input parameters
        if not validate_user_name(user):
            return APIResponse.bad_request(f"Invalid user name: {user}")

        if not validate_permission_name(name):
            return APIResponse.bad_request(f"Invalid permission name: {name}")

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.user_has_permission(user, name)
        data = format_permission_response(result)
        if not result:
            reason = _strict_reason(auth_service, user)
            if reason:
                data["reason"] = reason

        return APIResponse.success(
            data=data,
            message=f"Permission check for user '{user}' and permission '{name}' completed",
        )

    @app.route("/api/user_permissions/<user>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.USER_PERMISSIONS, resource_extractor=lambda kwargs: client_fingerprint(kwargs['user']))
    @sanitize_input
    def get_user_permissions(db, user):
        """Get all permissions for a user"""
        # Validate input parameters
        if not validate_user_name(user):
            return APIResponse.bad_request(f"Invalid user name: {user}")

        auth_service = _get_auth_service(db)  # Use helper
        permissions = auth_service.get_user_permissions(user)
        data = format_user_permissions_response(permissions)
        if not permissions:
            reason = _strict_reason(auth_service, user)
            if reason:
                data["reason"] = reason

        return APIResponse.success(
            data=data,
            message=f"Retrieved permissions for user '{user}'",
        )

    @app.route("/api/role_permissions/<role>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_PERMISSIONS, resource_extractor=lambda kwargs: kwargs['role'])
    @sanitize_input
    def get_role_permissions(db, role):
        """Get all permissions for a role"""
        # Validate input parameters
        if not validate_role_name(role):
            return APIResponse.bad_request(f"Invalid role name: {role}")

        auth_service = _get_auth_service(db)  # Use helper
        permissions = auth_service.get_permissions(role)

        return APIResponse.success(
            data=permissions, message=f"Retrieved permissions for role '{role}'"
        )

    @app.route("/api/user_roles/<user>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: client_fingerprint(kwargs['user']))
    @sanitize_input
    def get_user_roles(db, user):
        """Get all roles for a user"""
        # Validate input parameters
        if not validate_user_name(user):
            abort(400, description=f"Invalid user name: {user}")

        auth_service = _get_auth_service(db)  # Use helper
        roles = auth_service.get_user_roles(user)

        return jsonify({"result": roles})

    @app.route("/api/members/<role>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: kwargs['role'])
    @sanitize_input
    def get_role_members(db, role):
        """Get all members of a role"""
        # Validate input parameters
        if not validate_role_name(role):
            abort(400, description=f"Invalid role name: {role}")

        auth_service = _get_auth_service(db)  # Use helper
        members = auth_service.get_role_members(role)

        return jsonify({"result": members})

    @app.route("/api/roles", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_ROLES, resource_extractor=lambda kwargs: "all")
    def list_roles(db):
        """List all roles"""
        auth_service = _get_auth_service(db)  # Use helper
        roles = auth_service.get_roles()

        return jsonify({"result": roles})

    @app.route("/api/which_roles_can/<name>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_ROLES, resource_extractor=lambda kwargs: kwargs['name'])
    @sanitize_input
    def which_roles_can(db, name):
        """Get roles that can perform an action"""
        # Validate input parameters
        if not validate_permission_name(name):
            abort(400, description=f"Invalid permission name: {name}")

        auth_service = _get_auth_service(db)  # Use helper
        roles = auth_service.which_roles_can(name)

        return jsonify({"result": roles})

    @app.route("/api/which_users_can/<name>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: kwargs['name'])
    @sanitize_input
    def which_users_can(db, name):
        """Get users that can perform an action"""
        # Validate input parameters
        if not validate_permission_name(name):
            abort(400, description=f"Invalid permission name: {name}")

        auth_service = _get_auth_service(db)  # Use helper
        users = auth_service.which_users_can(name)

        return jsonify({"result": users})

    @app.route("/api/role/<role>", methods=["POST"])
    @with_db_session
    @audit_log(AuditAction.CREATE_ROLE, resource_extractor=lambda kwargs: kwargs['role'])
    @sanitize_input
    def create_role(db, role):
        """Create a new role"""
        # Validate input parameters
        if not validate_role_name(role):
            abort(400, description=f"Invalid role name: {role}")

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.add_role(role)

        return jsonify({"result": result})

    @app.route("/api/role/<role>", methods=["DELETE"])
    @with_db_session
    @audit_log(AuditAction.DELETE_ROLE, resource_extractor=lambda kwargs: kwargs['role'])
    @sanitize_input
    def delete_role(db, role):
        """Delete a role"""
        # Validate input parameters
        if not validate_role_name(role):
            return APIResponse.bad_request(f"Invalid role name: {role}")

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.del_role(role)

        return APIResponse.success(
            data={"result": result}, message=f"Role '{role}' deletion completed"
        )

    # Workflow-related endpoints
    @app.route("/api/workflow/users/<workflow_name>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: f"workflow:{kwargs['workflow_name']}")
    @sanitize_input
    def get_users_for_workflow(db, workflow_name):
        """Get all users who can run a specific workflow"""
        # Validate workflow name
        if not validate_permission_name(workflow_name):
            return APIResponse.bad_request(f"Invalid workflow name: {workflow_name}")

        auth_service = _get_auth_service(db)

        users = auth_service.which_users_can(workflow_name)

        return APIResponse.success(
            data=format_role_members_response(users),
            message=f"Retrieved users who can run workflow '{workflow_name}'",
        )

    @app.route("/api/workflow/user/<user>/can_run/<workflow_name>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.CHECK_PERMISSION, resource_extractor=lambda kwargs: f"workflow:{kwargs['workflow_name']}")
    @sanitize_input
    def check_user_workflow_permission(db, user, workflow_name):
        """Check if a user can run a specific workflow"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, workflow_name)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        auth_service = _get_auth_service(db)

        result = auth_service.user_has_permission(user, workflow_name)
        data = format_permission_response(result)
        if not result:
            reason = _strict_reason(auth_service, user)
            if reason:
                data["reason"] = reason

        return APIResponse.success(
            data=data,
            message=f"Workflow permission check for user '{user}' and workflow '{workflow_name}' completed",
        )

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
            return APIResponse.bad_request(
                'JSON body required: {"api_key": "rak_..."}'
            )
        api_key = body.get("api_key")
        if not isinstance(api_key, str) or not API_KEY_PATTERN.match(api_key):
            return APIResponse.bad_request(
                "api_key must be a string matching rak_[0-9A-Za-z]{43}"
            )

        auth_service = _get_auth_service(db)
        result = auth_service.validate_api_key(api_key)
        return APIResponse.success(
            data=result, message="API key validation completed"
        )

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
        if not isinstance(permission, str) or not validate_permission_name(
            permission
        ):
            return APIResponse.bad_request(f"Invalid permission name: {permission!r}")

        auth_service = _get_auth_service(db)
        result = auth_service.check_api_key_permission(api_key, permission)
        return APIResponse.success(
            data=result, message="API-key permission check completed"
        )

    # Tenant settings (SPEC 0010)
    @app.route("/api/settings", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.GET_SETTINGS, resource_extractor=lambda kwargs: "settings"
    )
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
        if not isinstance(body, dict) or not isinstance(
            body.get("strict_users"), bool
        ):
            return APIResponse.bad_request(
                'JSON body required: {"strict_users": true|false}'
            )

        auth_service = _get_auth_service(db)
        result = auth_service.set_strict_users(body["strict_users"])
        return APIResponse.success(data=result, message="Tenant settings updated")
