"""Membership routes: is a user in a role, add them, remove them."""

import logging

from flask import abort, jsonify

from auth.audit import (
    AuditAction,
    client_fingerprint,
)
from auth.decorators import audit_log
from auth.response_format import (
    APIResponse,
    format_permission_response,
)
from auth.routes._common import (
    _get_auth_service,
    _strict_reason,
    with_db_session,
)
from auth.validation import (
    validate_user_role_combination,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the membership routes on ``app``."""

    @app.route("/api/membership/<user>/<group>", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.CHECK_MEMBERSHIP,
        resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['group']}",
    )
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
    @audit_log(
        AuditAction.ADD_MEMBERSHIP,
        resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['group']}",
    )
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
                return (
                    jsonify(
                        {
                            "result": False,
                            "reason": reason,
                            "hint": (
                                f"strict_users is enabled and user '{user}' has no "
                                "API key. Either create one with "
                                f"POST /api/apikeys/user/{user}, or opt this "
                                "namespace out with PUT /api/settings "
                                '{"strict_users": false}.'
                            ),
                        }
                    ),
                    409,
                )

        return jsonify({"result": result})

    @app.route("/api/membership/<user>/<group>", methods=["DELETE"])
    @with_db_session
    @audit_log(
        AuditAction.REMOVE_MEMBERSHIP,
        resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['group']}",
    )
    def remove_membership(db, user, group):
        """Remove user from a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            abort(400, description=error_msg)

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.del_membership(user, group)

        return jsonify({"result": result})
