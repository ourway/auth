"""Permission routes: grants on roles and effective answers for users."""

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
    format_user_permissions_response,
)
from auth.routes._common import (
    _get_auth_service,
    _strict_reason,
    with_db_session,
)
from auth.sanitizer import sanitize_input
from auth.validation import (
    validate_permission_name,
    validate_role_name,
    validate_user_name,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the permissions routes on ``app``."""

    @app.route("/api/permission/<group>/<name>", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.CHECK_PERMISSION,
        resource_extractor=lambda kwargs: f"{kwargs['group']}:{kwargs['name']}",
    )
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
    @audit_log(
        AuditAction.ADD_PERMISSION,
        resource_extractor=lambda kwargs: f"{kwargs['group']}:{kwargs['name']}",
    )
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
    @audit_log(
        AuditAction.REMOVE_PERMISSION,
        resource_extractor=lambda kwargs: f"{kwargs['group']}:{kwargs['name']}",
    )
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
    @audit_log(
        AuditAction.CHECK_PERMISSION,
        resource_extractor=lambda kwargs: f"{client_fingerprint(kwargs['user'])}:{kwargs['name']}",
    )
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
    @audit_log(
        AuditAction.USER_PERMISSIONS,
        resource_extractor=lambda kwargs: client_fingerprint(kwargs["user"]),
    )
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
    @audit_log(
        AuditAction.LIST_PERMISSIONS, resource_extractor=lambda kwargs: kwargs["role"]
    )
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
