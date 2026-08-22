"""Role routes: listing, membership projections, creation and deletion."""

import logging

from flask import abort, jsonify

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
from auth.sanitizer import sanitize_input
from auth.validation import (
    validate_permission_name,
    validate_role_name,
    validate_user_name,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the roles routes on ``app``."""

    @app.route("/api/user_roles/<user>", methods=["GET"])
    @with_db_session
    @audit_log(
        AuditAction.LIST_MEMBERSHIPS,
        resource_extractor=lambda kwargs: client_fingerprint(kwargs["user"]),
    )
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
    @audit_log(
        AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: kwargs["role"]
    )
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
    @audit_log(AuditAction.LIST_ROLES, resource_extractor=lambda kwargs: kwargs["name"])
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
    @audit_log(
        AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: kwargs["name"]
    )
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
    @audit_log(
        AuditAction.CREATE_ROLE, resource_extractor=lambda kwargs: kwargs["role"]
    )
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
    @audit_log(
        AuditAction.DELETE_ROLE, resource_extractor=lambda kwargs: kwargs["role"]
    )
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
