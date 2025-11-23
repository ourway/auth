"""
Flask routes for authorization service
"""

from functools import wraps

from flask import abort, jsonify, request

from auth.audit import AuditAction
from auth.database import get_db, get_pool_status
from auth.decorators import audit_log
from auth.response_format import (
    APIResponse,
    format_permission_response,
    format_role_members_response,
    format_user_permissions_response,
)
from auth.sanitizer import sanitize_input
from auth.services.service import AuthorizationService
from auth.validation import (
    validate_client_key,
    validate_permission_name,
    validate_role_name,
    validate_user_name,
    validate_user_role_combination,
)


def with_db_session(route_func):
    """
    Decorator to provide a database session to route functions
    """

    @wraps(route_func)  # Preserve function metadata to avoid Flask endpoint conflicts
    def wrapper(*args, **kwargs):
        with get_db() as db:
            try:
                return route_func(db, *args, **kwargs)
            except Exception as e:
                db.rollback()  # Rollback any failed transactions
                raise e

    return wrapper


def _get_auth_service(db):
    """
    Extracts the Bearer token, validates it, and returns an auth service.
    Aborts with 400/401 on error.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        abort(401, description="Authorization header is missing.")

    parts = auth_header.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        abort(
            401,
            description="Invalid Authorization header format. Must be 'Bearer <token>'.",
        )

    client_key = parts[1]
    # Additional validation for client key format
    if not validate_client_key(client_key):
        abort(
            400,
            description=f"Invalid client key: {client_key}. Client key must be a valid UUID4.",
        )

    try:
        # The service init validates the UUID4 format
        auth_service = AuthorizationService(db, client_key, validate_client=True)
        return auth_service
    except ValueError as e:
        abort(400, description=str(e))


def register_routes(app):
    """Register all routes with the Flask app"""

    @app.route("/ping", methods=["GET"])
    def ping():
        """Health check endpoint"""
        return jsonify({"message": "PONG"})

    @app.route("/health", methods=["GET"])
    def health():
        """
        Health check endpoint with connection pool statistics
        Useful for monitoring and debugging in production
        """
        pool_stats = get_pool_status()
        return jsonify({
            "status": "healthy",
            "database": {
                "pool_size": pool_stats.get("pool_size", 0),
                "checked_out": pool_stats.get("checked_out", 0),
                "available": pool_stats.get("available", 0),
                "overflow": pool_stats.get("overflow", 0),
                "total_connections": pool_stats.get("total_connections", 0),
            }
        })

    @app.route("/api/membership/<user>/<group>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.CHECK_MEMBERSHIP, resource_extractor=lambda kwargs: f"{kwargs['user']}:{kwargs['group']}")
    def check_membership(db, user, group):
        """Check if user is member of a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.has_membership(user, group)

        return APIResponse.success(
            data=format_permission_response(result),
            message=f"Membership check for user '{user}' and group '{group}' completed",
        )

    @app.route("/api/membership/<user>/<group>", methods=["POST"])
    @with_db_session
    @audit_log(AuditAction.ADD_MEMBERSHIP, resource_extractor=lambda kwargs: f"{kwargs['user']}:{kwargs['group']}")
    def add_membership(db, user, group):
        """Add user to a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            abort(400, description=error_msg)

        auth_service = _get_auth_service(db)  # Use helper
        result = auth_service.add_membership(user, group)

        return jsonify({"result": result})

    @app.route("/api/membership/<user>/<group>", methods=["DELETE"])
    @with_db_session
    @audit_log(AuditAction.REMOVE_MEMBERSHIP, resource_extractor=lambda kwargs: f"{kwargs['user']}:{kwargs['group']}")
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
    @audit_log(AuditAction.CHECK_PERMISSION, resource_extractor=lambda kwargs: f"{kwargs['user']}:{kwargs['name']}")
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

        return APIResponse.success(
            data=format_permission_response(result),
            message=f"Permission check for user '{user}' and permission '{name}' completed",
        )

    @app.route("/api/user_permissions/<user>", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.USER_PERMISSIONS, resource_extractor=lambda kwargs: kwargs['user'])
    @sanitize_input
    def get_user_permissions(db, user):
        """Get all permissions for a user"""
        # Validate input parameters
        if not validate_user_name(user):
            return APIResponse.bad_request(f"Invalid user name: {user}")

        auth_service = _get_auth_service(db)  # Use helper
        permissions = auth_service.get_user_permissions(user)

        return APIResponse.success(
            data=format_user_permissions_response(permissions),
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
    @audit_log(AuditAction.LIST_MEMBERSHIPS, resource_extractor=lambda kwargs: kwargs['user'])
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

        return APIResponse.success(
            data=format_permission_response(result),
            message=f"Workflow permission check for user '{user}' and workflow '{workflow_name}' completed",
        )
