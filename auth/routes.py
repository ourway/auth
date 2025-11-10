"""
Flask routes for authorization service
"""

from flask import abort, jsonify, request

from auth.audit import AuditAction, log_audit_event
from auth.database import SessionLocal
from auth.response_format import (
    APIResponse,
    format_permission_response,
    format_role_members_response,
    format_user_permissions_response,
    handle_exception,
)
from auth.service import AuthorizationService
from auth.validation import (
    validate_client_key,
    validate_permission_name,
    validate_role_name,
    validate_user_name,
    validate_user_role_combination,
)


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


def register_routes(app, limiter=None):
    """Register all routes with the Flask app"""

    @app.route("/ping", methods=["GET"])
    def ping():
        """Health check endpoint"""
        return jsonify({"message": "PONG"})

    @app.route("/api/membership/<user>/<group>", methods=["GET"])
    def check_membership(user, group):
        """Check if user is member of a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.CHECK_MEMBERSHIP,
                resource=f"{user}:{group}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.bad_request(error_msg)

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.has_membership(user, group)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.CHECK_MEMBERSHIP,
                resource=f"{user}:{group}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return APIResponse.success(
                data=format_permission_response(result),
                message=f"Membership check for user '{user}' and group '{group}' completed",
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    @app.route("/api/membership/<user>/<group>", methods=["POST"])
    def add_membership(user, group):
        """Add user to a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.ADD_MEMBERSHIP,
                resource=f"{user}:{group}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=error_msg)

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.add_membership(user, group)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.ADD_MEMBERSHIP,
                resource=f"{user}:{group}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=result,
            )

            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/membership/<user>/<group>", methods=["DELETE"])
    def remove_membership(user, group):
        """Remove user from a group"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, group)
        if not is_valid:
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.REMOVE_MEMBERSHIP,
                resource=f"{user}:{group}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=error_msg)

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.del_membership(user, group)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.REMOVE_MEMBERSHIP,
                resource=f"{user}:{group}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=result,
            )

            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/permission/<group>/<name>", methods=["GET"])
    def check_permission(group, name):
        """Check if group has permission"""
        # Validate input parameters
        if not validate_role_name(group):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"{group}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid group name: {group}")

        if not validate_permission_name(name):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"{group}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid permission name: {name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.has_permission(group, name)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"{group}:{name}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/permission/<group>/<name>", methods=["POST"])
    def add_permission(group, name):
        """Add permission to a group"""
        # Validate input parameters
        if not validate_role_name(group):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.ADD_PERMISSION,
                resource=f"{group}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid group name: {group}")

        if not validate_permission_name(name):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.ADD_PERMISSION,
                resource=f"{group}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid permission name: {name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.add_permission(group, name)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.ADD_PERMISSION,
                resource=f"{group}:{name}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=result,
            )

            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/permission/<group>/<name>", methods=["DELETE"])
    def remove_permission(group, name):
        """Remove permission from a group"""
        # Validate input parameters
        if not validate_role_name(group):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.REMOVE_PERMISSION,
                resource=f"{group}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid group name: {group}")

        if not validate_permission_name(name):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.REMOVE_PERMISSION,
                resource=f"{group}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid permission name: {name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.del_permission(group, name)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.REMOVE_PERMISSION,
                resource=f"{group}:{name}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=result,
            )

            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/has_permission/<user>/<name>", methods=["GET"])
    def check_user_permission(user, name):
        """Check if user has permission"""
        # Validate input parameters
        if not validate_user_name(user):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"{user}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.bad_request(f"Invalid user name: {user}")

        if not validate_permission_name(name):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"{user}:{name}",
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.bad_request(f"Invalid permission name: {name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.user_has_permission(user, name)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"{user}:{name}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return APIResponse.success(
                data=format_permission_response(result),
                message=f"Permission check for user '{user}' and permission '{name}' completed",
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    @app.route("/api/user_permissions/<user>", methods=["GET"])
    def get_user_permissions(user):
        """Get all permissions for a user"""
        # Validate input parameters
        if not validate_user_name(user):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.USER_PERMISSIONS,
                resource=user,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.bad_request(f"Invalid user name: {user}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            permissions = auth_service.get_user_permissions(user)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.USER_PERMISSIONS,
                resource=user,
                details={"count": len(permissions)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return APIResponse.success(
                data=format_user_permissions_response(permissions),
                message=f"Retrieved permissions for user '{user}'",
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    @app.route("/api/role_permissions/<role>", methods=["GET"])
    def get_role_permissions(role):
        """Get all permissions for a role"""
        # Validate input parameters
        if not validate_role_name(role):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.LIST_PERMISSIONS,
                resource=role,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.bad_request(f"Invalid role name: {role}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            permissions = auth_service.get_permissions(role)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.LIST_PERMISSIONS,
                resource=role,
                details={"count": len(permissions)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return APIResponse.success(
                data=permissions, message=f"Retrieved permissions for role '{role}'"
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    @app.route("/api/user_roles/<user>", methods=["GET"])
    def get_user_roles(user):
        """Get all roles for a user"""
        # Validate input parameters
        if not validate_user_name(user):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=user,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=user,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid user name: {user}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            roles = auth_service.get_user_roles(user)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=user,
                details={"count": len(roles)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return jsonify({"result": roles})
        finally:
            db.close()

    @app.route("/api/members/<role>", methods=["GET"])
    def get_role_members(role):
        """Get all members of a role"""
        # Validate input parameters
        if not validate_role_name(role):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=role,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid role name: {role}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            members = auth_service.get_role_members(role)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=role,
                details={"count": len(members)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return jsonify({"result": members})
        finally:
            db.close()

    @app.route("/api/roles", methods=["GET"])
    def list_roles():
        """List all roles"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            roles = auth_service.get_roles()

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.LIST_ROLES,
                resource="all",
                details={"count": len(roles)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return jsonify({"result": roles})
        finally:
            db.close()

    @app.route("/api/which_roles_can/<name>", methods=["GET"])
    def which_roles_can(name):
        """Get roles that can perform an action"""
        # Validate input parameters
        if not validate_permission_name(name):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.LIST_ROLES,
                resource=name,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid permission name: {name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            roles = auth_service.which_roles_can(name)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.LIST_ROLES,
                resource=name,
                details={"count": len(roles)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return jsonify({"result": roles})
        finally:
            db.close()

    @app.route("/api/which_users_can/<name>", methods=["GET"])
    def which_users_can(name):
        """Get users that can perform an action"""
        # Validate input parameters
        if not validate_permission_name(name):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=name,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid permission name: {name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            users = auth_service.which_users_can(name)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=name,
                details={"count": len(users)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return jsonify({"result": users})
        finally:
            db.close()

    @app.route("/api/role/<role>", methods=["POST"])
    def create_role(role):
        """Create a new role"""
        # Validate input parameters
        if not validate_role_name(role):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.CREATE_ROLE,
                resource=role,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            abort(400, description=f"Invalid role name: {role}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.add_role(role)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.CREATE_ROLE,
                resource=role,
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=result,
            )

            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/role/<role>", methods=["DELETE"])
    def delete_role(role):
        """Delete a role"""
        # Validate input parameters
        if not validate_role_name(role):
            log_audit_event(
                client_id=request.headers.get("Authorization", "").replace(
                    "Bearer ", ""
                )[:10]
                + "...",
                user=None,
                action=AuditAction.DELETE_ROLE,
                resource=role,
                details={"success": False, "reason": "validation_error"},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=False,
            )
            return APIResponse.bad_request(f"Invalid role name: {role}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.del_role(role)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.DELETE_ROLE,
                resource=role,
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=result,
            )

            return APIResponse.success(
                data={"result": result}, message=f"Role '{role}' deletion completed"
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    # Workflow-related endpoints
    @app.route("/api/workflow/users/<workflow_name>", methods=["GET"])
    def get_users_for_workflow(workflow_name):
        """Get all users who can run a specific workflow"""
        # Validate workflow name
        if not validate_permission_name(workflow_name):
            return APIResponse.bad_request(f"Invalid workflow name: {workflow_name}")

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            # Use the auth service to find which users can perform this workflow action
            users = auth_service.which_users_can(workflow_name)

            log_audit_event(
                client_id=client_id,
                user=None,
                action=AuditAction.LIST_MEMBERSHIPS,
                resource=f"workflow:{workflow_name}",
                details={"count": len(users)},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return APIResponse.success(
                data=format_role_members_response(users),
                message=f"Retrieved users who can run workflow '{workflow_name}'",
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    @app.route("/api/workflow/user/<user>/can_run/<workflow_name>", methods=["GET"])
    def check_user_workflow_permission(user, workflow_name):
        """Check if a user can run a specific workflow"""
        # Validate input parameters
        is_valid, error_msg = validate_user_role_combination(user, workflow_name)
        if not is_valid:
            return APIResponse.bad_request(error_msg)

        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)

            # Extract client ID from authorization header for logging
            auth_header = request.headers.get("Authorization", "")
            client_id = (
                auth_header.replace("Bearer ", "")
                if auth_header.startswith("Bearer ")
                else "unknown"
            )

            # Check if user has permission to run workflow
            result = auth_service.user_has_permission(user, workflow_name)

            log_audit_event(
                client_id=client_id,
                user=user,
                action=AuditAction.CHECK_PERMISSION,
                resource=f"workflow:{workflow_name}",
                details={"result": result},
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                success=True,
            )

            return APIResponse.success(
                data=format_permission_response(result),
                message=f"Workflow permission check for user '{user}' and workflow '{workflow_name}' completed",
            )
        except Exception as e:
            return handle_exception(e)
        finally:
            db.close()

    # Apply rate limiting if limiter is provided
    if limiter:
        # Apply rate limiting to API endpoints
        ping = limiter.limit("100 per minute")(ping)
        check_membership = limiter.limit("500 per hour")(check_membership)
        add_membership = limiter.limit("200 per hour")(add_membership)
        remove_membership = limiter.limit("200 per hour")(remove_membership)
        check_permission = limiter.limit("500 per hour")(check_permission)
        add_permission = limiter.limit("200 per hour")(add_permission)
        remove_permission = limiter.limit("200 per hour")(remove_permission)
        check_user_permission = limiter.limit("500 per hour")(check_user_permission)
        get_user_permissions = limiter.limit("500 per hour")(get_user_permissions)
        get_role_permissions = limiter.limit("500 per hour")(get_role_permissions)
        get_user_roles = limiter.limit("500 per hour")(get_user_roles)
        get_role_members = limiter.limit("500 per hour")(get_role_members)
        list_roles = limiter.limit("500 per hour")(list_roles)
        which_roles_can = limiter.limit("500 per hour")(which_roles_can)
        which_users_can = limiter.limit("500 per hour")(which_users_can)
        create_role = limiter.limit("200 per hour")(create_role)
        delete_role = limiter.limit("200 per hour")(delete_role)
        get_users_for_workflow = limiter.limit("500 per hour")(get_users_for_workflow)
        check_user_workflow_permission = limiter.limit("500 per hour")(
            check_user_workflow_permission
        )
