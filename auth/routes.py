"""
Flask routes for authorization service
"""

from flask import abort, jsonify, request

from auth.database import SessionLocal
from auth.service import AuthorizationService


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

    @app.route("/api/membership/<user>/<group>", methods=["GET"])
    def check_membership(user, group):
        """Check if user is member of a group"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.has_membership(user, group)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/membership/<user>/<group>", methods=["POST"])
    def add_membership(user, group):
        """Add user to a group"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.add_membership(user, group)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/membership/<user>/<group>", methods=["DELETE"])
    def remove_membership(user, group):
        """Remove user from a group"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.del_membership(user, group)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/permission/<group>/<name>", methods=["GET"])
    def check_permission(group, name):
        """Check if group has permission"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.has_permission(group, name)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/permission/<group>/<name>", methods=["POST"])
    def add_permission(group, name):
        """Add permission to a group"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.add_permission(group, name)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/permission/<group>/<name>", methods=["DELETE"])
    def remove_permission(group, name):
        """Remove permission from a group"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.del_permission(group, name)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/has_permission/<user>/<name>", methods=["GET"])
    def check_user_permission(user, name):
        """Check if user has permission"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.user_has_permission(user, name)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/user_permissions/<user>", methods=["GET"])
    def get_user_permissions(user):
        """Get all permissions for a user"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            permissions = auth_service.get_user_permissions(user)
            return jsonify({"results": permissions})
        finally:
            db.close()

    @app.route("/api/role_permissions/<role>", methods=["GET"])
    def get_role_permissions(role):
        """Get all permissions for a role"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            permissions = auth_service.get_permissions(role)
            return jsonify({"results": permissions})
        finally:
            db.close()

    @app.route("/api/user_roles/<user>", methods=["GET"])
    def get_user_roles(user):
        """Get all roles for a user"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            roles = auth_service.get_user_roles(user)
            return jsonify({"result": roles})
        finally:
            db.close()

    @app.route("/api/members/<role>", methods=["GET"])
    def get_role_members(role):
        """Get all members of a role"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            members = auth_service.get_role_members(role)
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
            return jsonify({"result": roles})
        finally:
            db.close()

    @app.route("/api/which_roles_can/<name>", methods=["GET"])
    def which_roles_can(name):
        """Get roles that can perform an action"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            roles = auth_service.which_roles_can(name)
            return jsonify({"result": roles})
        finally:
            db.close()

    @app.route("/api/which_users_can/<name>", methods=["GET"])
    def which_users_can(name):
        """Get users that can perform an action"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            users = auth_service.which_users_can(name)
            return jsonify({"result": users})
        finally:
            db.close()

    @app.route("/api/role/<role>", methods=["POST"])
    def create_role(role):
        """Create a new role"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.add_role(role)
            return jsonify({"result": result})
        finally:
            db.close()

    @app.route("/api/role/<role>", methods=["DELETE"])
    def delete_role(role):
        """Delete a role"""
        db = SessionLocal()
        try:
            auth_service = _get_auth_service(db)  # Use helper
            result = auth_service.del_role(role)
            return jsonify({"result": result})
        finally:
            db.close()
