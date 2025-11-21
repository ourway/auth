"""
Consistent error handling and response formatting for the authorization system
"""

from typing import Any, Dict, Optional, Tuple

from flask import Response, jsonify


class APIResponse:
    """Standardized API response format"""

    @staticmethod
    def success(
        data: Any = None, message: str = "Success", code: int = 200
    ) -> Tuple[Response, int]:
        """Create a standardized success response"""
        response_data = {
            "success": True,
            "code": code,
            "message": message,
            "data": data,
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        }
        return jsonify(response_data), code

    @staticmethod
    def error(
        message: str, code: int = 400, details: Optional[Dict] = None
    ) -> Tuple[Response, int]:
        """Create a standardized error response"""
        response_data = {
            "success": False,
            "code": code,
            "message": message,
            "details": details or {},
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        }
        return jsonify(response_data), code

    @staticmethod
    def not_found(
        item_type: str = "Resource", item_id: Optional[str] = None
    ) -> Tuple[Response, int]:
        """Create a standardized not found response"""
        message = f"{item_type} not found"
        if item_id:
            message = f"{item_type} with ID {item_id} not found"

        return APIResponse.error(message, 404)

    @staticmethod
    def unauthorized(message: str = "Unauthorized access") -> Tuple[Response, int]:
        """Create a standardized unauthorized response"""
        return APIResponse.error(message, 401)

    @staticmethod
    def forbidden(message: str = "Forbidden access") -> Tuple[Response, int]:
        """Create a standardized forbidden response"""
        return APIResponse.error(message, 403)

    @staticmethod
    def bad_request(message: str = "Bad request") -> Tuple[Response, int]:
        """Create a standardized bad request response"""
        return APIResponse.error(message, 400)

    @staticmethod
    def server_error(message: str = "Internal server error") -> Tuple[Response, int]:
        """Create a standardized server error response"""
        return APIResponse.error(message, 500)


def handle_exception(e: Exception) -> Tuple[Response, int]:
    """Handle exceptions and return appropriate error response"""
    import traceback

    error_msg = str(e)
    error_code = 500

    # Differentiate between different types of errors
    if "validation" in error_msg.lower() or "invalid" in error_msg.lower():
        error_code = 400
    elif "unauthorized" in error_msg.lower() or "auth" in error_msg.lower():
        error_code = 401
    elif "forbidden" in error_msg.lower():
        error_code = 403
    elif "not found" in error_msg.lower() or "404" in error_msg.lower():
        error_code = 404

    # Log the full traceback for debugging
    print(f"Error: {e}")
    print(traceback.format_exc())

    return APIResponse.error(
        message="An error occurred processing your request",
        code=error_code,
        details={
            "error_type": type(e).__name__,
            "error_message": error_msg,
            "dev_error": (
                str(e)
                if __import__("os").getenv("DEBUG", "").lower() == "true"
                else "Error details hidden"
            ),
        },
    )


def format_user_permissions_response(permissions: list) -> dict:
    """Format user permissions response consistently"""
    return {"count": len(permissions), "permissions": permissions}


def format_user_roles_response(roles: list) -> dict:
    """Format user roles response consistently"""
    return {"count": len(roles), "roles": roles}


def format_role_members_response(members: list) -> dict:
    """Format role members response consistently"""
    return {"count": len(members), "members": members}


def format_roles_response(roles: list) -> dict:
    """Format roles response consistently"""
    return {"count": len(roles), "roles": roles}


def format_permission_response(has_permission: bool) -> dict:
    """Format permission check response consistently"""
    return {"has_permission": has_permission}
