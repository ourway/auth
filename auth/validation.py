"""
Input validation and sanitization utilities for the authorization system
"""

import re
from typing import Optional

# Define validation patterns
CLIENT_KEY_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
USER_ROLE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_client_key(client_key: str) -> bool:
    """
    Validate that the client key is a valid UUID4
    """
    if not isinstance(client_key, str):
        return False
    return bool(CLIENT_KEY_PATTERN.match(client_key))


def validate_user_name(user_name: str) -> bool:
    """
    Validate user name format
    """
    if not isinstance(user_name, str):
        return False
    return bool(USER_ROLE_NAME_PATTERN.match(user_name))


def validate_role_name(role_name: str) -> bool:
    """
    Validate role name format
    """
    if not isinstance(role_name, str):
        return False
    return bool(USER_ROLE_NAME_PATTERN.match(role_name))


def validate_permission_name(permission_name: str) -> bool:
    """
    Validate permission name format
    """
    if not isinstance(permission_name, str):
        return False
    # Permission names can include more characters than role names
    pattern = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
    return bool(pattern.match(permission_name))


def sanitize_input(input_str: str) -> str:
    """
    Sanitize input by removing dangerous characters
    """
    if not isinstance(input_str, str):
        return ""

    # Remove potentially dangerous characters
    # Only allow alphanumeric, underscore, hyphen
    sanitized = re.sub(r"[^\w\-]", "", input_str)
    return sanitized


def validate_and_sanitize_user_input(user_input: str) -> Optional[str]:
    """
    Validate and sanitize user input
    Returns sanitized input if valid, None if invalid
    """
    if not isinstance(user_input, str):
        return None

    # Check for potential SQL injection patterns
    dangerous_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)",
        r"(--|#|/\*|\*/|;)",
        r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)",
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return None

    # Sanitize the input
    sanitized = sanitize_input(user_input)
    return sanitized if sanitized else None


def validate_api_parameters(params: dict) -> tuple[bool, str]:
    """
    Validate common API parameters
    Returns (is_valid, error_message)
    """
    # Validate required parameters
    for param_name, param_value in params.items():
        if param_value is not None and not validate_and_sanitize_user_input(
            str(param_value)
        ):
            return False, f"Invalid parameter: {param_name}"

    return True, ""


def validate_user_role_combination(user: str, role: str) -> tuple[bool, str]:
    """
    Validate user and role parameters together
    """
    if not validate_user_name(user):
        return (
            False,
            f"Invalid user name: {user}. User names must be 1-64 characters long and contain only alphanumeric, underscore, and hyphen.",
        )

    if not validate_role_name(role):
        return (
            False,
            f"Invalid role name: {role}. Role names must be 1-64 characters long and contain only alphanumeric, underscore, and hyphen.",
        )

    return True, ""
