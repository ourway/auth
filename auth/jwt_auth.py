"""
JWT-based authentication and authorization for the authorization system
"""

import datetime
from typing import Any, Dict, Optional

import jwt

from auth.config import get_settings


class JWTAuth:
    """JWT-based authentication and authorization handler"""

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def encode_token(
        self,
        client_id: str,
        user_id: Optional[str] = None,
        permissions: Optional[list] = None,
        expires_delta: Optional[datetime.timedelta] = None,
    ) -> str:
        """
        Encode a JWT token with the given information
        """
        if expires_delta is None:
            expires_delta = datetime.timedelta(hours=24)  # Default to 24 hours

        expire = datetime.datetime.utcnow() + expires_delta
        payload = {
            "sub": client_id,
            "user_id": user_id,
            "permissions": permissions or [],
            "exp": expire,
            "iat": datetime.datetime.utcnow(),
        }

        encoded_token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return encoded_token

    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode a JWT token and return the payload
        """
        try:
            payload: Dict[str, Any] = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def verify_client_token(
        self, token: str, required_permission: Optional[str] = None
    ) -> bool:
        """
        Verify a client token is valid and optionally check for required permissions
        """
        payload = self.decode_token(token)
        if not payload:
            return False

        # Check if token has expired
        if payload.get("exp", 0) < datetime.datetime.utcnow().timestamp():
            return False

        # If required permission is specified, check if it exists in the payload
        if required_permission:
            permissions = payload.get("permissions", [])
            if required_permission not in permissions:
                return False

        return True

    def create_client_token(
        self, client_id: str, permissions: Optional[list] = None
    ) -> str:
        """
        Create a JWT token for the given client with optional permissions
        """
        return self.encode_token(client_id, permissions=permissions)

    def refresh_token(self, token: str) -> Optional[str]:
        """
        Refresh an existing token by extending its expiration
        """
        payload = self.decode_token(token)
        if not payload:
            return None

        # Create a new token with extended expiration
        return self.encode_token(
            payload["sub"],
            user_id=payload.get("user_id"),
            permissions=payload.get("permissions", []),
            expires_delta=datetime.timedelta(hours=24),
        )


# Initialize JWT auth with secret key from config
settings = get_settings()
jwt_auth = JWTAuth(settings.jwt_secret_key, settings.jwt_algorithm)


def get_user_permissions_from_jwt(token: str) -> list:
    """
    Extract user permissions from a JWT token
    """
    payload = jwt_auth.decode_token(token)
    if payload:
        permissions: list = payload.get("permissions", [])
        return permissions
    return []


def validate_jwt_client_access(
    client_id: str, token: str, required_permission: Optional[str] = None
) -> bool:
    """
    Validate if a client can access the system with the given JWT token
    """
    return jwt_auth.verify_client_token(token, required_permission)


def create_jwt_for_client(client_id: str, permissions: Optional[list] = None) -> str:
    """
    Create a JWT token for a client
    """
    return jwt_auth.create_client_token(client_id, permissions=permissions)
