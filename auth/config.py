
"""
Centralized configuration management for the authorization system
"""

import os
from enum import Enum
from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseType(Enum):
    """Supported database types"""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


# Values that must never protect a production secret. The audit pepper keys the
# HMAC that fingerprints client keys in the audit trail; if it is one of these
# (or empty), the fingerprints are computable by anyone and the audit log's
# offline-guess resistance is gone. Boot fails closed rather than run weak.
_KNOWN_WEAK_SECRETS = frozenset(
    {
        "",
        "default_secret_key_for_development",
        "your_secure_jwt_secret_key_here",
        "changeme",
        "change-me",
        "secret",
        "password",
    }
)


class Settings(BaseSettings):
    """Configuration class for the authorization system"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        env_prefix="AUTH_"
    )

    # Database settings
    database_type: DatabaseType = DatabaseType.SQLITE
    database_url: str = Field("", validate_default=True)
    sqlite_path: str = Field(default= "~/.auth.sqlite3")
    postgresql_url: str = ""

    # JWT settings
    jwt_secret_key: str = "default_secret_key_for_development"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 1440  # 24 hours
    jwt_refresh_token_expire_days: int = 7

    # Security settings
    allow_cors: bool = True
    cors_origins: str = "*"
    enable_audit_logging: bool = True
    # Pepper used to fingerprint the client key before it is written to audit
    # rows or logs. Falls back to jwt_secret_key when empty so the fingerprint
    # is never unsalted; set a dedicated AUTH_AUDIT_PEPPER in production.
    audit_pepper: str = ""
    # Application-layer rate limiting. Defense in depth only — nginx is the
    # primary per-IP limiter at the edge. Off by default; to be effective across
    # gunicorn workers it needs shared storage
    # (e.g. AUTH_RATELIMIT_STORAGE_URI=redis://...).
    enable_rate_limit: bool = False
    ratelimit_default: str = "40/second"
    ratelimit_storage_uri: str = "memory://"

    # Server settings
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    debug_mode: bool = False

    # Encryption settings
    enable_encryption: bool = False
    encryption_key: str = ""

    # Schema settings (for PostgreSQL multi-tenancy)
    database_schema: str = ""  # Optional schema name (e.g., "auth_rbac" for Highway)

    @model_validator(mode="after")
    def assemble_db_connection(self) -> "Settings":
        # If database_url is not explicitly set, construct it from other fields
        if not self.database_url:
            if self.database_type == DatabaseType.SQLITE:
                # Expand tilde in sqlite_path
                expanded_path = os.path.expanduser(self.sqlite_path)
                self.database_url = f"sqlite:///{expanded_path}"
            elif self.postgresql_url:
                self.database_url = self.postgresql_url
        else:
            # An explicit AUTH_DATABASE_URL wins: keep database_type in sync
            # with the URL scheme so engine creation uses the right settings.
            if self.database_url.startswith(("postgresql", "postgres:")):
                self.database_type = DatabaseType.POSTGRESQL
            elif self.database_url.startswith("sqlite"):
                self.database_type = DatabaseType.SQLITE
        # psycopg (v3) is the installed driver; SQLAlchemy resolves a bare
        # postgresql:// URL to psycopg2, which is not a dependency.
        if self.database_url.startswith("postgresql://"):
            self.database_url = self.database_url.replace(
                "postgresql://", "postgresql+psycopg://", 1
            )
        elif self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace(
                "postgres://", "postgresql+psycopg://", 1
            )
        return self

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if v in _KNOWN_WEAK_SECRETS:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "AUTH_JWT_SECRET_KEY is a weak/placeholder value. "
                "Set a strong secret for production."
            )
        return v

    @model_validator(mode="after")
    def require_strong_audit_pepper(self) -> "Settings":
        """Fail closed in production on a weak audit pepper.

        The pepper is ``audit_pepper`` if set, else ``jwt_secret_key`` (the same
        fallback ``audit.client_fingerprint`` uses). When audit logging is on and
        we are not in debug mode, refuse to start unless it is a strong, dedicated
        value — a placeholder pepper makes the audit key-fingerprints computable.
        """
        if self.enable_audit_logging and not self.debug_mode:
            pepper = (self.audit_pepper or self.jwt_secret_key or "").strip()
            if pepper in _KNOWN_WEAK_SECRETS or len(pepper) < 16:
                raise ValueError(
                    "Refusing to start: the audit pepper is unset, a placeholder, "
                    "or too short. Set AUTH_AUDIT_PEPPER to a strong random value "
                    "(>= 16 chars), or set AUTH_DEBUG_MODE=true for local use."
                )
        return self


@lru_cache()
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


