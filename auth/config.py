"""
Centralized configuration management for the authorization system
"""

import os
from enum import Enum
from functools import lru_cache

from pydantic import Field, model_validator
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
        env_file=".env", env_file_encoding="utf-8", extra="ignore", env_prefix="AUTH_"
    )

    # Database settings
    database_type: DatabaseType = DatabaseType.SQLITE
    database_url: str = Field("", validate_default=True)
    sqlite_path: str = Field(default="~/.auth.sqlite3")
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

    # Strict user identity (SPEC 0008/0012). Applies ONLY to tenants with no
    # auth_tenant_settings row: 3.0.0 defaults them to strict (key-backed
    # users required for authorization decisions). Tenants existing before
    # 3.0.0 are grandfathered with explicit false rows (migration +
    # create_tables pass), so this reaches new tenants only. Embedded
    # consumers not yet key-backed can set AUTH_STRICT_USERS_DEFAULT=false.
    strict_users_default: bool = True

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


def jwt_secret_is_weak(settings: "Settings") -> bool:
    """Whether the configured JWT signing secret is a known placeholder."""
    return settings.jwt_secret_key in _KNOWN_WEAK_SECRETS


def audit_pepper_is_weak(settings: "Settings") -> bool:
    """Whether the effective audit pepper is unset/placeholder/too short.

    The pepper is ``audit_pepper`` if set, else ``jwt_secret_key`` — the same
    fallback ``audit.client_fingerprint`` uses.
    """
    pepper = (settings.audit_pepper or settings.jwt_secret_key or "").strip()
    return pepper in _KNOWN_WEAK_SECRETS or len(pepper) < 16


_weak_secret_warnings_emitted = False


def warn_on_weak_secrets(settings: "Settings") -> None:
    """Warn (never raise) about weak server secrets, at most once per process.

    Call this from the paths that actually *use* these secrets — server boot and
    the embedded entry points — never from ``Settings`` construction. ``auth`` is
    also a client library: ``pip install auth; from auth import Client`` to talk
    to a remote service signs no JWTs and writes no audit rows, so these
    warnings are unactionable for such a consumer. Emitting them at import time
    put two secrets-shaped lines in every REST consumer's boot logs, where they
    read as *that consumer's* misconfiguration and train operators to ignore
    secret warnings (tokengate report thr-b7e8b0c2c7914d56b6f1, runflow note
    thr-44794b4bbb6448c2bc01).

    The hard, fail-closed pepper check remains :func:`verify_audit_pepper`.
    """
    global _weak_secret_warnings_emitted
    if _weak_secret_warnings_emitted:
        return
    _weak_secret_warnings_emitted = True

    import logging

    logger = logging.getLogger(__name__)
    if jwt_secret_is_weak(settings):
        logger.warning(
            "AUTH_JWT_SECRET_KEY is a weak/placeholder value. "
            "Set a strong secret for production."
        )
    if (
        settings.enable_audit_logging
        and not settings.debug_mode
        and audit_pepper_is_weak(settings)
    ):
        logger.warning(
            "AUTH_AUDIT_PEPPER is unset, a placeholder, or too short; audit "
            "key fingerprints are not offline-guess resistant. Set a strong "
            "value before serving traffic."
        )


def verify_audit_pepper(settings: "Settings") -> None:
    """Fail closed on a weak audit pepper — called when the SERVER starts.

    A placeholder pepper makes the audit trail's key fingerprints computable, so
    a server that writes audit rows must not run with one. Importing the package
    as a library is unaffected (see :func:`warn_on_weak_secrets`).
    """
    if settings.enable_audit_logging and not settings.debug_mode:
        if audit_pepper_is_weak(settings):
            raise ValueError(
                "Refusing to start: the audit pepper is unset, a placeholder, "
                "or too short. Set AUTH_AUDIT_PEPPER to a strong random value "
                "(>= 16 chars), or set AUTH_DEBUG_MODE=true for local use."
            )


@lru_cache()
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
