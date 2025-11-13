"""
Centralized configuration management for the authorization system
"""

import os
from dataclasses import dataclass
from enum import Enum

# Load environment variables from .env file if it exists
try:
    import os

    # Determine the project root directory based on the location of this file
    from dotenv import load_dotenv

    # Get the directory containing this config.py file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # The project root is one level up from the auth package directory
    project_root = os.path.dirname(current_dir)
    load_dotenv(os.path.join(project_root, ".env"))
    # Load test.env as fallback/override
    load_dotenv(os.path.join(project_root, "test.env"))
except ImportError:
    # python-dotenv is not required, just a nice-to-have
    pass


class DatabaseType(Enum):
    """Supported database types"""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


@dataclass
class Config:
    """Configuration class for the authorization system"""

    # Database settings
    database_type: DatabaseType = DatabaseType.SQLITE
    database_url: str = os.getenv("AUTH_DB_URL", "")
    sqlite_path: str = os.getenv("AUTH_DB_PATH", os.path.expanduser("~/.auth.sqlite3"))
    postgresql_url: str = os.getenv("POSTGRESQL_URL", "")

    # JWT settings
    jwt_secret_key: str = os.getenv(
        "JWT_SECRET_KEY", "default_secret_key_for_development"
    )
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_access_token_expire_minutes: int = int(
        os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "1440")
    )  # 24 hours
    jwt_refresh_token_expire_days: int = int(
        os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7")
    )

    # Security settings
    allow_cors: bool = os.getenv("ALLOW_CORS", "true").lower() == "true"
    cors_origins: str = os.getenv("CORS_ORIGINS", "*")
    enable_audit_logging: bool = (
        os.getenv("ENABLE_AUDIT_LOGGING", "true").lower() == "true"
    )

    # Server settings
    server_host: str = os.getenv("SERVER_HOST", "0.0.0.0")
    server_port: int = int(os.getenv("SERVER_PORT", "4000"))
    debug_mode: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Encryption settings
    enable_encryption: bool = os.getenv("ENABLE_ENCRYPTION", "false").lower() == "true"
    encryption_key: str = os.getenv("ENCRYPTION_KEY", "")

    def __post_init__(self):
        """Validate configuration after initialization"""
        if (
            not self.jwt_secret_key
            or self.jwt_secret_key == "default_secret_key_for_development"
        ):
            print(
                "WARNING: Using default JWT secret key. This should be changed for production!"
            )

        # Set database URL based on type if not explicitly provided
        if not self.database_url:
            if self.database_type == DatabaseType.SQLITE:
                self.database_url = f"sqlite:///{self.sqlite_path}"
            elif self.database_type == DatabaseType.POSTGRESQL:
                self.database_url = self.postgresql_url
        else:
            # If database_url is provided, detect database type from the URL
            if (
                self.database_url.startswith("postgresql://")
                or self.database_url.startswith("postgresql+psycopg2://")
                or self.database_url.startswith("postgresql+psycopg3://")
                or self.database_url.startswith("postgresql+pg8000://")
                or self.database_url.startswith("postgresql+asyncpg://")
            ):
                self.database_type = DatabaseType.POSTGRESQL
            elif self.database_url.startswith("sqlite:///"):
                self.database_type = DatabaseType.SQLITE


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance"""
    return config


def validate_config(config: Config) -> bool:
    """Validate the configuration"""
    if not config.jwt_secret_key:
        raise ValueError("JWT secret key is required")

    if config.enable_encryption and not config.encryption_key:
        raise ValueError("Encryption key is required when encryption is enabled")

    if config.database_type == DatabaseType.POSTGRESQL and not config.postgresql_url:
        raise ValueError("PostgreSQL URL is required when using PostgreSQL database")

    return True
