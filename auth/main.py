"""
Flask application setup
"""

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from auth.audit import setup_audit_tables
from auth.config import get_config
from auth.database import create_tables
from auth.workflow_checker import initialize_workflow_checker


def create_app():
    # Create Flask app
    app = Flask(__name__)

    # Get configuration
    config = get_config()

    # Configure rate limiting with optional Redis support
    # Use the rate_limit_storage_url from config which can be set via environment variable
    storage_url = config.rate_limit_storage_url
    if storage_url != "memory://" and storage_url.startswith("redis://"):
        # Use Redis storage with options
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["1000 per hour", "100 per minute"],
            app=app,
            storage_uri=storage_url,
            storage_options={"socket_connect_timeout": 30},
            strategy="fixed-window",
        )
    else:
        # Use in-memory storage
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["1000 per hour", "100 per minute"],
            app=app,
            storage_uri=storage_url,  # Use the configured storage URL even if it's memory://
        )

    # Enable CORS
    CORS(app)

    # Create tables on startup
    with app.app_context():
        create_tables()
        setup_audit_tables()  # Set up audit tables
        initialize_workflow_checker()  # Initialize workflow permission checker

    # Import and register routes
    from auth.routes import register_routes

    register_routes(app, limiter)

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    app.run()
