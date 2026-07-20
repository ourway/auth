"""
Flask application setup
"""

import logging

from flask import Flask
from flask_cors import CORS

from auth.audit import setup_audit_tables
from auth.config import get_settings
from auth.logging_config import setup_logging
from auth.workflow_checker import initialize_workflow_checker

setup_logging()

logger = logging.getLogger(__name__)


def create_app():
    # Create Flask app
    app = Flask(__name__)

    # Enable CORS according to configuration (default: all origins)
    settings = get_settings()
    if settings.allow_cors:
        raw_origins = settings.cors_origins or "*"
        if raw_origins == "*":
            CORS(app)
        else:
            CORS(app, origins=[origin.strip() for origin in raw_origins.split(",")])

    # Create tables on startup
    with app.app_context():
        from auth.database import create_tables
        create_tables()
        setup_audit_tables()  # Set up audit tables
        initialize_workflow_checker()  # Initialize workflow permission checker

    # Import and register routes
    from auth.docs_page import register_docs_routes
    from auth.routes import register_routes

    register_routes(app)
    register_docs_routes(app)

    @app.errorhandler(Exception)
    def _unhandled_exception(e):
        from werkzeug.exceptions import HTTPException

        if isinstance(e, HTTPException):
            # abort(...) and friends keep their existing responses
            return e

        from auth.response_format import APIResponse

        logger.exception("Unhandled exception while processing request")
        return APIResponse.server_error("An internal error occurred")

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    from auth.config import get_settings
    settings = get_settings()
    app.run(
        host=settings.server_host,
        port=settings.server_port,
        debug=settings.debug_mode
    )
