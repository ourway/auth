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


def _init_rate_limiter(app, settings):
    """Attach a Flask-Limiter to the app (best effort, defense in depth).

    Keyed by the client-key fingerprint when authenticated, else by remote IP;
    public endpoints are exempt. ``settings.ratelimit_storage_uri`` of
    ``memory://`` is per-worker — point it at redis:// for a shared limit across
    gunicorn workers. If flask-limiter is not installed the app still boots with
    limiting off (nginx remains the primary limiter).
    """
    try:
        from flask import request
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
    except ImportError:
        logger.error(
            "AUTH_ENABLE_RATE_LIMIT is set but flask-limiter is not installed; "
            "application-layer rate limiting is OFF."
        )
        return

    from auth.audit import client_fingerprint

    def _key():
        header = request.headers.get("Authorization", "")
        parts = header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return client_fingerprint(parts[1])
        return get_remote_address()

    limiter = Limiter(
        key_func=_key,
        default_limits=[settings.ratelimit_default],
        storage_uri=settings.ratelimit_storage_uri,
        headers_enabled=True,
    )
    limiter.request_filter(
        lambda: request.path
        in ("/ping", "/health", "/", "/docs", "/llms.txt", "/claude", "/opencode", "/codex")
    )
    limiter.init_app(app)


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

    # Application-layer rate limiting (defense in depth; nginx is the primary
    # limiter at the edge). Disabled unless AUTH_ENABLE_RATE_LIMIT is set.
    if settings.enable_rate_limit:
        _init_rate_limiter(app, settings)

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
