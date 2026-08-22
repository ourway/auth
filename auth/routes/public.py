"""Public, unauthenticated routes plus the /api/* authentication gate."""

import logging

from flask import abort, g, jsonify, request
from sqlalchemy import text

from auth.database import engine
from auth.validation import (
    validate_client_key,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register the public routes on ``app``."""

    @app.before_request
    def _authenticate_api():
        """Authenticate every /api/* request before any audit or DB work.

        Runs ahead of each route's ``@with_db_session``/``@audit_log`` chain so
        that unauthenticated or malformed requests are rejected without opening a
        database session or writing an audit row. Public routes (/ping, /health,
        the docs pages) and CORS preflight are exempt.
        """
        if request.method == "OPTIONS":
            return None
        if not request.path.startswith("/api/"):
            return None

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            abort(401, description="Authorization header is missing.")

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            abort(
                401,
                description="Invalid Authorization header format. Must be 'Bearer <token>'.",
            )

        client_key = parts[1]
        if not validate_client_key(client_key):
            abort(400, description="Invalid client key. Must be a valid UUID4.")

        # Canonicalize to lowercase: a UUID4 is case-insensitive, but the raw
        # string is used verbatim as the tenant identifier AND the encryption KDF
        # input, so `3F6B...` and `3f6b...` would otherwise be two disjoint
        # namespaces with different keys. Store one canonical form.
        g.client_key = client_key.lower()
        return None

    @app.route("/ping", methods=["GET"])
    def ping():
        """Health check endpoint"""
        return jsonify({"message": "PONG"})

    @app.route("/health", methods=["GET"])
    def health():
        """Public liveness + database-readiness probe.

        Actually round-trips the database (``SELECT 1``) so it reports unhealthy
        when the DB is unreachable, instead of always claiming healthy. Returns
        no internal pool details — those are not the public probe's business.
        """
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            logger.exception("health check failed: database unreachable")
            return jsonify({"status": "unhealthy"}), 503
        return jsonify({"status": "healthy"})
