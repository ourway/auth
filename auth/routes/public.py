"""Public, unauthenticated routes plus the /api/* authentication gate."""

import logging
import threading

from flask import abort, g, jsonify, request
from sqlalchemy import text

from auth import keycheck
from auth.database import engine
from auth.validation import (
    validate_client_key,
)

logger = logging.getLogger(__name__)


_COMMIT_PROBE_LOCK = threading.Lock()
_last_commit_verdict = ["ready"]


def _pool_depth():
    """Connection-pool saturation. Needs no database round trip.

    Rises through slow-but-working and keeps rising through stalled, so it
    detects the condition a timeout-based probe can only flap around.
    """
    try:
        # QueuePool only; SQLite uses a pool without these counters.
        pool = engine.pool
        return {
            "size": pool.size(),  # type: ignore[attr-defined]
            "checked_out": pool.checkedout(),  # type: ignore[attr-defined]
            "overflow": pool.overflow(),  # type: ignore[attr-defined]
        }
    except Exception:
        return None


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
        # Recovery authenticates with the rotate key, in the body. Demanding a
        # client-key Bearer here would make the endpoint useless to the only
        # caller it exists for: someone who has lost theirs.
        if request.path == "/api/keys/recover":
            return None

        # Fail closed and LOUDLY when the encryption key cannot read our own
        # data. Serving would answer every authorization question negatively
        # with a 200, which a caller cannot distinguish from a real denial.
        if keycheck.is_degraded():
            abort(503, description=f"Service degraded: {keycheck.detail()}")

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
        if keycheck.is_degraded():
            return jsonify({"status": "unhealthy", "reason": keycheck.detail()}), 503
        return jsonify({"status": "healthy"})

    @app.route("/readyz", methods=["GET"])
    def readyz():
        """Readiness: can this instance actually COMMIT?

        ``/health`` round-trips a ``SELECT``, which a database keeps serving
        happily while its commit path is stalled — the failure mode actually
        observed on this deployment. ``statement_timeout`` does not bound
        COMMIT either, so nothing else notices.

        SINGLE-FLIGHT, deliberately. Only one commit probe runs at a time and
        concurrent callers get the last settled verdict. A bounded socket
        timeout was considered and rejected: killing the probe's socket does
        not kill its work — the backend finishes the flush and only notices the
        departed client afterwards — so a scrape across a six-minute stall
        would leave dozens of orphaned backends queued on the very fsync path
        being measured. (crypto-trader-platform-c429b3 established this.)

        ``pool`` is reported alongside and needs no round trip at all: pool
        saturation rises through slow-but-working and keeps rising through
        stalled, with nothing to tune and nothing written to the fsync path.

        Flask serves HEAD for a GET route, so HEAD probes get the same status
        with an empty body.
        """
        if keycheck.is_degraded():
            return jsonify({"status": "unready", "reason": keycheck.detail()}), 503

        pool_depth = _pool_depth()
        if not _COMMIT_PROBE_LOCK.acquire(blocking=False):
            # A probe is already in flight — almost certainly stalled. Report
            # the previous verdict rather than adding another backend to the
            # queue we are trying to measure.
            body = {
                "status": _last_commit_verdict[0],
                "reason": "commit probe already in flight",
                "pool": pool_depth,
            }
            return jsonify(body), (200 if _last_commit_verdict[0] == "ready" else 503)
        try:
            with engine.begin() as conn:
                if conn.dialect.name == "postgresql":
                    # Forces XID assignment, so COMMIT writes and flushes a real
                    # commit record. A read-only transaction would not.
                    conn.execute(text("SELECT txid_current()"))
                else:
                    conn.execute(text("SELECT 1"))
            _last_commit_verdict[0] = "ready"
        except Exception:
            logger.exception("readiness check failed: commit path unavailable")
            _last_commit_verdict[0] = "unready"
            return jsonify({"status": "unready", "reason": "commit path", "pool": pool_depth}), 503
        finally:
            _COMMIT_PROBE_LOCK.release()
        return jsonify({"status": "ready", "pool": pool_depth})
