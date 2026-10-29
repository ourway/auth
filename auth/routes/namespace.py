from flask import request

from auth.audit import AuditAction
from auth.decorators import audit_log, record_outcome
from auth.response_format import APIResponse
from auth.routes._common import _get_auth_service, with_db_session


def register(app):
    @app.route("/api/namespace", methods=["GET"])
    @with_db_session
    @audit_log(AuditAction.GET_NAMESPACE, resource_extractor=lambda kwargs: "namespace")
    def get_namespace(db):
        summary = _get_auth_service(db).namespace_summary()
        return APIResponse.success(data=summary, message="Namespace summary")

    @app.route("/api/namespace", methods=["DELETE"])
    @with_db_session
    @audit_log(AuditAction.PURGE_NAMESPACE, resource_extractor=lambda kwargs: "namespace")
    def purge_namespace(db):
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) != {"confirm"}:
            record_outcome(refused=True, reason="confirm_required")
            return APIResponse.bad_request(
                'Send {"confirm": "<fingerprint>"}. GET /api/namespace shows the fingerprint.'
            )
        auth_service = _get_auth_service(db)
        fingerprint = auth_service.namespace_summary()["fingerprint"]
        if body["confirm"] != fingerprint:
            record_outcome(refused=True, reason="confirm_mismatch")
            return APIResponse.bad_request(
                "confirm does not match this namespace's fingerprint. "
                "GET /api/namespace shows it. Nothing was deleted."
            )
        deleted = auth_service.purge_namespace()
        record_outcome(**{k: v for k, v in deleted.items() if k != "fingerprint"})
        return APIResponse.success(data=deleted, message="Namespace purged")
