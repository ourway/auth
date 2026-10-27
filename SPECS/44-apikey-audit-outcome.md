# #44 Audit key_id and outcome on API-key entries

issuedb #44. Release 3.7.0. Requested by vellum-build (thread 01M5XVVFMPJZ7F5YWNWPXKVSGA).

EARS SPEC:
- When a per-user API key is created, the audit entry shall carry its key_id.
- When a key is validated or checked, the audit entry shall carry the key_id when the key resolves in the namespace, the outcome (valid, reason, has_permission and permission name) and success=false when the key was refused.
- The audit entry shall never carry the secret or its hash.

EVIDENCE: live 2026-10-27, CHECK_API_KEY_PERMISSION for a revoked key recorded resource "api_key", success true, details {"status_code": 200}; CREATE_API_KEY resource is the user fingerprint without key_id. Requested by vellum-build (thread 01M5XVVFMPJZ7F5YWNWPXKVSGA).
SYNTHESIS: deferred to start; awaiting director ordering.

SYNTHESIS (localized, no new component): domain = audit trail of authentication decisions; concept = record the resolved subject id and the decision outcome, never the credential. ALTERNATIVES: routes pass outcome facts to the existing audit_log decorator via flask g [CHOSEN: the decorator stays the single writer, and the API responses do not change] vs adding key_id to the API response of refused keys [REJECTED: changes the public contract for an audit need] vs a second audit write in the route [REJECTED: two rows per request]. key_id is recorded only when the key belongs to the caller's namespace, so another tenant's key leaves no trace of its existence.

## Measured

- tests/test_apikey_audit_outcome.py: 6 cases through /api/audit. Against the 3.6.0 code, 5 fail. The sixth, that no secret or hash is recorded, guards a property that already held.

## Synthesis

- Domain: the audit trail of authentication decisions. Concept: record the resolved subject id and the decision outcome, never the credential.
- ALTERNATIVES: routes pass outcome facts to the existing audit_log decorator through flask g [CHOSEN: the decorator stays the single writer, and API responses do not change] vs adding key_id to the response for refused keys [REJECTED: changes the public contract for an audit need] vs a second audit write in the route [REJECTED: two rows per request].
- key_id is recorded only when the key belongs to the caller's namespace, so another tenant's key leaves no trace of its existence.
