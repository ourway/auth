# SPEC 0004 — Per-user API keys (`/api/apikeys/*`)

- **Ticket:** issuedb #9 — "Per-user API-key lifecycle: create/list/revoke/validate under /api/apikeys/*"
- **Model:** additive registry · server-generated `rak_` secrets, SHA-256 at rest, shown once ·
  tenant-scoped validate · per-user keys do NOT authenticate auth's own `/api/*` gate
- **Consumer context:** the identity platform's UI fronts create/list/revoke; backend services
  call validate with their own tenant bearer, then use existing RBAC checks. Identity and those
  backends must share one tenant key (they already must, for RBAC to line up).

## EARS requirements

1. The auth service shall expose four tenant-authenticated endpoints: `POST /api/apikeys/user/<user>`
   (create), `GET /api/apikeys/user/<user>` (list), `DELETE /api/apikeys/user/<user>/<key_id>`
   (revoke), `POST /api/apikeys/validate` (validate), each authenticated solely by the caller's
   existing client key in `Authorization: Bearer` and scoped to that tenant's namespace.
2. When a valid tenant calls create for a user matching `USER_NAME_PATTERN`, the service shall
   generate a server-side secret `rak_` + 43 base62 chars (~256-bit), persist only its SHA-256
   hex digest plus a display prefix, and return the raw secret exactly once in the creating
   response; the raw secret shall never be persisted, logged, or audited.
3. When validate receives JSON `{"api_key": ...}` whose hash matches an active, unexpired key of
   the calling tenant, the service shall return `valid: true` with the key's user, key_id, label,
   and expires_at.
4. If a validated key is revoked, expired, unknown, or belongs to a different tenant, then the
   service shall return HTTP 200 with `valid: false` and reason `revoked|expired|unknown_key`,
   where a foreign tenant's key is indistinguishable from an unknown key.
5. If an API-key secret would appear in a URL path, then the service shall not accept it there;
   secrets travel only in JSON bodies (request-line logging in gunicorn/nginx must never see one).
6. When revoke is called for an existing (tenant, user, key_id), the service shall set
   `is_active=false` and `revoked_at`, shall be idempotent on repeats, and shall return 404 only
   when no such row exists in the caller's namespace.
7. The service shall cap active keys at 25 per (tenant, user); create beyond the cap shall return
   400, and revoking a key shall restore the ability to create.
8. While `AUTH_ENABLE_ENCRYPTION` is true, the service shall store `auth_api_key.user` and
   `.label` field-encrypted under the tenant's derived key, equality-queryable, exactly as
   existing encrypted columns.
9. When a tenant rotates its client key (`POST /api/keys/rotate`), the service shall migrate all
   `auth_api_key` rows to the new creator (re-encrypting encrypted cells) in the same transaction,
   shall leave `key_hash`/`key_id` unchanged so end-user secrets keep validating, and the rotate
   response's `migrated` object shall gain an additive `api_keys` count.
10. Create, list, revoke, and validate shall each write one audit record (`CREATE_API_KEY`,
    `LIST_API_KEYS`, `REVOKE_API_KEY`, `VALIDATE_API_KEY`) with fingerprinted identifiers and no
    raw secret material.
11. The feature shall be additive: no existing route's path, method, request shape, response
    shape, or status semantics changes except the additive `migrated.api_keys` field; the
    `/api/*` authentication gate remains byte-identical.
12. The schema change shall ship as the project's first migretti migration (Alembic retired to a
    legacy path), with SQL mirroring the SQLAlchemy model so `create_all(checkfirst=True)` and
    `mg apply` converge in either order.

## Notes

- Routes nest user segments under a static `user/` component so users literally named `validate`,
  `rotate`, or `user` can never collide with static routes (Werkzeug prefers static rules —
  nesting removes the shadowing hazard by construction, not by precedence).
- SHA-256 without pepper is deliberate: the audit-pepper chain is mutable
  (`AUTH_AUDIT_PEPPER` → `AUTH_JWT_SECRET_KEY` fallback) and a pepper change must never
  invalidate every stored key; at 256-bit server-generated entropy, offline brute force against
  a leaked hash is not a threat. `key_hash` excludes the creator so tenant rotation preserves it.
- `expires_at` is honored by validate but v1 exposes no TTL API (column reserved to avoid a
  second migration); `last_used_at` is touched at most once per 60s per key.
- Two new JSON-body-reading endpoints (validate always; create's optional `{"label": ...}`) are
  the first in the API — justified by requirement 5 and by labels being free-ish user text.
- 25-key cap exists to bound namespace abuse; tested in both directions (26th blocked, create
  resumes after a revoke).
