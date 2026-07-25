# SPEC 0001 — API-key rotation (`POST /api/keys/rotate`)

- **Ticket:** issuedb #1 — "API-key rotation endpoint (POST /api/keys/rotate)"
- **Model:** instant atomic cutover · server-generated new key · always available (no feature flag)

## EARS requirements

1. The auth service shall expose `POST /api/keys/rotate`, authenticated by the caller's current client key in the `Authorization: Bearer` header, and no other credential.
2. When a valid client key calls `POST /api/keys/rotate`, the service shall generate a fresh UUID4 `new_key`, atomically reassign every `auth_group`, `auth_membership`, and `auth_permission` row owned by the calling key (`creator = old_key`) to `creator = new_key`, and return `{ new_key, migrated: { roles, memberships, permissions } }` with HTTP 200.
3. While `AUTH_ENABLE_ENCRYPTION` is true, when rotating, the service shall decrypt each field-encrypted cell (`auth_membership.user`, `auth_permission.name`, `auth_group.description`) under the old key and re-encrypt it under the new key within the same transaction, so the new namespace remains equality-queryable.
4. The service shall perform the entire reassignment in a single database transaction; on any error it shall roll back leaving the old key's namespace unchanged, and shall never leave rows split across both keys as a committed state.
5. The service shall write exactly one `ROTATE_KEY` audit record linking the HMAC fingerprint of the old key to the HMAC fingerprint of the new key plus the migrated counts, and shall never persist either raw key in the audit trail.
6. If a caller supplies a key or places a key in a URL path, then the service shall not honor it; the new key shall be returned only in the response body of the rotating call, and no raw key shall be logged.
7. Rotation shall require no authorization beyond possession of the current key (threat: possession is full authority, including rotating the namespace away).

## Notes

- No DB migration: `ROTATE_KEY` is an app-level `AuditAction` enum value written to a `String(50)` column with no check constraint; `creator` is `VARCHAR(64)` and a UUID4 is 36 chars.
- Junction tables (`membership_groups`, `permission_groups`) carry no `creator` and key off row `id`, so their links follow the reassignment automatically.
- Concurrency: rotation and the mutating writes take a transaction-scoped, per-tenant PostgreSQL advisory lock (`pg_advisory_xact_lock(hashtext(creator))`), so a rotation cannot interleave with a concurrent write or another rotation for the same tenant — the scan-then-reassign pass sees a stable row set (no stranded insert, no clobbered update, no torn state). Residual (inherent to cutover): a write serialized *after* a rotation lands under the now-dead old key; clients switch to the returned key (the client library does so automatically), so operate under the new key once rotation returns.
- The `ROTATE_KEY` audit row is written in the SAME transaction as the reassignment (atomic); a failed rotation records a `success=false` `ROTATE_KEY` row.
