# SPEC 0011 — 2.5.2: caller sslmode honored, embedded strict surface, release hygiene

- **Ticket:** issuedb #17 — "2.5.2: honor caller sslmode (highway report), embedded
  strict passthroughs on Authorization wrapper, docs sweep, retro release tags"
- **Origin:** highway report `01KYTW2B5E15R9M64Z50X3MZW1` (thread
  `thr-7745c815fd0a425cabac`) + highway's three embedded-mode questions on auth#13.

## EARS requirements

1. When the caller's PostgreSQL URL carries an explicit `sslmode` query parameter, the
   engine factory shall honor it and never override it via `connect_args`.
2. When no URL `sslmode` is present and `PGSSLMODE` is set, the engine factory shall
   defer to it.
3. When neither is present, the factory shall default `sslmode=require` for genuinely
   remote hosts, decided by host-component comparison (not URL substring): a URL whose
   host is `localhost`/`127.0.0.1`/`::1` gets no forced sslmode; any other host does.
4. The `Authorization` in-process wrapper shall accept `strict_users`
   (None = tenant setting, bool = per-instance pin) and expose
   `get_settings`/`set_strict_users` and the per-user API-key lifecycle
   (`create_api_key`, `list_api_keys`, `revoke_api_key`, `validate_api_key`,
   `check_api_key_permission`), giving embedded consumers semantics identical to REST.
5. docs/API.md, ARCHITECTURE.md, SECURITY.md and README shall document the settings
   endpoints, `check_permission`, the strict gate list, the 409 refusal, and the
   sslmode precedence.
6. Releases 2.4.0, 2.4.1, 2.5.0 and 2.5.1 shall be retro-tagged at their build
   commits; 2.5.2 shall be tagged, released on GitHub, published to PyPI and deployed
   only after hosted CI is green.

## Notes

- Answers highway's embedded questions: enforcement lives in `AuthorizationService`
  (identical embedded/REST semantics; the 3.0.0 default flip therefore reaches
  embedded callers, with the same surviving opt-out); backfill = `create_api_key` per
  user (cap is per-user; the tenant advisory lock serializes; no HTTP rate limit
  applies in-process); machine subjects use the same mechanism with a clear label
  convention (`expires_at` is reserved, no TTL API yet).
