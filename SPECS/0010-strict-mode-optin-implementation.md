# SPEC 0010 — 2.5.0 opt-in strict user identity (implementation of SPEC 0008 phase 1)

- **Ticket:** issuedb #15 — "Implement + deploy 2.5.0: opt-in strict user identity,
  tenant settings, check_permission endpoint (phase 1 of SPEC 0008)"
- **Scope guard:** opt-in ONLY. Tenants that never touch `/api/settings` are
  byte-identical to 2.4.1. The 3.0.0 default flip (the actual decommission) remains
  gated on the SPEC 0008 all-clients confirmation ledger (issuedb #13).

## EARS requirements

1. The service shall store per-tenant settings in a new `auth_tenant_settings` table
   (`creator` unique, `strict_users` bool default false), created by a migretti
   migration mirroring the SQLAlchemy model (`IF NOT EXISTS`, converges with
   `create_all` in either order).
2. The service shall expose `GET /api/settings` (current settings; defaults when no
   row exists) and `PUT /api/settings` with JSON `{"strict_users": <bool>}` — an
   audited upsert taken under the tenant advisory lock.
3. While a tenant's `strict_users` is true, when `has_permission`, the membership
   check, `user_permissions`, workflow `can_run`, or a membership add is asked about a
   user with no active, unexpired API key, the service shall answer negatively in the
   existing response shape with additive reason `user_not_key_backed`.
   *(Refined in 2.5.1, issuedb #16, after independent reports from sponsorsignal and
   runflow: the membership-ADD refusal answers HTTP **409** with
   `{"result": false, "reason": "user_not_key_backed"}` so status-only callers cannot
   read a refused grant as success. Read-decision shapes are unchanged; non-strict
   tenants are unchanged, including the documented missing-role 200-false.)*
4. When `strict_users` is false or unset, all behavior shall be byte-identical to
   2.4.1.
5. The service shall expose `POST /api/apikeys/check_permission` with JSON
   `{"api_key", "permission"}`: an invalid key answers `{valid: false, reason}`; a
   valid key answers `{valid: true, user, key_id, has_permission}` in one round trip,
   with the secret never in a URL.
6. Key rotation shall migrate the `auth_tenant_settings` row (a strict tenant stays
   strict under its new key), and the rotate response's `migrated` object shall gain
   an additive `settings` count.
7. `AuthorizationService` shall accept `strict_users: Optional[bool]` — `None` reads
   the tenant's stored setting; an explicit bool overrides it for in-process/library
   callers, whose default behavior is unchanged.
8. The release shall deploy only after hosted CI is green; live probes shall exercise
   strict mode in both directions (blocks a keyless user AND releases after key
   issuance and after disabling); PyPI updates only after the live service verifies.
9. When deployed, a fix-notice announcing availability (opt-in only; decommission
   still gated on confirmations) shall be sent to all bus platforms.

## Notes

- Enforcement is at decision points only; configuration listings stay unfiltered
  (SPEC 0008 req 5). Bare-shape endpoints gain the additive `reason` key only when
  strict-blocked.
- `check_permission` also delivers the single-round-trip pattern runflow asked about
  (SPEC 0006 adjacent — does not close #11, which asks for arbitrary batch sets).
- Additive `migrated.settings` is the same declared-delta class as `migrated.api_keys`
  in 2.4.0: field-based readers unaffected; docs example updated in the same commit.
