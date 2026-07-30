# SPEC 0008 — Strict key-backed user identity (decomm of bare user strings)

- **Ticket:** issuedb #13 — "Decommission bare user strings: strict key-backed user
  identity (opt-in 2.5.0, default 3.0.0) — gated on ALL client confirmations"
- **Status:** PLANNED + documented; deprecation notice sent to all 10 bus platforms
  2026-07-31. **Nothing deploys until every platform confirms** (ledger on the ticket).
- **Intent:** after 3.0.0, "clients always need a user" — every authorization subject
  must be backed by a validated per-user API key (SPEC 0004). A bare `<user>` string
  with no active key behind it stops answering positively anywhere.

## EARS requirements

1. While the decommission is pending client confirmations, the service shall answer
   user-scoped authorization checks for bare (non-key-backed) user strings unchanged.
2. Where a tenant has enabled strict user identity (2.5.0 opt-in, stored in a new
   `auth_tenant_settings` row), when an authorization decision endpoint
   (`has_permission`, membership check, workflow `can_run`, `user_permissions`) is asked
   about a user with no active, unexpired API key, the service shall answer negatively
   in the unchanged response shape with an additive reason `user_not_key_backed`.
3. Where strict mode is enabled, when a membership is added for a user with no active
   key, the service shall return the established `200 {"result": false}` no-op answer
   (bootstrap order becomes: `create_api_key` first, then memberships).
4. The service shall provide `POST /api/apikeys/check_permission` accepting
   `{"api_key", "permission"}` and returning validation plus the key-subject user's
   effective permission answer in one round trip, with the secret never in a URL. It
   ships with the opt-in phase and is the recommended backend pattern (also halves the
   validate→check round trips; see runflow's SPEC 0006 request).
5. Strict-mode enforcement shall apply at decision points only; configuration listings
   (`members`, `roles`, `which_users_can`, key listings) shall remain unfiltered.
6. In-process/library callers shall receive an explicit `strict_users` parameter,
   default `False` throughout 2.x, with the flip documented as part of the 3.0 major.
7. When every platform on the bus has confirmed readiness, auth 3.0.0 shall enable
   strict user identity by default for HTTP tenants, decommissioning bare-user-string
   authorization.
8. The deprecation shall be documented (README, changelog, `docs/DEPRECATIONS.md`,
   served docs) before any enforcement ships, and no enforcement shall deploy before
   requirement 7's confirmations are all recorded.

## Design notes (for the 2.5.0 implementation ticket when it opens)

- **Tenant settings storage:** new `auth_tenant_settings` table (`creator` unique,
  `strict_users` bool, timestamps) — second migretti migration; toggle via an
  authenticated endpoint (e.g. `PUT /api/settings` `{"strict_users": true}`), audited.
- **"Key-backed" predicate:** user has ≥1 `auth_api_key` row with `is_active` and not
  expired, same tenant — one indexed lookup on `(creator, user)`.
- **Rollout:** 2.5.0 ships opt-in + `check_permission` (additive, deployable safely) —
  but per the standing instruction, even that does not deploy before the confirmations.
  3.0.0 flips the default; per-tenant opt-out during a grace window is a 3.0 decision
  recorded on the ticket.
- Revocation story becomes end-to-end: revoking a user's last key immediately turns
  their authorization answers negative in strict tenants.

## Relationship to other campaigns

- SPEC 0007 / issuedb #12 (client error-dict removal) is a separate, already-running
  confirmation campaign; both land in 3.0.0 but are gated independently.
