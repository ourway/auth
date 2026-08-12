# SPEC — Self-service audit + actionable strict_users 409

**Ticket:** issuedb #2 (auth repo)
**Status:** in-progress
**Date:** 2026-08-12

## EARS requirements

1. When a client presents a valid namespace key to `GET /api/audit`, the system
   shall return that namespace's own audit-log entries, newest first, and shall
   never return another namespace's entries.
2. When a `limit` or `offset` query parameter is provided to `GET /api/audit`,
   the system shall paginate the returned entries accordingly (default limit 50,
   max 500).
3. When an `action` query parameter is provided to `GET /api/audit`, the system
   shall return only entries whose action matches.
4. When `POST /api/membership/{user}/{role}` is refused because strict user
   identity is enabled and the user has no API key, the system shall return
   HTTP 409 with `reason: user_not_key_backed` AND a `hint` naming the two ways
   forward (create an API key, or opt the namespace out via
   `PUT /api/settings {"strict_users": false}`).
5. The audit endpoint shall return no raw client key, no raw user identifier,
   and no audit pepper; client and user fields shall remain non-reversible
   fingerprints.

## Context

Two real gaps surfaced during the 2026-08-12 registry + runflow incidents:

- **No self-service diagnosis.** Auth has no audit/diagnostic API — the audit
  trail is DB-only. A client hitting an unexpected denial cannot ask auth *why*
  (who granted/revoked what, when). The registry's 403 incident escalated into a
  multi-party "auth must be broken" hunt for what turned out to be a client-side
  credential mistake, because nobody could query auth's own record.
- **Undiscoverable opt-out.** `strict_users` defaults to true for new namespaces;
  the `409 user_not_key_backed` error does not name the fix, so new integrators
  are blocked with no discoverable path to `PUT /api/settings
  {"strict_users": false}`. Hit by runflow (issuedb #90) and futex (FTX-96).

## Verification

Before closing: exercise both endpoints against the deployed public path
(`https://auth.rodmena.co.uk`) — `GET /api/audit` returns only the caller's
namespace and a strict-mode membership grant answers 409 with `reason` + `hint`.
