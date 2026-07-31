# Active deprecations

Authoritative list of contract changes announced to auth's consumers. Each is gated on
**explicit confirmation from every platform on the agent-mail bus** — nothing here ships
its breaking phase while any consumer is unconfirmed or blocked.

## 1. Bare user strings → key-backed user identity (target: 3.0.0)

**Old method (deprecated):** backends assert any `<user>` string in RBAC paths
(`/api/has_permission/<user>/<name>`, membership checks, workflow `can_run`, …) with
nothing behind it. auth answers purely from configured roles — it cannot tell a
validated identity from a typo or a forged one.

**New method (available since 2.4.0):** end users hold per-user API keys
(`/api/apikeys/*`). A backend receives `rak_…`, calls `POST /api/apikeys/validate`
(secret in the JSON body, never the URL), gets the key's user back, then runs the
permission checks — or, once 2.5.0 ships, does both in one round trip via
`POST /api/apikeys/check_permission`.

**Timeline**

| Phase | Version | Behavior |
|---|---|---|
| Done | 2.4.0 | Nothing enforced. Issue keys, migrate backends to the validate flow. |
| **Live (opt-in)** | 2.5.0 | Per-tenant strict mode via `PUT /api/settings` `{"strict_users": true}`: authorization decisions about a user with no active key answer negatively (`user_not_key_backed`, same response shapes); `POST /api/apikeys/check_permission` does validate + permission in one round trip. Tenants that don't opt in are byte-identical to 2.4.1. |
| Default | 3.0.0 | Strict mode becomes the **default**. The per-tenant opt-out (`PUT /api/settings` `{"strict_users": false}`) survives as a first-class, audited setting — resource servers that validate machine-subject credentials themselves (e.g. mail-api's keyed-hash subjects) may hold it false indefinitely. Ships only after all client confirmations. |

Spec: `SPECS/0008-strict-user-identity.md` · ticket auth#13. Enforcement deploys only
after all client confirmations are on the ticket ledger.

## 2. Python client: legacy transport-failure error dict (target: 3.0.0)

**Old method (deprecated):** on transport failure, client methods return
`{"error", "success": False, "data": {…inputs…}}` — answer-shaped, minus the answer
field, so unchecked readers turn outages into denials.

**New method (available since 2.4.0):** `Client(..., raise_on_error=True)` raises
`auth.AuthTransportError`; legacy payloads now carry `"transport_error": true`.

**In 3.0.0:** raising becomes the only behavior; the error-dict return is removed. The
REST API is unaffected — this is client-library behavior when the service is
unreachable.

Spec: `SPECS/0007-decomm-legacy-transport-errors.md` · ticket auth#12. Same
all-consumers-confirm gate, tracked independently of deprecation 1.
