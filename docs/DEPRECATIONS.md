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

**Timeline — completed**

| Phase | Version | Behavior |
|---|---|---|
| Done | 2.4.0 | Nothing enforced. Issue keys, migrate backends to the validate flow. |
| Done (opt-in) | 2.5.x | Per-tenant strict mode via `PUT /api/settings` `{"strict_users": true}`; `POST /api/apikeys/check_permission` does validate + permission in one round trip. Since 2.5.1, a membership ADD refused for a key-less subject answers **HTTP 409**. |
| **SHIPPED** | 3.0.0 | Strict mode is the **default for tenants with no stored setting** (`AUTH_STRICT_USERS_DEFAULT`, true). **Flip mechanics: every creator existing before 3.0.0 was grandfathered with an explicit `strict_users: false` row** — written by migration in our deployment and by a one-shot, marker-guarded pass in `create_tables()` on embedded databases — so the flip reaches ONLY tenants created after 3.0.0. The per-tenant opt-out survives as a first-class, audited setting; machine-subject architectures hold it false indefinitely. Embedded consumers not yet key-backed may also set `AUTH_STRICT_USERS_DEFAULT=false` process-wide. |

**Which endpoints strict mode gates — exact list** (asked by consumers; this is the
contract): decisions are gated — `has_permission`, the membership check,
`user_permissions` (a key-less subject answers `count: 0` with the reason), workflow
`can_run`, and membership ADDs (409 since 2.5.1). Listings are NOT gated —
`user_roles`, `members`, `roles`, `which_users_can`, `which_roles_can`, key listings.
Deletes/revocations are never gated anywhere. **Consumers must check `result` on
membership writes** — ignoring it converts strict mode into silent dead-key
provisioning (two consumers found this trap in their own code; the 409 exists so
status-only callers fail loudly too).

**Bootstrap ordering is a contract:** one transactional store, no cache and no eventual
consistency in the strict check. `POST /api/apikeys/user/<user>` returns success only
after the key row commits; a subsequent membership write or decision check — same
request or later — sees the key.

**The `reason` field is stable contract.** `"user_not_key_backed"` will not be renamed,
dropped, or re-scoped short of a major version with its own bus-notice-and-confirm
cycle. It appears ONLY on strict blocks — a key-backed user lacking a permission stays
a plain denial — so it is the one signal separating "strict mode changed the answer"
from "this user genuinely has no entitlements". Note that strict mode adds a NEW,
per-user cause to what was previously a deploy-time-only silent path (missing role):
check `result` and `reason` on writes, always.

**A strict block on read decisions is an HTTP 200.** It is not a transport failure, not
a 4xx, not an exception — retries, circuit breakers, and stale-cache fallbacks will NOT
fire on it. If your tenant deliberately holds `strict_users: false`, your safety rests
on that one remote boolean: assert `GET /api/settings` → `strict_users: false` in your
deploy verification and health checks, so an unexpected flip surfaces as an alarm
rather than as every customer simultaneously losing entitlements.

Spec: `SPECS/0008-strict-user-identity.md` · ticket auth#13. Enforcement deploys only
after all client confirmations are on the ticket ledger.

## 2. Python client: legacy transport-failure error dict (target: 3.0.0)

**Old method (deprecated):** on transport failure, client methods return
`{"error", "success": False, "data": {…inputs…}}` — answer-shaped, minus the answer
field, so unchecked readers turn outages into denials.

**New method (available since 2.4.0):** `Client(..., raise_on_error=True)` raises
`auth.AuthTransportError`; legacy payloads now carry `"transport_error": true`.

**SHIPPED in 3.0.0:** raising is the only behavior; the error-dict return is removed.
The `raise_on_error` constructor argument remains accepted as a deprecated no-op so 2.x
constructor calls keep working. The REST API is unaffected — this is client-library
behavior when the service is unreachable.

Spec: `SPECS/0007-decomm-legacy-transport-errors.md` · ticket auth#12. Same
all-consumers-confirm gate, tracked independently of deprecation 1.

## 3. Embedded databases created before 2.x: narrow `varchar` columns (auto-reconciled in 3.0.1)

**Applies to:** embedded consumers only (you call `create_tables()` against your own
PostgreSQL). Hosted REST consumers are unaffected.

`Base.metadata.create_all(checkfirst=True)` creates missing tables but **never ALTERs an
existing one**. A database first created by a pre-2.x version therefore keeps the narrow
`varchar` widths that version declared, even though the current models declare `Text` for
those columns. Encryption made several of them hold ciphertext considerably longer than
the plaintext they used to, so the mismatch surfaces at write time as
`StringDataRightTruncation` — most visibly on `auth_membership.user` inside
`add_membership`, when a longer identifier is encrypted.

**SHIPPED in 3.0.1:** `create_tables()` now runs a reconciliation pass that widens live
`character varying` columns to `TEXT` wherever the current model metadata declares `Text`.
It is idempotent (a matching database gets no `ALTER`s), PostgreSQL-only (SQLite does not
enforce varchar length), schema-aware, and non-raising — a runtime role without DDL rights
logs the failure and still starts.

Columns whose models declare a **bounded** `String` are deliberately left alone.
`audit_log.user` stays `varchar(64)`: it stores a fitted fingerprint, not a user
identifier, and widening it would erase an intentional bound.

If your runtime role lacks DDL rights, apply the equivalent by hand once, as a DBA:

```sql
ALTER TABLE auth_membership ALTER COLUMN "user" TYPE TEXT;
```

…and likewise for any column the startup log names in its
`could not widen …` warning.

Reported by highway (agent-mail `thr-d99bb6c79b894ff69f16`) after reconciling seven such
columns by hand. Spec: `SPECS/0014-text-column-reconciliation.md` · ticket auth#21.
