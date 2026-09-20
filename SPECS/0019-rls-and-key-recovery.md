# 0019 — Database-enforced tenant isolation (RLS) and issue-once key recovery

Ticket: issuedb #19 · Branch: `feat/rls-and-key-recovery` · Supersedes nothing;
follows from the findings in [0020](0020-adversarial-audit-2026-09.md).

## EARS spec

- The auth service shall enforce tenant isolation at the database layer, not only in application code.
- When a query omits its tenant filter, then the database shall return only the calling tenant's rows.
- When no tenant is bound to the session, then the database shall return no rows.
- The auth service shall apply FORCE ROW LEVEL SECURITY, because the application role owns the tables and PostgreSQL does not apply RLS to a table owner.
- When RLS is not in force at boot, the auth service shall log CRITICAL, refuse `/api` with 503 and report `/health` unhealthy, and shall not hard-crash.
- When a tenant binding is set, the auth service shall scope it to the current transaction, so that it cannot reach the next borrower of a pooled connection.
- When a new `audit_log` partition is provisioned, the database shall enable and force row level security on it.
- Where a tenant has never been issued a rotate key, the auth service shall issue one exactly once on request.
- If a rotate key has already been issued for a tenant, then the auth service shall refuse to disclose it again.
- When a valid rotate key is presented, the auth service shall move the namespace to a new client key and issue a new rotate key, each disclosed exactly once.
- If the client key named as a recovery target already owns rows, then the auth service shall refuse the recovery.
- The auth service shall not change the contract of any existing endpoint.
- The `GET /api/user_permissions/<user>` path shall cost no more than 1 ms additional p50 at 300 permission edges as a result of the junction policies. **Measured: +0.25 ms p50 (2.00 ms with policies, 1.75 ms bypassed, 300 rows both sides).**

## Technical problems

1. Tenant isolation as an invariant rather than a query convention — authorization under a discretionary access control the application cannot forget.
2. Carrying a caller identity into the database session safely under connection pooling.
3. Recovering a namespace whose only credential is lost, without weakening the credential model.
4. Detecting, at boot, that the isolation control is present but inert.

## Solution domains

- **(1)** PostgreSQL Row Level Security (the database's own manual). `FORCE` is mandatory because the application role owns the tables.
- **(1)** Generated columns (`GENERATED ALWAYS AS ... STORED`) for the tenant discriminator, so `creator` and `creator_fp` cannot drift.
- **(2)** `set_config(name, value, is_local => true)` plus a SQLAlchemy `after_begin` listener — the existing per-transaction hook pattern already used by `ServiceBase._lock_tenant`.
- **(3)** Bearer recovery credential, hashed at rest, issue-once — mirrors `auth/api_keys.py`'s existing `rak_` construction rather than a second secret generator.
- **(4)** The boot-check pattern already established by `auth/keycheck.py` for the encryption canary (#12).

## Alternatives

**Tenant discriminator on the RBAC tables**
- CHOSEN: `creator_fp text GENERATED ALWAYS AS (encode(sha256(creator::bytea),'hex')) STORED`.
- REJECTED: an application-maintained column — decided by the sync-bug class it creates; a generated column makes the bug impossible rather than unlikely.
- REJECTED: policies on `creator` directly, comparing the raw client key — decided by the requirement that the session variable and anything logging it must not be the credential.
- REJECTED: deriving the fingerprint from `AUTH_AUDIT_PEPPER` (as `client_fingerprint` does) — decided by blast radius: rotating that pepper already breaks audit reads (#11), and this would additionally lock every tenant out of their own rows.

**Carrying the tenant into the session**
- CHOSEN: `set_config(..., is_local => true)` re-applied by an `after_begin` listener.
- REJECTED: a plain `SET` at request start — decided by pooling: it persists on the connection and hands the next tenant the previous tenant's identity, i.e. the isolation mechanism becomes the leak. Falsified by `probe_rls_no_leak_across_pooled_connections`.
- REJECTED: a one-shot `SET LOCAL` at request start — decided by lifetime: library callers construct services with `manage_transaction=True` and commit per method, so the binding dies at the first commit and every later statement sees zero rows.

**Junction tables (`membership_groups`, `permission_groups`), which carry no tenant column**
- CHOSEN: `EXISTS` policy against the parent's `creator_fp`.
- REJECTED: denormalising `creator_fp` onto the junctions — decided by the sync-bug class again; admissible only if the measured cost had exceeded the 1 ms threshold above, which it did not (+0.25 ms p50).

**`audit_log` partitions**
- CHOSEN: `ENABLE` + `FORCE` with no policy of their own; the parent's policy governs reads through the parent, and a direct query matches nothing.
- REJECTED: a copy of the parent's policy on each partition — decided by drift: the predicate would live in a function that is not re-run when the parent's policy changes.

**Recovery credential**
- CHOSEN: a second bearer secret (`rrk_`), hashed at rest, disclosed exactly once, use audited; sufficient on its own to move a namespace.
- REJECTED: requiring the old client key as well — decided by the requirement: that is re-keying, which already exists, and cannot help someone who lost the key.
- REJECTED: an out-of-band operator-mediated recovery — decided by the fact that nothing is stored in plaintext, so no operator can identify whose namespace is whose.

**Target client key for recovery**
- CHOSEN: caller may supply it, but the namespace behind it must be empty.
- REJECTED: accepting any supplied key — decided by a hole this opened during implementation: a valid rotate key for namespace X could name a victim's client key as the target and merge X into it, gaining a credential the victim also holds.

## Verification

Probes in `audit/evaluations/`, all exercised against a real PostgreSQL container
as a non-superuser role that owns the tables (`make probe-postgres`):

| probe | asserts |
|---|---|
| `probe_rls_cross_tenant_isolation` | unscoped queries return only the bound tenant's rows; none when unbound; superuser control proves the rows exist |
| `probe_rls_forced_not_merely_enabled` | every table enabled+forced+policied, and the boot verifier goes red when FORCE is removed and green again when restored |
| `probe_rls_no_leak_across_pooled_connections` | the binding does not survive onto the next borrower of the same backend PID, with a bound control proving the statement can return rows |
| `probe_rls_covers_every_tenant_table` | the protected set is discovered from the database, so a table added later is not silently unprotected |
| `probe_rotate_key_recovery` | issue-once, refusal on re-request, namespace moves, non-empty target refused |
| `probe_encryption_key_canary` | the sentinel canary still detects a changed key with RLS in force |

## Not done / known limits

- RLS closes the "forgot `.filter(creator==)`" class. It does not stop a *wrong*
  tenant being bound, and it does not make authentication stronger.
- `pgadmin` is superuser and bypasses RLS entirely. Admin and migration paths are
  unprotected by design.
- A tenant who never claimed a rotate key and then loses the client key is still
  unreachable — unchanged from before, and the reason `get_rotate_key` needs
  announcing to consumers.
- The junction-policy cost was measured on a synthetic 300-edge namespace on one
  container, not under production concurrency.

## Found while implementing, fixed here

- **A fresh database came up with the junction tables unprotected.** Only five
  tables are created by migrations; `membership_groups`, `permission_groups` and
  `audit_log` are created by the ORM at first boot, *after* migrations, so the
  RLS migration correctly found them absent and skipped them. Fixed by moving
  the same DDL into `auth_rbac.apply_tenant_rls()` and calling it from
  `create_tables` once the ORM has finished.
- **The boot check could not tell "unprotected" from "absent"**, so it reported
  the remaining tables forced and passed. It now fails closed on a missing table.
- **A failure in one startup reconciliation skipped the rest.** `_grandfather_
  strict_users` raised under RLS and aborted the block before RLS was applied.
  The steps are now ordered with RLS first.
- **Grandfathering cannot run under RLS at all** — it is a cross-tenant pass and
  the app role can no longer see another tenant's settings row. On PostgreSQL the
  `grandfather_strict_users` migration owns it; the boot pass now stands aside
  there and still runs for embedded SQLite consumers.
- **New `audit_log` partitions were created with no RLS.** `provision_audit_log_
  partition` predates this work; a partition it created could be queried directly
  for every tenant's entries. Reproduced live (tenant `deadbeef` read `cafebabe`'s
  rows via `audit_log_2029_03`), then fixed and re-verified.
- **`verify_row_level_security` reported `ok` with FORCE removed.** Two causes:
  the later encryption check overwrote its verdict, and the query filtered on
  `current_schema()` rather than the configured schema. Both fixed; the verdict
  is now sticky and `probe_rls_forced_not_merely_enabled` asserts both directions.

## Out of scope, filed separately

`audit_log` is never partitioned on a database built from migrations alone
(issuedb #20) — the same ORM-after-migrations ordering, but a retention problem
rather than an isolation one. An existing deployment is unaffected.
