# 48. Namespace purge: DELETE /api/namespace and auth-admin

Ticket: issuedb #48. Release: 3.8.0.

Requested by the director on 2026-10-29. HR needs to erase a namespace when a customer leaves. l10n has one orphaned namespace known only by fingerprint 78408c2d4b71. Vellum and Casebound left test namespaces whose keys were never stored.

## EARS spec

Self-service (HR customer exit, test teardown):
- When a caller sends GET /api/namespace, the auth service shall answer with the namespace fingerprint (first 12 hex of sha256 of the key) and the number of roles, permissions, memberships, per-user API keys, and whether settings and a recovery key exist.
- When a caller sends DELETE /api/namespace with body {"confirm": "<that fingerprint>"}, the auth service shall delete every role, permission, membership, role link, per-user API key, the settings row and the recovery key of that namespace in one transaction, and answer 200 with the deleted counts.
- If confirm is missing, malformed or names another fingerprint, then the auth service shall answer 400 and delete nothing.
- The auth service shall record a PURGE_NAMESPACE audit entry with the deleted counts, and shall keep the namespace's existing audit entries.
- When a namespace has been purged, every former per-user key shall validate as unknown_key, the former recovery key shall not recover, and the same client key shall open an empty namespace with the server's strict_users default.
- If a purge fails part way, then the auth service shall roll back and leave the namespace unchanged.
Operator (orphans whose key nobody holds):
- When an operator runs auth-admin namespaces list, the tool shall print one line per namespace: fingerprint prefix (16 hex), counts per kind, role names, first created and last modified time, and shall never print a client key, user name or any decrypted value.
- When an operator runs auth-admin namespaces purge --fp P --confirm P with P of at least 12 hex matching exactly one namespace, the tool shall purge it through the same service code as DELETE /api/namespace, bound to that tenant under row level security, and record the PURGE_NAMESPACE audit entry marked as an operator action.
- If P matches no namespace or more than one, or --confirm differs from --fp, then the tool shall purge nothing and exit non-zero.
- The tool shall read the cross-tenant listing through AUTH_ADMIN_DATABASE_URL only, refuse a non-PostgreSQL URL, and never echo a database URL.
Quality: a purge of a namespace with 1,000 rows shall complete in under 2 s on the production database; no new endpoint shall be reachable without a valid namespace key.

## Technical problems

1. Tenant-scoped bulk erasure with referential integrity (association tables before parents) inside one transaction.
2. Operator discovery of tenants without their credential, under forced RLS.
3. An audit record for an erasure whose subject no longer exists.
4. Confirmation that ties a destructive call to one specific tenant.

## Solution domains

- Erasure: the existing service layer and tenant lock (codebase pattern), RLS binding by creator_fp (auth/rls.py).
- Discovery: PostgreSQL role privileges (BYPASSRLS / superuser) used read-only for listing; the action itself goes through the app role.
- Audit: existing AuditLog writer; audit rows are append-only and retained.
- Confirmation: fingerprint echo, the same idea as typing a resource name to delete it.

## Alternatives

- Erasure path: service-layer purge under the tenant's own RLS binding [CHOSEN]: same code for API and operator, RLS still enforced on the write. Raw SQL DELETE by creator_fp from the operator tool [REJECTED: bypasses the audit and the service invariants; CLAUDE.md forbids direct writes]. Tombstone / soft-delete flag [REJECTED: HR needs erasure, and a flag leaves the data].
- Operator discovery: privileged read for listing only, then act as the tenant [CHOSEN]. SECURITY DEFINER SQL function [REJECTED: a migration-owned privilege surface inside the app database that the app role could call]. No operator path at all [REJECTED: l10n, Vellum and Casebound orphans are unreachable otherwise].
- Confirmation: fingerprint prefix [CHOSEN: binds to one namespace]. Literal word 'purge' [REJECTED: a loop over keys would purge all of them]. No body [REJECTED: one stray DELETE erases a tenant].
- Audit: keep existing entries [CHOSEN: the record of what happened, needed for deletion certificates]. Delete them too [REJECTED: destroys the evidence of the purge itself; retention is a separate policy].

## Notes from implementation

- `DELETE /api/role` only marks a role inactive and leaves its rows, so the purge hard-deletes every row by `creator`, link tables first.
- `auth-admin namespaces list` also shows the time of each namespace's last audit entry. The tool holds the creator in memory, derives the audit fingerprint with the server pepper, and reads `max(timestamp)` from `audit_log`. It is the best available sign that a namespace is abandoned. The creator is never printed.
- On PostgreSQL the application role sees no rows when listing across namespaces, because no tenant is bound and row level security filters everything. A test asserts this, and that the privileged connection does list the namespace.
- The rollback test lives in the PostgreSQL suite. On SQLite a failed write holds the database lock while the audit decorator's failure path opens its own session, which then waits out the busy timeout. That is existing behaviour of the audit path on SQLite.
