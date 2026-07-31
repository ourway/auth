# Security

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR.
Email **farsheed.ashouri@gmail.com** with a description, reproduction steps, and
impact. You'll get an acknowledgement and a coordinated fix/disclosure.

## Supported versions

The latest released `2.x` line receives security fixes.

## Security model

`auth` is authorization-only and multi-tenant. The properties below are what the
service guarantees; the threat notes are what it deliberately does **not**.

### Identity & tenancy

- The **client key** is a UUID4 bearer token that *is* the tenant identity — it
  is not checked against a stored secret. Possession of a key is full authority
  over that namespace. Treat it like a password: keep it out of source control,
  logs, and URLs; scope one key per application.
- The key is canonicalized to lowercase at the edge, so case variants cannot
  fork a namespace or its encryption keys.
- **Tenant isolation**: every read and write is scoped by `creator == client key`.
  Junction rows are only ever created within a single tenant. No API path can
  read or mutate another namespace's data.

### Data protection

- **Field encryption at rest** (`AUTH_ENABLE_ENCRYPTION=true`, on in production):
  `membership.user`, `permission.name`, and `group.description` are encrypted
  with deterministic, authenticated, **per-tenant** encryption (AES-256-CTR,
  synthetic-IV `HMAC(hmac_key, plaintext)[:16]`, per-tenant HKDF keys). Identical
  plaintext in two tenants yields different ciphertext (no cross-tenant
  correlation). Reads **fail closed** — a tampered, corrupt, or wrong-tenant value
  is rejected, never returned as garbage.
- **No secret leakage**: the raw client key, encryption key, and JWT secret are
  never logged or returned. Failure logs carry only a non-reversible
  `client_fingerprint`.

### Auditing

- Every state-mutating operation writes an audit row **in the same transaction**
  as the mutation (fail-closed: a failed audit rolls the mutation back). Recorded
  `success` reflects whether the write actually took effect.
- **No PII in the audit trail**: the client key and the managed user are stored
  as HMAC fingerprints (peppered by `AUTH_AUDIT_PEPPER`); role/permission names
  are not PII and stay readable. The log stream carries no user/resource.

### Configuration hardening

- The service **refuses to boot** with a weak/placeholder audit pepper when audit
  logging is on and debug is off. Set a strong, dedicated `AUTH_AUDIT_PEPPER`.
- `debug_mode` is off by default; `.env` must be `chmod 600` and never committed.

### Revocation

- **Deleting a role purges its grants.** `DELETE /api/role/<role>` unlinks the
  role's members and permissions, so revocation is durable: re-creating a role
  with the same name yields an empty role and never restores former access.
  Re-adding a role that still exists remains idempotent (repeat bootstrap keeps
  its grants). Users and permissions survive the delete — only that role's links
  are removed — so a user who also belongs to another role keeps that access.

### Key rotation

- `POST /api/keys/rotate` (authenticated with the current key) mints a fresh key
  and atomically moves the whole namespace onto it, re-encrypting bound fields
  under the new key. A per-tenant advisory lock serializes rotation against
  concurrent writes. The returned key is the only copy — persist it.

### Per-user API keys

- `/api/apikeys/*` manages keys for a tenant's **users**. Secrets are
  server-generated (`rak_` + 43 base62 chars, 256-bit), returned **exactly once**
  at creation, and stored only as a SHA-256 digest — a DB dump reveals nothing
  usable, and there is no recovery path (revoke + re-create instead). The digest
  is unpeppered by design: at this entropy offline brute force is not a threat,
  and a pepper change must never invalidate every issued key.
- Secrets travel **only in JSON bodies** (validate) or response bodies (create) —
  never URLs, which are logged by gunicorn/nginx. `user` and `label` cells join
  the per-tenant field-encryption scheme.
- **Validation is tenant-scoped**: a key answers only under the client key whose
  namespace created it; a foreign tenant's key is indistinguishable from an
  unknown one (`unknown_key`), so key existence cannot be probed across tenants.
- Per-user keys never authenticate `/api/*` itself — they are subjects of the
  registry, not bearer credentials for auth. Client-key rotation moves the rows
  and re-encrypts bound cells while the secrets (hashes) keep validating.
- At most **25 active keys per (tenant, user)** bounds abuse; create/list/revoke/
  validate are audited (fingerprints only — never the secret or its hash).

### Strict user identity (default since 3.0.0; pre-3.0 tenants grandfathered)

- `PUT /api/settings {"strict_users": true}` (audited) makes authorization
  decisions answer negatively for subjects holding no live API key — revocation
  becomes end-to-end: revoke a user's last key and their answers turn negative
  immediately. The `reason: "user_not_key_backed"` field is **stable contract**
  and appears only on strict blocks; a refused membership grant is an HTTP 409
  so it can never be read as success. Enforcement lives at decision points in
  the service layer (identical for REST and embedded callers); listings, key
  issuance, and every delete/revoke path are never gated. Tenants that perform
  their own end-user authentication (machine/synthetic subjects) legitimately
  hold `strict_users: false` — the per-tenant opt-out survives the 3.0.0
  default flip. Flip mechanics: no-row tenants follow
  `AUTH_STRICT_USERS_DEFAULT` (true since 3.0.0), and a one-shot grandfathering
  pass (migration + marker-guarded `create_tables` pass for embedded
  databases) wrote explicit false rows for every pre-3.0 creator, so the flip
  reaches only tenants created after it. See docs/DEPRECATIONS.md.

### Transport security (embedded mode)

- The PostgreSQL engine defaults `sslmode=require` for remote hosts, decided by
  host-component comparison; an explicit URL `?sslmode=...` or `PGSSLMODE` is
  always honored and never overridden (precedence fixed in 2.5.2).

## Threat notes (by design)

- **Authentication is out of scope.** `auth` trusts the caller already knows who
  the user is; pair it with whatever authenticates them.
- **Possession = authority.** A leaked key grants full access to that namespace,
  and whoever holds it can rotate it away. Rotate promptly on any suspected leak.
- **Coarse RBAC.** No attribute/row-level rules; encode resource scope in
  permission names (`doc:123:edit`) only while that stays manageable, otherwise
  use an ABAC/policy engine.
- **Edge is the primary rate limiter.** The app-layer limiter is best-effort
  defense-in-depth; nginx enforces the real per-IP limit.
