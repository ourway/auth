=========
Changelog
=========

Version 3.0.1 (2026-07-31)
==========================

Two consumer-reported defects from the 3.0.0 adoption round, plus a broken
quickstart found while releasing them. No API change.

Fixed
-----

- **The documented quickstart could not succeed on a namespace created after
  3.0.0.** Strict user identity is the default for new namespaces, so the
  README's third step — granting a membership straight after creating a role —
  was refused with ``409 {"reason": "user_not_key_backed"}``. The 409 is correct
  and unchanged; the documentation predated the flip and never taught the step
  that satisfies it, so every brand-new user hit a wall. README and all three
  landing-page quickstarts (``/``, ``/claude``, Python client) now issue a
  per-user API key first, and document the per-tenant opt-out
  (``PUT /api/settings`` with ``{"strict_users": false}``) for consumers whose
  users can never hold auth keys. The pre-publish smoke test now mirrors the
  documented sequence and asserts both directions, so a quickstart that cannot
  succeed fails the release. SPEC 0015, issuedb #22.

- **Importing ``auth`` in a client-only process no longer prints
  embedded-server secret warnings.** ``python -c "import auth"`` emitted the
  weak-``AUTH_JWT_SECRET_KEY`` and weak-``AUTH_AUDIT_PEPPER`` lines to stderr,
  because importing the package builds the database engine singleton, which
  constructs ``Settings``, whose validators warned. A consumer that only talks
  to a remote service signs no JWTs and writes no audit rows, so neither line
  was actionable — and both landed in *that consumer's* boot logs, reading as
  their misconfiguration. The warnings now fire from the paths that actually use
  the secrets: ``create_app`` (server boot), ``create_tables`` and the
  ``Authorization`` wrapper (embedded), at most once per process. The
  fail-closed ``verify_audit_pepper`` check at server boot is unchanged.
  Reported independently by tokengate and runflow. SPEC 0013, issuedb #20.
- **``create_tables()`` reconciles pre-2.x ``varchar`` columns to ``TEXT``.**
  ``create_all(checkfirst=True)`` never ALTERs an existing table, so embedded
  databases created by pre-2.x versions kept narrow ``varchar`` widths where the
  current models declare ``Text``. Encrypted values of longer identifiers
  overflow them, raising ``StringDataRightTruncation`` on write — highway hit
  this on ``auth_membership.user`` inside ``add_membership``. A reconciliation
  pass now widens exactly those columns on PostgreSQL. Columns whose models
  declare a bounded ``String`` are untouched: ``audit_log.user`` is a 64-char
  fingerprint by design. The pass is idempotent and non-raising, so a runtime
  role without DDL rights still starts. SPEC 0014, issuedb #21.

Version 3.0.0 (2026-07-31)
==========================

The two decommissions announced on the platform bus (SPEC 0007, SPEC 0008),
shipped after every consuming platform confirmed or was declared a
non-consumer by the operator. Mechanics: SPEC 0012.

Changed (breaking)
------------------

- **Client: transport failures always raise ``AuthTransportError``.** The 2.x
  answer-shaped error dict (``{"error", "success": False, ...}``) is removed —
  an outage can never again be misread as a denial. The ``raise_on_error``
  constructor argument is retained as a deprecated no-op so 2.x constructor
  calls keep working (it warns).
- **Strict user identity is the default for tenants with no stored setting**
  (new ``AUTH_STRICT_USERS_DEFAULT``, default true). **Grandfathering:** every
  creator existing before 3.0.0 receives an explicit ``strict_users: false``
  row — via migretti migration ``grandfather_strict_users`` in our deployment
  and via a one-shot, marker-guarded pass in ``create_tables()`` on embedded
  databases — so NO existing tenant's behavior changes at upgrade; the flip
  reaches only namespaces created after 3.0.0. The audited per-tenant opt-out
  survives indefinitely. Embedded consumers that have not adopted key-backed
  users yet should pin ``auth<3`` or set ``AUTH_STRICT_USERS_DEFAULT=false``.

Version 2.5.2 (2026-07-31)
==========================

Fixed
-----

- **Embedded engine no longer overrides the caller's sslmode** (reported by
  Highway). ``auth.database`` used to force ``sslmode=require`` for any URL
  failing a *substring* test on "localhost", silently discarding an explicit
  ``?sslmode=...`` (connect_args beat URL conninfo in psycopg). Precedence is
  now: URL ``sslmode`` param > ``PGSSLMODE`` env > secure-by-default
  ``require`` for genuinely remote hosts, with the host decided by component
  comparison (``?fallback_application_name=localhost`` no longer skips SSL).

Added
-----

- The in-process ``Authorization`` wrapper now exposes the full 2.5.x surface
  for embedded consumers: ``strict_users`` constructor override,
  ``get_settings``/``set_strict_users``, and the per-user API-key lifecycle
  (``create_api_key``, ``list_api_keys``, ``revoke_api_key``,
  ``validate_api_key``, ``check_api_key_permission``) — strict semantics are
  identical to the REST layer (enforcement lives in ``AuthorizationService``).
- Docs: API.md documents the settings endpoints, ``check_permission``, the
  strict gate list and the 409 refusal; ARCHITECTURE.md and SECURITY.md cover
  ``auth_tenant_settings`` and the strict model; release tags are now pushed
  for every published version.

Version 2.5.1 (2026-07-31)
==========================

Changed
-------

- **Strict-mode membership refusal is now HTTP 409** with body
  ``{"result": false, "reason": "user_not_key_backed"}`` (was 200-with-false).
  Adopted after two consumers independently showed that a refused grant
  answering 200 gets written past (``raise_for_status()`` passes, ``result``
  goes unchecked), turning strict mode into silent dead-key provisioning.
  Strict mode is opt-in with no adopters yet, so the shape could still change
  safely; non-strict tenants are byte-identical (the documented missing-role
  ``200 {"result": false}`` is untouched). Docs now state explicitly which
  endpoints strict mode gates (``user_permissions`` is gated; ``user_roles``
  and all listings are not) and that key-creation-before-grant ordering is a
  transactional contract.

Version 2.5.0 (2026-07-31)
==========================

Added
-----

- **Opt-in strict user identity** (SPEC 0008 phase 1 / SPEC 0010). New per-tenant
  settings: ``GET /api/settings`` and ``PUT /api/settings`` with
  ``{"strict_users": true|false}`` (audited upsert; new ``auth_tenant_settings``
  table via migretti migration ``add_auth_tenant_settings``). While enabled,
  authorization decisions about users with **no active API key** answer negatively
  in the unchanged response shapes with additive reason ``user_not_key_backed``
  (``has_permission``, membership check, ``user_permissions``, workflow
  ``can_run``), and membership adds for key-less users return
  ``{"result": false, "reason": "user_not_key_backed"}``. Key issuance and every
  delete/revoke path are never strict-gated. Tenants that don't opt in are
  byte-identical to 2.4.1.
- ``POST /api/apikeys/check_permission`` — body ``{"api_key", "permission"}``:
  validates the secret and answers the key-subject's effective permission in one
  round trip. Client methods: ``check_api_key_permission``, ``get_settings``,
  ``set_strict_users``.

Changed
-------

- ``POST /api/keys/rotate`` also migrates the ``auth_tenant_settings`` row (a strict
  tenant stays strict under its new key); ``data.migrated`` gains an additive
  ``settings`` count — same declared-delta class as 2.4.0's ``api_keys``.

Deprecated
----------

- **Bare user strings in authorization checks** (decommission target: 3.0.0, gated on
  confirmation from every consuming platform — see ``docs/DEPRECATIONS.md`` and
  ``SPECS/0008-strict-user-identity.md``). The opt-in phase above IS the migration
  vehicle; 3.0.0 makes strict identity the default.
- **Python client legacy transport-failure error dict** (decommission target: 3.0.0,
  same all-consumers gate — ``SPECS/0007``). Construct with ``raise_on_error=True``
  and catch ``AuthTransportError`` now; in 3.0.0 raising becomes the only behavior.

Version 2.4.1 (2026-07-31)
==========================

Removed
-------

- **Alembic, entirely.** The frozen legacy tree, ``alembic.ini``, the legacy
  round-trip test, and the ``alembic`` entries in the ``migrations``/``dev``
  extras are gone; migration ``drop_alembic_version`` removes the
  ``alembic_version`` tracking table from deployments (its down restores the
  table and its single recorded revision). The one historical revision
  (``0001_widen_text``) lives in git history only. ``pip install
  auth[migrations]`` now installs migretti alone. No runtime or API behavior
  changes.

Version 2.4.0 (2026-07-30)
==========================

Added
-----

- **Per-user API keys** (SPEC 0004): ``POST/GET /api/apikeys/user/<user>``,
  ``DELETE /api/apikeys/user/<user>/<key_id>``, ``POST /api/apikeys/validate``.
  auth mints ``rak_``-prefixed 256-bit secrets for a tenant's users, returns
  each exactly once, stores only a SHA-256 digest, and validates them
  tenant-scoped (a foreign tenant's key answers ``unknown_key``). ``user`` and
  ``label`` cells join the per-tenant field encryption; create/list/revoke/
  validate are audited; at most 25 active keys per (tenant, user). These are
  the API's first JSON-body-reading endpoints — secrets never travel in URLs.
  Client methods: ``create_api_key`` (no automatic retry — create is not
  idempotent), ``list_api_keys``, ``revoke_api_key``, ``validate_api_key``.
- ``Client(..., raise_on_error=True)`` raises the new ``AuthTransportError``
  on transport failure instead of returning the legacy error dict, and every
  transport-failure payload now carries ``"transport_error": true`` (reported
  by RunFlow: the error dict's ``data`` echoes inputs and lacks the answer
  field, so unchecked reads turned outages into denials).
- **migretti adopted** for schema migrations (Alembic retired to
  ``migrations_legacy_alembic/``); first migration ``add_auth_api_key``.

Changed
-------

- ``POST /api/keys/rotate`` also migrates ``auth_api_key`` rows (re-encrypting
  bound cells); its ``data.migrated`` gains an additive ``api_keys`` count —
  the sole observable change to any pre-existing endpoint. Issued user keys
  keep validating after tenant rotation, under the new tenant key.

Fixed
-----

- ``EnhancedAuthClient`` now actually passes ``pool_connections`` /
  ``pool_maxsize`` to its HTTP adapter (they were accepted and silently
  dropped, pinning the pool at urllib3's default 10); default ``pool_maxsize``
  raised to 64 (reported by RunFlow).

Version 2.3.1 (2026-07-25)
==========================

Fixed
-----

- **``import auth`` no longer requires server-side secrets.** 2.3.0 enforced the
  strong-audit-pepper check while constructing ``Settings``, so simply importing
  the package — e.g. ``pip install auth; from auth import Client`` to talk to a
  remote auth service — raised ``ValidationError`` unless ``AUTH_AUDIT_PEPPER``
  was set. The fail-closed check now runs where it belongs, at **server boot**
  (``auth.main.create_app``), so a server still refuses to start with a
  placeholder pepper while library and client use import cleanly. Constructing
  ``Settings`` with a weak pepper now logs a warning instead of raising.

Version 2.3.0 (2026-07-25)
==========================

Security
--------

- **Deleting a role now purges its grants (behavioural change).** ``del_role`` /
  ``DELETE /api/role/<role>`` previously only soft-deleted the role row and left
  its membership and permission links intact, so **re-creating a role with the
  same name silently restored every former member and every former permission** —
  a privilege-restoration hazard, since deleting a role is how callers revoke
  access. Deletion now unlinks the role's members and permissions, so revocation
  is durable and reusing a role name yields an **empty** role.

  Unchanged, and still guaranteed: **re-adding a role that still exists is
  idempotent** and keeps its grants, so callers that bootstrap the same roles on
  every start are unaffected. Users and permissions themselves survive a role
  delete — only that role's links are removed — so a user who also belongs to
  another role keeps that access.

  *Action required only if you relied on delete-then-recreate to restore access;
  re-grant explicitly instead.*

Version 2.2.0 (2026-07-25)
==========================

Production-hardening release (bank-grade certification remediation), plus CI and
documentation. The public HTTP API is unchanged; note the behavioural changes
under *Changed* and *Security*.

Security
--------

- **Auditing is now transactional, accurate, and fail-closed.** The audit row is
  written in the SAME transaction as the mutation (a failed audit rolls the
  mutation back — a mutation can no longer commit unaudited), recorded ``success``
  reflects the real operation result (a no-op write is not logged as success),
  and rotation is audited on success and failure.
- **No PII in the audit trail.** The managed user is stored as a non-reversible
  HMAC fingerprint in both the ``user`` column and ``resource``; the log stream
  carries no user/resource. Role/permission names stay readable.
- **The raw client key is never logged.** Write/rotate failure paths log a
  fingerprint, never the credential.
- **Config fails closed on a weak audit pepper** (when audit logging is on and
  debug is off): the service refuses to boot with a placeholder/empty pepper.
- **Per-tenant advisory lock** serializes key rotation against concurrent writes
  (PostgreSQL), so rotation cannot strand or clobber a concurrent change.

Changed
-------

- **Database errors are no longer masked as** ``{"result": false}`` — a genuine
  DB failure now surfaces as HTTP 500 (and a failed audit); ``false`` is reserved
  for the documented "role does not exist" case.
- **Client keys are canonicalised to lowercase**, so case-variant UUIDs no longer
  fork a namespace or its encryption keys.
- ``/health`` now performs a real database round-trip (reports 503 when the DB is
  unreachable) and no longer exposes connection-pool internals.
- The audit ``user`` column now holds a fingerprint, not a raw identifier.

Added
-----

- **GitHub Actions CI** (``.github/workflows/ci.yml``): ruff + mypy, the SQLite
  suite on 3.11/3.12, and the PostgreSQL integration suite with encryption on.
- Encryption-on integration now runs in the default test gate.
- Concise ``README.md``, ``docs/ARCHITECTURE.md`` (with diagrams),
  ``CONTRIBUTING.md``, ``SECURITY.md``, and ``MIGRATIONS.md``.

Packaging
---------

- The long description is now ``README.md`` (Markdown); ``README.rst`` was
  removed. Dependencies are pinned with upper bounds and a lockfile; the unused
  ``PyJWT`` dependency was dropped.

Version 2.1.0 (2026-07-25)
==========================

Added
-----

- **API-key rotation.** ``POST /api/keys/rotate`` (authenticated with the current
  key) mints a fresh key, atomically moves the caller's whole namespace onto it in
  a single transaction, and returns the new key. It is an instant *cutover*: the
  old key is left owning nothing. When field encryption is enabled the bound
  columns (membership user, permission name, group description) are decrypted under
  the old key and re-encrypted under the new key in the same transaction, so the
  new namespace stays equality-queryable. The rotation is recorded as a single
  ``ROTATE_KEY`` audit event linking the old and new key fingerprints (never the
  raw keys). The Python client gains ``Client.rotate_key()``, which also switches
  the live client instance to the returned key. No database migration is required.

Version 2.0.0 (2026-07-23)
==========================

Security
--------

- **Per-tenant field encryption.** Encrypted columns (membership user, permission
  name, group description) are now encrypted under a key derived per tenant
  (``creator``) via HKDF, so the same value in two tenants no longer produces the
  same ciphertext — closing a cross-tenant correlation leak. New ciphertext is
  tagged ``v2:``; legacy global-key values remain readable until re-encrypted.

Migration (BREAKING)
--------------------

- Existing **encrypted** deployments MUST re-encrypt their data, because equality
  lookups now use the per-tenant key and would otherwise miss un-migrated rows.
  Run, in a maintenance window with the app stopped and after a database backup::

      python -m scripts.reencrypt_pertenant           # preview (dry run)
      python -m scripts.reencrypt_pertenant --apply   # re-encrypt

  The pass is idempotent and resumable. New or encryption-off deployments need no
  migration.

Version 1.7.0 (2026-07-23)
==========================

Security
--------

- **Authenticated field encryption.** Deterministic encryption now verifies the
  synthetic IV it stores (``HMAC(key, plaintext)[:16]``) when decrypting, so
  tampered, corrupted, or wrong-key values are rejected with
  ``InvalidCiphertextError`` instead of silently returning plaintext or garbage.
  The field layer fails closed: a wrong or rotated ``AUTH_ENCRYPTION_KEY`` now
  fails loudly. The on-disk format is unchanged, so existing encrypted data
  keeps decrypting and legacy (never-encrypted) rows are still read as-is.

Added
-----

- **Managed schema migrations (Alembic).** ``migrations/`` and ``alembic.ini``;
  install the extra (``pip install auth[migrations]``) and run
  ``alembic upgrade head``. Migration ``0001`` widens the variable and encrypted
  columns to ``TEXT`` on PostgreSQL — idempotent, and a no-op on SQLite. Alembic
  manages schema *changes*; ``create_all`` still creates tables.

Changed
-------

- Variable and encrypted string columns are now ``TEXT`` (``auth_group.role`` /
  ``description``, ``auth_membership.user``, ``auth_permission.name``,
  ``audit_log.client_id`` / ``resource`` / ``user_agent``), removing the varchar
  limits that encrypted values or long audit fields could overflow. Existing
  PostgreSQL deployments converge by running the migration above.
- gunicorn now preloads the app and disposes the SQLAlchemy engine after fork,
  so the schema bootstrap runs once in the master rather than racing across the
  worker processes at startup.

Upgrading
---------

- After deploying, run ``alembic upgrade head`` once. It is idempotent and safe
  on deployments whose columns were already altered to ``text`` by hand.
- Because decryption now fails closed, confirm that existing encrypted rows
  authenticate under the configured key before rolling out — a wrong key now
  surfaces as errors rather than silently returning plaintext.

Version 1.6.0 (2026-07-23)
==========================

Security
--------

- **Client keys are no longer written in clear text.** The bearer token was
  previously stored verbatim in the ``audit_log.client_id`` column and in the
  JSON audit logs — including on failed authentication. Audit records now store
  a non-reversible HMAC fingerprint of the key (peppered with
  ``AUTH_AUDIT_PEPPER``, falling back to the JWT secret). Audit rows written by
  older versions still contain the raw key and should be scrubbed out of band.
- **Authentication now runs before auditing.** A missing, malformed or non-UUID
  bearer token is rejected up front, so unauthenticated requests no longer open
  a database session or write an audit row. The 400 returned for a non-UUID key
  no longer echoes the submitted value back.

Fixed
-----

- **Audit rows are no longer silently dropped.** Over-length fields (a long
  ``User-Agent``, an oversized ``Authorization`` header) overflowed the
  ``audit_log`` varchar columns and aborted the INSERT on PostgreSQL, losing the
  record entirely. Values are now clamped to their column width before insert.
  No schema migration is required.

Added
-----

- **Optional application-layer rate limiting**, as defense in depth alongside
  the nginx edge limiter. Off by default; enable with ``AUTH_ENABLE_RATE_LIMIT``
  and install the extra (``pip install auth[ratelimit]``). Point
  ``AUTH_RATELIMIT_STORAGE_URI`` at a shared store such as ``redis://`` for a
  limit shared across workers, and set ``AUTH_RATELIMIT_DEFAULT`` to tune it.
- ``AUTH_AUDIT_PEPPER`` configuration option.

Changed
-------

- ``AUTH_ENABLE_AUDIT_LOGGING=false`` is now honoured; audit logging was
  previously always on regardless of the flag.

Version 1.5.1 (2026-07-20)
==========================

Fixed
-----

- The documentation endpoints sent ``charset=utf-8`` twice in their
  ``Content-Type`` header (``text/markdown; charset=utf-8; charset=utf-8``).
  Flask appends the parameter to ``text/*`` responses itself, so passing it
  explicitly duplicated it.

Version 1.5.0 (2026-07-20)
==========================

Added
-----

- **Self-describing documentation at** ``/``: the service root used to return
  404. It now serves a complete usage guide — authentication model, quickstart,
  every endpoint with its exact response shape, naming rules and the Python
  client — aimed at coding agents given nothing but the base URL. Content is
  negotiated: Markdown for API clients, a readable HTML page for browsers.
  ``/docs`` and ``/llms.txt`` serve the same document. No authentication
  required.

  The page documents four behaviours that are easy to get wrong: writes to a
  non-existent role return ``200 {"result": false}`` rather than an error;
  responses come in two different shapes depending on the endpoint; error
  bodies are HTML rather than JSON; and the membership check answers with a
  key named ``has_permission``. A test asserts every registered ``/api/``
  route appears on the page, so new endpoints cannot ship undocumented.

Version 1.4.0 (2026-07-03)
==========================

Fixed
-----

- **Installation**: ``requests``, ``bleach`` and ``python-json-logger`` are
  now declared as dependencies — ``pip install auth`` followed by
  ``import auth`` failed on every clean install of 1.3.0. The SQLAlchemy
  floor was raised to 2.0 (the code requires ``DeclarativeBase``).
- **REST client**: ``EnhancedAuthClient`` no longer crashes at construction
  on urllib3 >= 2.0 (``method_whitelist`` was removed upstream).
- **SQLite support**: ``add_role`` / ``add_membership`` / ``add_permission``
  were raw PostgreSQL SQL hardcoded to the ``auth_rbac`` schema; they now
  use dialect-aware idempotent upserts that honor ``AUTH_DATABASE_SCHEMA``
  and work on both SQLite and PostgreSQL. The documented Python quick-start
  works on the default backend again.
- **Encryption consistency**: ``add_role`` stored role descriptions in
  plaintext while readers tried to decrypt them; descriptions are now
  encrypted on write. Reads remain tolerant of plaintext rows written by
  older versions — no data migration required.
- ``postgresql://`` URLs are normalized to ``postgresql+psycopg://`` (the
  installed driver is psycopg v3).
- Fresh PostgreSQL databases bootstrap correctly: ``create_tables()``
  creates the configured schema and reports real failures instead of
  logging "tables already exist".
- The REST API now accepts email addresses as user names (``@ . +``),
  matching the documented examples and the Python API; previously
  ``POST /api/membership/alice@example.com/admin`` returned 400.
- Malformed ``Authorization`` headers return HTTP 401 instead of a 500.
- Unhandled server errors return the JSON error envelope instead of an
  HTML page.
- ``:memory:`` SQLite databases now use a shared connection (previously
  each pooled connection saw its own empty database).
- The workflow permission checker no longer holds a closed database
  session; each operation opens its own.
- The legacy ``auth.core.REST.client.Client`` stored credentials on the
  class — instances no longer share state.
- Wheels no longer install stray top-level ``docs``/``scripts`` packages.

Changed
-------

- License metadata corrected to MIT (matching the LICENSE file).
- ``auth.__version__`` is now available.
- New-deployment column widths widened (role/user/name to 255,
  description to 512) so encrypted values fit. Existing databases are
  unaffected; optionally align them with::

      ALTER TABLE auth_rbac.auth_group ALTER COLUMN role TYPE varchar(255);
      ALTER TABLE auth_rbac.auth_group ALTER COLUMN description TYPE varchar(512);
      ALTER TABLE auth_rbac.auth_membership ALTER COLUMN "user" TYPE varchar(255);
      ALTER TABLE auth_rbac.auth_permission ALTER COLUMN name TYPE varchar(255);

- The audit log table now follows ``AUTH_DATABASE_SCHEMA``. Existing
  deployments that created ``audit_log`` in the default schema can move it
  with ``ALTER TABLE audit_log SET SCHEMA auth_rbac;`` (old rows stay
  readable either way; new rows go to the configured schema).
- CORS now honors ``AUTH_ALLOW_CORS`` / ``AUTH_CORS_ORIGINS`` (defaults
  unchanged: enabled, all origins).

Security
--------

- Documented the security model explicitly: client keys are unauthenticated
  tenant namespaces; deploy behind a trusted network or authenticating
  gateway. No behavioral change in this release.

Version 1.3.0 (2025-12-30)
==========================

- Idempotent PostgreSQL migrations for role/membership/permission writes
- Dependency fixes

Version 1.2.x (2025-12)
=======================

- PostgreSQL schema support (``AUTH_DATABASE_SCHEMA``)
- Deterministic field-level encryption enabled in production deployments
- Bug fixes and improvements

Version 1.1.0 (2025-11-23)
==========================

Features
--------

- Comprehensive Read the Docs documentation
- Full API reference
- Security and encryption guides
- Deployment examples

Improvements
------------

- Enhanced error handling
- Improved audit logging
- Better test coverage (152 tests)
- PostgreSQL optimizations

Version 1.0.0
=============

- Initial stable release
- RBAC implementation
- JWT authentication
- Field-level encryption
- Audit logging
- PostgreSQL and SQLite support
- REST API and Python library
