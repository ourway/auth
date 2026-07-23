=========
Changelog
=========

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
