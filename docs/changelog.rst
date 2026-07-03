=========
Changelog
=========

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
