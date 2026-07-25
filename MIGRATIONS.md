# Schema & migrations runbook

This service owns a small schema (`auth_group`, `auth_membership`,
`auth_permission`, the two junction tables, `audit_log`) in the configured
PostgreSQL schema (`AUTH_DATABASE_SCHEMA`, e.g. `auth_rbac`).

## How the schema is created and changed

- **Initial creation** is done by `auth.database.create_tables()`
  (`Base.metadata.create_all`), invoked at app startup (`auth.main.create_app`).
  A fresh install gets the final table shape directly (encrypted columns are
  `TEXT`). This call is **intentionally non-raising** (`raise_on_error=False` at
  boot): the runtime DB role may legitimately lack DDL rights, so the app must
  still start against an already-provisioned schema. It logs at **ERROR** if DDL
  fails — treat that log line as a provisioning failure.
- **Changes** (altering existing tables) are *not* done by `create_all`. Today
  they live in `migrations/` (Alembic, one revision `0001_widen_text`).

## Provisioning / upgrading (operator, with a DDL-capable role)

1. Back up the database.
2. Apply pending changes:
   ```
   cd ~/develop/auth && .venv/bin/alembic upgrade head
   ```
   `migrations/env.py` reads `auth.config`, so it targets the real DB + schema.
3. **Verify** the expected tables exist before serving:
   ```
   .venv/bin/python - <<'PY'
   from sqlalchemy import inspect
   from auth.database import engine
   from auth.config import get_settings
   s = get_settings().database_schema or None
   have = set(inspect(engine).get_table_names(schema=s))
   need = {"auth_group","auth_membership","auth_permission",
           "membership_groups","permission_groups","audit_log"}
   missing = need - have
   print("MISSING:", missing) if missing else print("schema OK:", sorted(have))
   PY
   ```
4. Restart the service (`sudo systemctl restart auth.service`).

## Rollback

`0001_widen_text` has a `downgrade()`. To roll back one revision:
```
.venv/bin/alembic downgrade -1
```
Widening `varchar -> TEXT` is backward-compatible, so a code rollback does **not**
require a schema downgrade; downgrade only if a specific revision requires it.

## House standard for NEW migrations: migretti

Per the org standard, **new** PostgreSQL migrations must be authored with
**migretti** (SQL-first), not Alembic
(reference: https://raw.githubusercontent.com/rodmena-limited/migretti/refs/heads/main/README.md).
The existing single Alembic revision is applied in production and is left in
place; adopting migretti is tracked as a follow-up (issuedb) and should happen
the next time a schema change is required, at which point the Alembic revision is
stamped/imported into migretti and Alembic is retired.

## Note on `AuditLog.user` width

`audit_log.user` is `String(64)` and now stores a **fingerprint** (36 chars), not
a raw identifier, so it fits comfortably; no migration is required for the audit
PII change.
