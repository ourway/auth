# Schema & migrations runbook

This service owns a small schema (`auth_group`, `auth_membership`,
`auth_permission`, the two junction tables, `auth_api_key`, `audit_log`) in the
configured PostgreSQL schema (`AUTH_DATABASE_SCHEMA`, e.g. `auth_rbac`).

## How the schema is created and changed

- **Initial creation** is done by `auth.database.create_tables()`
  (`Base.metadata.create_all`), invoked at app startup (`auth.main.create_app`).
  A fresh install gets the final table shape directly. This call is
  **intentionally non-raising** (`raise_on_error=False` at boot): the runtime DB
  role may legitimately lack DDL rights, so the app must still start against an
  already-provisioned schema. It logs at **ERROR** if DDL fails — treat that log
  line as a provisioning failure.
- **Changes** are authored with **migretti** (`mg`, SQL-first — the house
  standard). Migration files live in `migrations/` with `-- migrate: up` /
  `-- migrate: down` sections; config is `mg.yaml` (no credentials — targets are
  selected via `MG_DATABASE_URL`). Every migration must mirror what the
  SQLAlchemy models would emit and use `IF NOT EXISTS`, so the boot-time
  `create_all(checkfirst=True)` and `mg apply` converge in either order.
- **Legacy Alembic** is retired: its single revision (`0001_widen_text`,
  applied in production) is frozen in `migrations_legacy_alembic/` for history
  and stays loadable (`tests/test_migrations.py`). Never author new Alembic
  revisions.

## Provisioning / upgrading (operator, with a DDL-capable role)

1. Back up the database (`pg_dump`).
2. Apply pending migrations — build `MG_DATABASE_URL` from the deployment env,
   never type credentials inline:
   ```bash
   cd ~/develop/auth
   set -a; . ./.env; set +a
   # Prod defines AUTH_DATABASE_URL; strip any +psycopg driver suffix.
   MG_DATABASE_URL="${AUTH_DATABASE_URL/+psycopg/}" .venv/bin/mg apply
   MG_DATABASE_URL="${AUTH_DATABASE_URL/+psycopg/}" .venv/bin/mg status
   ```
3. **Verify** the expected tables exist before serving:
   ```
   .venv/bin/python - <<'PY'
   from sqlalchemy import inspect
   from auth.database import engine
   from auth.config import get_settings
   s = get_settings().database_schema or None
   have = set(inspect(engine).get_table_names(schema=s))
   need = {"auth_group","auth_membership","auth_permission",
           "membership_groups","permission_groups","auth_api_key","audit_log"}
   missing = need - have
   print("MISSING:", missing) if missing else print("schema OK:", sorted(have))
   PY
   ```
4. Restart the service (`sudo systemctl restart auth.service`).

Order matters: migrate **before** deploying code that needs the new schema. The
running old code ignores new tables; the new code's boot `create_all` then
no-ops. (If a restart accidentally runs first, `IF NOT EXISTS` makes the later
`mg apply` converge and record the migration as applied.)

## Rollback

- `mg down` reverts the most recent migration (each file carries real
  `-- migrate: down` SQL); `mg rollback <n>` reverts N.
- **Code rollback usually needs no schema rollback**: old code neither queries
  nor maps new tables, so they can safely remain (mirrors the old
  varchar→TEXT reasoning). Only run `mg down` when a table must actually go —
  e.g. `auth_api_key`'s down DROPs issued keys, so don't run it if keys exist
  that you intend to keep. Caveat: while code is rolled back, tenant key
  rotation will not migrate `auth_api_key` rows (old code doesn't know the
  table), orphaning keys created in the interim — keep rollback windows short.
- Partial-failure repair: `mg fix <id> --applied` / `mg fix <id> --remove`
  after fixing by hand; `mg verify` checks applied checksums against disk.

## CI

- `make test-postgres` and the GitHub `postgres` job run `mg apply` against the
  disposable database before pytest — the SQL, its tracking, and its
  convergence with `create_all` are exercised on every run.

## Migration log

| id | name | notes |
|---|---|---|
| `0001_widen_text` (alembic, retired) | varchar→TEXT widening | applied in prod; frozen in `migrations_legacy_alembic/` |
| `01KYTMDEYFVH43HKR0MQWW1EMP` | add_auth_api_key | per-user API-key registry (SPEC 0004, issuedb #9) |

## Note on `AuditLog.user` width

`audit_log.user` is `String(64)` and stores a **fingerprint** (36 chars), not a
raw identifier, so it fits comfortably; no migration is required for the audit
PII change.
