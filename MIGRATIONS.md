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
- **Alembic is fully purged** (2.4.1): no tree, no config, no dependency. Its
  single historical revision (`0001_widen_text`, a varchar→TEXT widening that
  production already carries) exists in **git history only**, and the
  `alembic_version` tracking table is dropped by migration
  `drop_alembic_version`.

## Provisioning / upgrading (operator, with a DDL-capable role)

**Run `mg` on vm-2, not from a workstation.** The database is
`pg-nano-02.rodmena.co.uk` and the DSN authenticates with client certificates
that exist only at `/opt/auth/etc/tls/` on the deploy host, so a laptop cannot
reach it. `migretti` is installed in `/opt/auth/venv` for this. The env file is
**not shell-sourceable** — a value contains `&` — so read the DSN with `grep`,
never `. auth.env`.

1. Back up the database (`pg_dump`). For a migration that drops anything, dump
   the affected tables specifically and **verify the dump holds rows**, not just
   that the file exists:
   ```bash
   pg_dump "$DSN" --schema=public -f /opt/auth/backups/public-$(date -u +%Y%m%dT%H%M%SZ).sql
   ```
2. Apply pending migrations:
   ```bash
   ssh vm2
   cd /opt/auth/app
   DSN=$(grep '^AUTH_DATABASE_URL=' /opt/auth/etc/auth.env | cut -d= -f2- | sed 's/+psycopg//')
   MG_DATABASE_URL="$DSN" /opt/auth/venv/bin/mg status
   MG_DATABASE_URL="$DSN" /opt/auth/venv/bin/mg apply
   MG_DATABASE_URL="$DSN" /opt/auth/venv/bin/mg verify
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

**Exception — a migration that constrains what the running code may read.**
Row Level Security is the example: the policies added by
`enable_row_level_security` filter on a session variable that only the newer
code sets. Migrate first, with the old code still serving, and every query
returns zero rows — a total authorization outage, not a degraded one. For that
class: **stop the service, deploy the code, migrate, start.** The 3.1.1 window
cost 1m44s end to end.

### Three things that will bite you, all learned the hard way

- **`CREATE OR REPLACE FUNCTION` fails if an earlier migration ran as a
  different role** — `ERROR: must be owner of function`. The app role owns the
  *schema*, which is enough to DROP an object inside it, so use
  `DROP FUNCTION IF EXISTS` + `CREATE FUNCTION`. Afterwards the function belongs
  to the role that owns the tables, and the next person is not blocked.
- **A migration that counts rows sees them through RLS.** The app role owns
  these tables and FORCE applies to the owner, so an unbound `SELECT count(*)`
  in a migration returns **0** — a guard built on that count silently decides
  the table is empty. Run as a superuser the same migration behaves differently.
  Lift FORCE for the duration of the count and restore it before committing (see
  `drop_stale_public_tables`), or the result depends on who invokes it.
- **Amending an applied migration leaves `mg verify` failing** until the
  checksum is re-baselined with `mg fix <id> --applied`. Only do that once you
  have confirmed the amendment produces the state the database is already in —
  `partition_audit_log` qualified because its change only wrapped existing index
  creation in an existence guard.

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

## Amending a migration that is already applied

`mg apply` does **not** verify checksums — only `mg verify` does. So correcting
the SQL of an already-applied migration is safe for a deployed host: `mg apply`
reports `No pending migrations`, exits 0, and touches no schema. `mg verify`,
however, will report `Checksum mismatch` and exit 1 from then on, because the
file on disk no longer hashes to what was recorded when it ran.

After deploying such a correction, re-baseline the recorded checksum on each
host that had already applied it:

```bash
MG_DATABASE_URL="${AUTH_DATABASE_URL/+psycopg/}" .venv/bin/mg fix <id> --applied --yes
MG_DATABASE_URL="${AUTH_DATABASE_URL/+psycopg/}" .venv/bin/mg verify
```

`mg fix --applied` re-records the checksum from disk and changes no schema and
no rows. Only do this when the correction is a no-op against the state that host
is already in — if the amended SQL would have produced a *different* schema, it
needs a new migration instead.

## CI

- `make test-postgres` and the GitHub `postgres` job run `mg apply` against the
  disposable database before pytest — the SQL, its tracking, and its
  convergence with `create_all` are exercised on every run.

## Migration log

| id | name | notes |
|---|---|---|
| `0001_widen_text` (pre-migretti) | varchar→TEXT widening | applied in prod 2026-07; source in git history only |
| `01KYTMDEYFVH43HKR0MQWW1EMP` | add_auth_api_key | per-user API-key registry (SPEC 0004, issuedb #9) |
| `01KYTQN79R1ZBNDPA3ND9AAA73` | drop_alembic_version | Alembic purge (SPEC 0009, issuedb #14) |
| `01KYTRKMWNBDDZPN1H0AXRTT5G` | add_auth_tenant_settings | per-tenant settings / strict_users (SPEC 0010, issuedb #15) |

## Note on `AuditLog.user` width

`audit_log.user` is `String(64)` and stores a **fingerprint** (36 chars), not a
raw identifier, so it fits comfortably; no migration is required for the audit
PII change.
