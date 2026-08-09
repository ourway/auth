# Runbook: database deployment (where the auth database lives)

**Component:** the `auth` PostgreSQL database
**Status:** MIGRATED + VERIFIED — moved off the bikeroom host to pg-nano-02 on
2026-08-09 with **70 seconds** of downtime. Row counts and content checksums matched
the source exactly; live production traffic verified writing to the new host.

## Where the database is

| | |
|---|---|
| Host | `pg-nano-02.rodmena.co.uk` (51.91.248.208), OVH VPS, FreeBSD 15 |
| PostgreSQL | 18.4 |
| Database | `auth` (was `auth_db` on the old host) |
| Schemas | `auth_rbac` (live), `public` (legacy pre-3.0.0 tables + migretti state) |
| Neighbours | `tokengate` shares this host; `runflow`, `futex`, `ledger` are on pg-nano-01 |
| Application | still on the bikeroom host (`93.89.141.253`, `/opt/auth`, user `authsvc`) |

The database is deliberately **off-site from the application**. The app is
redeployable anywhere; the data is not. If the bikeroom is lost, auth's records
survive, and the service can be stood up elsewhere against the same database.

## Connections

Three things are required together — any one missing is refused:

1. **TLS** (`sslmode=verify-full`). Server certificate is from Let's Encrypt and
   auto-renews, so the system trust store validates it.
2. **A client certificate** signed by the pg-nano CA whose **CN equals the role name**.
3. **A SCRAM password.**

`pg_hba.conf` is scoped per role *and* per database: the `auth` role can reach the
`auth` database and nothing else. That is enforced at connection time, not by GRANT.

TLS material on the app host, owned by `authsvc`, mode 0600:

```
/opt/auth/etc/tls/auth.crt     client certificate (CN=auth)
/opt/auth/etc/tls/auth.key     client key
/opt/auth/etc/tls/ca.crt       the pg-nano CA — informational only; NOT used to
                               verify the server (Let's Encrypt does that)
```

`AUTH_DATABASE_URL` in `/opt/auth/etc/auth.env`:

```
postgresql://auth:<password>@pg-nano-02.rodmena.co.uk:5432/auth\
?sslmode=verify-full&sslrootcert=system\
&sslcert=/opt/auth/etc/tls/auth.crt&sslkey=/opt/auth/etc/tls/auth.key
```

`sslrootcert=system` works here because the deployed `psycopg-c` links the system
libpq/OpenSSL. It does **not** work under every psycopg build — see the migretti note
below. Nothing in the app needed changing: `auth.database._forced_sslmode()` already
declines to override an sslmode the caller puts in the URL.

## Running migrations

Migrations are authored with **migretti** and are the only way the schema changes.
Run them as **`pgadmin`** (the DDL-capable superuser), not as `auth`, which has no
DDL rights in production.

```bash
export PGPASSWORD='<pgadmin password>'
export MG_DATABASE_URL="postgresql://pgadmin@pg-nano-02.rodmena.co.uk:5432/auth\
?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt\
&sslcert=$HOME/.config/pg-nano-01/clients/pgadmin.crt\
&sslkey=$HOME/.config/pg-nano-01/clients/pgadmin.key"

mg status        # what is pending
mg apply --yes   # apply
```

**Use the explicit CA path, not `sslrootcert=system`, for migretti.** migretti runs on
psycopg, and a psycopg binary wheel bundles its own OpenSSL whose default CA store is
not the system one — `system` then fails with a misleading
`SSL error: certificate verify failed`. The deployed app is unaffected because it uses
`psycopg-c` against the system libpq.

The migretti state table is `public._migrations`. It lives **inside** the database, so
`pg_dump`/`pg_restore` carries it with the data — after a restore, `mg status` correctly
reports the same applied set as the source.

## audit_log is partitioned

`auth_rbac.audit_log` was the entire growth problem: 175k rows / 52 MB, **79% of the
whole database**, growing ~4,800 rows/day on average and ~10,700/day in the most recent
month, with no retention or partitioning at all.

It is now **RANGE partitioned by month** on `"timestamp"`:

- one partition per month, named `audit_log_YYYY_MM`
- a `audit_log_default` DEFAULT partition that is a **trap, not a home** — rows landing
  there mean provisioning fell behind
- `PRIMARY KEY (id, "timestamp")` — PostgreSQL requires the partition key in every
  unique constraint. `id` is still globally unique in practice, fed by one sequence.
- a new index on `"timestamp"` (the old table had none, despite being time-series data)

Pruning is now `DROP TABLE` on a partition — O(1), no lock on live data — instead of a
`DELETE` that bloats the heap and demands a `VACUUM FULL` on the audit trail.

### Provisioning

Automatic: `/usr/local/sbin/pg-provision-partitions.sh` on pg-nano-02 runs on the 1st
of each month (cron, 03:20) and keeps **three months provisioned ahead**. It is
idempotent and logs to syslog with tag `pg-provision`. It also raises a syslog WARNING
if `audit_log_default` is non-empty.

By hand:

```sql
SELECT auth_rbac.provision_audit_log_partition('2027-06-01');   -- idempotent
```

### Retention — deliberately NOT automated

```sql
SELECT * FROM auth_rbac.drop_audit_log_partitions_before('2026-08-01');
```

Drops whole partitions entirely older than the cutoff and returns what it dropped.
**No cron runs this.** How long auth history must be kept is a compliance decision, not
a housekeeping default, so the mechanism ships but the policy does not.

Verified in both directions: dropping with a cutoff of `2026-08-01` removed
`audit_log_2026_07` (175,135 → 96,699 rows); a cutoff of `2020-01-01` correctly dropped
nothing.

> An earlier version of this function silently did nothing — its regex matched only
> `[0-9-]+` and so stopped at the space before the time in
> `TO ('2026-08-01 00:00:00')`, yielding NULL, skipping every partition, and still
> reporting success. It now parses the whole quoted bound and **raises** if it cannot,
> because a retention job that silently retains everything is worse than none.

## Backup and restore

Backups are handled on the database host by **pgBackRest to OVH S3** — daily full,
hourly incremental, continuous WAL archiving (`archive_timeout=300`, so RPO ≤ 5 min),
encrypted aes-256-cbc. This replaced nothing on the old host: the bikeroom database had
no off-box backup at all.

```bash
# on pg-nano-02, as root
pgbackrest --stanza=pg-nano-02 info      # catalogue + WAL range
pgbackrest --stanza=pg-nano-02 check     # validate archiving end to end
pgbackrest --stanza=pg-nano-02 restore   # full restore (postgres stopped)
pgbackrest --stanza=pg-nano-02 --type=time --target="2026-08-09 09:00:00+00" restore
```

Logical backups for a portable copy:

```bash
pg_dump -Fc -Z6 -d "<pgadmin dsn>" -f auth-$(date -u +%Y%m%d).dump
pg_restore -l auth-YYYYMMDD.dump | head      # verify it is readable BEFORE trusting it
```

The pre-migration dumps are kept on the operator workstation at
`~/backups/auth-premigration/` (3.2 MB each, `pg_restore -l` verified).

## Rolling back to the bikeroom database

**The old database was left completely untouched.** `auth_db` on 93.89.141.253 still
holds every row as of the cutover. To roll back:

```bash
# on 93.89.141.253
service authsvc stop
cp /opt/auth/etc/auth.env.pre-pgnano.<timestamp> /opt/auth/etc/auth.env
service authsvc start
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4000/health   # expect 200
```

Writes made against pg-nano-02 after the cutover would be lost by that rollback, so
export them first if the gap matters. Once you are satisfied the new host is good,
retire `auth_db` deliberately — do not leave two divergent copies indefinitely.

## What the cutover actually did (2026-08-09)

1. Verified backup taken and `pg_restore -l` checked **before** any change.
2. Migration rehearsed on a scratch copy of real production data — including
   up → down → up, which preserved the data md5 exactly.
3. Service stopped; confirmed **zero** live backends; final consistent dump taken.
4. Target database recreated clean, restored, and verified: **all 16 table counts
   matched**, `audit_log` md5 identical (`c1fdfe34…`, 175,169 rows), all 6 sequences
   preserved, migretti state carried over.
5. Partitioning migration applied — md5 unchanged, 15 partitions, DEFAULT trap empty.
6. DSN switched (old `auth.env` kept as `.pre-pgnano.<timestamp>`), service started.
7. Verified: `/health` 200 locally and publicly, workers connected to
   `51.91.248.208:5432`, and **live production traffic** wrote real `CHECK_PERMISSION`
   rows into `audit_log_2026_08`.

Downtime: **70 seconds.**

## Gotchas

- **`ALTER SEQUENCE ... OWNED BY` fails if the sequence and table have different
  owners.** The migration runner (`pgadmin`) is not the table owner (`auth`), so the
  partitioning migration captures the original owner and restores it — including on
  every partition, since `ALTER TABLE ... OWNER TO` does not cascade.
- **Detach the sequence before dropping its old owning table**, or `DROP TABLE`
  cascades to the sequence and the id counter restarts at 1.
- The app's boot-time `create_all(checkfirst=True)` is **safe** against the partitioned
  table: SQLAlchemy's `has_table` returns True for `relkind='p'`. Verified by running
  the app's own `create_tables(raise_on_error=True)` against a partitioned copy.
- The `public` schema still holds small legacy tables from before the 3.0.0 namespace
  move (94-row `audit_log`, a handful of 2-row RBAC tables). They came across with the
  dump. Nothing reads them; drop them deliberately once confirmed dead.
- `auth_rbac.audit_log.id` is `integer`, not `bigint`. At the current ~10.7k rows/day
  that is centuries away, but a sustained 100× would make it a real deadline.
