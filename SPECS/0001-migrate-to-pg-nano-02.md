# SPEC — Migrate auth to pg-nano-02 + partition audit_log

Ticket: issuedb #1 (auth repo). Runbook: docs/runbooks/database-deployment.md

## EARS requirements & verification
- auth shall use the `auth` database on pg-nano-02 as system of record.
  VERIFIED: workers connected to 51.91.248.208:5432; live traffic writing there.
- A verified backup shall precede any change; the source shall remain a rollback path.
  VERIFIED: two dumps taken (pre + final), both `pg_restore -l` readable; auth_db on
  93.89.141.253 untouched; previous auth.env kept as .pre-pgnano.<timestamp>.
- Connections shall require TLS + client cert (CN=role) + scram, all three.
  VERIFIED: connects only with all three; a pgadmin connection presenting auth's cert
  was refused (CN mismatch).
- Migrated data shall match source row counts and content checksums.
  VERIFIED: all 16 tables matched; audit_log 175169 rows, md5 c1fdfe3408218ac7b571537c119f31ea
  identical on both sides; all 6 sequences preserved.
- migretti state shall migrate so the target reports the same applied set.
  VERIFIED: public._migrations carried 4 applied rows through the dump; mg status then
  correctly showed 4 applied / 1 pending.
- audit_log shall be RANGE partitioned monthly on "timestamp".
  VERIFIED: relkind=p, 15 partitions, rows in audit_log_2026_07 / _2026_08, pruning
  confirmed by EXPLAIN (scans only the matching partition).
- Partitioning shall preserve every row, the sequence position and the indexes.
  VERIFIED: md5 unchanged across the conversion; seq 175169; 5 indexes incl. a NEW
  index on "timestamp" (the original table had none).
- Out-of-range rows shall route to a DEFAULT partition treated as a trap.
  VERIFIED: audit_log_default exists and holds 0 rows; provisioning job alarms if it fills.
- A provisioning function and a deliberate (unscheduled) retention function shall exist.
  VERIFIED: provision_audit_log_partition idempotent; drop_audit_log_partitions_before
  dropped 2026_07 for a 2026-08-01 cutoff (175135 -> 96699) and dropped NOTHING for a
  2020-01-01 cutoff.
- Rollback shall be possible by restoring the previous DSN.
  VERIFIED (procedure documented, artifact exists): auth.env.pre-pgnano.20260809-091748Z.
- A runbook shall be recorded in the repo.
  DONE: docs/runbooks/database-deployment.md.

## Downtime
70 seconds (09:16:46Z stop -> 09:17:56Z healthy). Budget was 30 minutes.

## Defects found and fixed while building the migration
1. Retention function silently no-opped: the bound regex matched only [0-9-]+ and so
   stopped at the space in "TO ('2026-08-01 00:00:00')", producing NULL, skipping every
   partition, and still reporting success. Now parses the full quoted bound and RAISES
   on a parse failure. Caught only because the test compared partition counts before
   and after rather than trusting the return value.
2. ALTER SEQUENCE ... OWNED BY failed because the migration runner (pgadmin) is not the
   table owner (auth). The migration now captures and restores the original owner,
   including on each partition (ALTER TABLE ... OWNER TO does not cascade).
3. sslrootcert=system fails under psycopg binary wheels (bundled OpenSSL, different
   default CA store) though it works for the deployed psycopg-c and for asyncpg.
   migretti therefore needs the explicit CA path.

## Not exercised
Sustained load on the new host; failover; a restore of the partitioned database from
pgBackRest (the pgBackRest restore path itself was proven on pg-nano-01 with a
checksum-compared round trip, but not with this dataset).
