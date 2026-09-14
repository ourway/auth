# SPEC 0019 — partition_audit_log fails on a fresh database

- **Ticket:** issuedb #5 (blocks #4)
- **Status:** in-progress
- **Tags:** bug
- **Origin:** master CI red since 2026-08-09; surfaced while releasing 3.1.1 (SPEC 0018)

## Context

`mg apply` against a fresh database fails on the fifth migration:

```
ERROR: Failed to apply 01KZJWHG32K9X1AFBPPB4YJC6A:
       relation "auth_rbac.audit_log" does not exist
```

The conversion `DO` block in that migration already guards for an absent table —
it reads `relkind`, gets NULL, raises a NOTICE and returns. The four
`CREATE INDEX IF NOT EXISTS ... ON auth_rbac.audit_log` statements that follow it
sit *outside* that block. `IF NOT EXISTS` guards the **index name**, not the
**table**, so with the table absent they raise rather than no-op. The down
section carried the same defect in its own trailing trio.

Underlying cause: **no migration creates `auth_rbac.audit_log`.** SQLAlchemy
`create_all(checkfirst=True)` does, at app boot. CI runs `mg apply` against an
empty database before the app has ever booted, so the migration amends a table
that has never existed there. Production was never at risk — the live table has
existed for years, so the migration met a populated table and completed.

## EARS requirements

- When `mg apply` runs against a fresh database in which `auth_rbac.audit_log`
  has never been created, the partition_audit_log migration shall complete with
  exit code 0 and create no indexes.
- When `mg apply` runs against a database holding a populated, unpartitioned
  `auth_rbac.audit_log`, the migration shall convert it to a RANGE-partitioned
  table preserving 100% of rows and the sequence position, and shall create all
  four indexes on the parent.
- If `auth_rbac.audit_log` is absent, then the migration shall raise a NOTICE and
  skip index creation rather than raising an error.
- The migration shall be idempotent: a second consecutive `mg apply` against the
  same database shall exit 0 and change nothing.
- The down migration shall carry the same absent-table guard as the up migration.

## Technical problems

1. Conditional DDL against a relation whose existence is not guaranteed at
   migration time.
2. Ordering mismatch between two schema authorities — `create_all` at app boot
   versus `mg apply` on an empty database.

## Solution domains

- PostgreSQL DDL guards -> `to_regclass()`, which returns NULL instead of
  raising. This mirrors the guard the migration's own conversion block already
  uses, so the file becomes self-consistent.
- Migration idempotence -> the repo's established pattern in this same file:
  guard, `RAISE NOTICE`, `RETURN`.

## Alternatives

- **Wrap the `CREATE INDEX` statements in a `to_regclass`-guarded `DO` block —
  CHOSEN.** No-op on a fresh database, full behaviour on a populated one,
  consistent with the file's existing guard.
- Add a migration that creates `auth_rbac.audit_log` — **REJECTED.** Duplicates
  the SQLAlchemy model as a second schema authority and breaks the
  `create_all(checkfirst=True)` convergence that MIGRATIONS.md requires and this
  migration's own header calls out.
- Boot the app (or run `create_all`) in CI before `mg apply` — **REJECTED.**
  Hides the defect rather than fixing it; the migration would still error for any
  operator running it by hand against a fresh database, and it makes the
  migration depend on application code having run first.

## Verification

Four directions, each on its own throwaway `postgres:16-alpine`, driven through
`mg apply` — the product's own interface, not raw SQL:

| # | Migration | Database | `mg apply` | Result |
|---|---|---|---|---|
| B | **original** | fresh | **exit 1** | `relation "auth_rbac.audit_log" does not exist` |
| C | fixed | fresh | exit 0 | table absent, no indexes; re-run exit 0 |
| D | fixed | populated, production shape | exit 0 | relkind `r`→`p`, rows 120→120, 18 partitions, 5 indexes, seq 120 |
| E | **original** | populated, production shape | exit 0 | relkind `p`, rows 120, 18 partitions, 5 indexes, seq 120 |

**B is the known-positive control**: the harness demonstrably goes red on the
unfixed file, so C's green is evidence rather than a vacuous pass.

**D and E are identical.** That is the regression control — the fix changes
nothing on the path production actually takes. A fix that greens CI while
quietly breaking the live conversion would be worse than red CI, and comparing
against the original file on a populated table is the only thing that rules it
out.

## Credit

The fourth index (`ix_auth_rbac_audit_log_timestamp`, separated from the other
three by a comment) was missed in this session's first diagnosis, which counted
the down section's trio instead. infra-manager-c13110 caught it and demonstrated
that a three-statement fix moves the error four lines down and leaves CI red.

## Production impact of amending an already-applied migration

This migration is already applied on vm-2, so editing the file has a deployed
consequence. Measured on a container seeded to production shape (populated table,
original migration applied, then the edited file swapped in):

| Command | Result after the swap |
|---|---|
| `mg apply` | `No pending migrations`, **exit 0** — no schema change, no rows touched |
| `mg status` | 5 total, 5 applied, 0 pending — unchanged |
| `mg verify` | `Checksum mismatch for 01KZJWHG32K9X1AFBPPB4YJC6A`, **exit 1** |
| data | 120 rows, relkind `p`, 18 partitions — intact |

`mg apply` does not verify checksums; only `mg verify` does. So the deploy itself
is safe, but `mg verify` fails from then on until the recorded checksum is
re-baselined. Remedy, measured:

```
mg fix 01KZJWHG32K9X1AFBPPB4YJC6A --applied --yes   -> exit 0
mg verify                                           -> exit 0, "All applied migrations match"
rows 120, relkind p, 18 partitions                  -> unchanged
```

**vm-2 deploy step:** after `git ff`, run `mg fix 01KZJWHG32K9X1AFBPPB4YJC6A
--applied --yes` and confirm `mg verify` exits 0. Documented in MIGRATIONS.md
under "Amending a migration that is already applied".

Note on measurement: the first two attempts at this check piped `mg` through
`tail`, so `$?` reported `tail`'s status and printed `exit 0` over a real
failure. The exit codes above are `mg`'s own, captured before any pipe.
