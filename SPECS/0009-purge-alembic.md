# SPEC 0009 — Purge Alembic entirely (2.4.1)

- **Ticket:** issuedb #14 — "Purge Alembic entirely: legacy tree, config, test, deps,
  prose, prod alembic_version table"

## EARS requirements

1. The repository shall contain no Alembic artifacts: no `migrations_legacy_alembic/`
   tree, no `alembic.ini`, no Alembic test module, and no `alembic` entry in any
   dependency list.
2. The production database shall not contain the `alembic_version` table; its removal
   shall ship as a migretti migration (`drop_alembic_version`) with a faithful down
   (recreate the table and reinsert the recorded revision `0001_widen_text`).
3. When the purge lands, documentation (MIGRATIONS.md, CONTRIBUTING.md,
   docs/PLATFORM_ADOPTION.md) shall state that pre-migretti history exists in git
   history only.
4. The release (2.4.1) shall deploy only after hosted CI is green, and PyPI shall be
   updated after the live service is verified healthy.
5. When deployed, an FYI notice summarizing the 2.4.0/2.4.1 changes shall be sent to
   all bus platforms.

## Notes

- The purged revision `0001_widen_text` only widened varchar→TEXT; production already
  carries the final shape, so nothing operational depends on the removed artifacts.
- Supersedes the "retired to a legacy path" wording of SPEC 0004 requirement 12: the
  legacy path itself is now gone (see addendum there).
