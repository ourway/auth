-- migration: drop_alembic_version
-- id: 01KYTQN79R1ZBNDPA3ND9AAA73
--
-- Alembic is fully purged (issuedb #14, SPEC 0009): migretti owns all
-- tracking, so the legacy alembic_version table goes. Its single recorded
-- revision was 0001_widen_text (varchar->TEXT widening, applied 2026-07);
-- the revision source now lives in git history only. The down section
-- faithfully restores the table and its one row. On databases that never ran
-- Alembic (fresh installs, CI) the up is a no-op.

-- migrate: up
DROP TABLE IF EXISTS auth_rbac.alembic_version;

-- migrate: down
CREATE TABLE IF NOT EXISTS auth_rbac.alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO auth_rbac.alembic_version (version_num)
VALUES ('0001_widen_text')
ON CONFLICT DO NOTHING;
