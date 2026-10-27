-- migration: add_auth_api_key
-- id: 01KYTMDEYFVH43HKR0MQWW1EMP
--
-- Per-user API-key registry (SPEC 0004, issuedb #9). Mirrors the SQLAlchemy
-- model auth.models.sql.AuthApiKey exactly — the app's boot-time
-- create_all(checkfirst=True) may legally create this table first on a fresh
-- install, so every statement is IF NOT EXISTS and the two DDL paths converge
-- in either order. Schema is the production/CI deployment schema (auth_rbac,
-- AUTH_DATABASE_SCHEMA); schemaless SQLite/dev installs are covered by
-- create_all and never run migretti.

-- migrate: up
CREATE SCHEMA IF NOT EXISTS auth_rbac;

CREATE TABLE IF NOT EXISTS auth_rbac.auth_api_key (
    id            SERIAL PRIMARY KEY,
    key_id        VARCHAR(36) NOT NULL,
    creator       VARCHAR(64) NOT NULL,
    "user"        TEXT        NOT NULL,
    key_hash      VARCHAR(64) NOT NULL,
    key_prefix    VARCHAR(16) NOT NULL,
    label         TEXT,
    is_active     BOOLEAN DEFAULT TRUE,
    date_created  TIMESTAMP DEFAULT now(),
    modified      TIMESTAMP DEFAULT now(),
    revoked_at    TIMESTAMP,
    expires_at    TIMESTAMP,
    last_used_at  TIMESTAMP,
    CONSTRAINT uq_auth_api_key_key_hash UNIQUE (key_hash),
    CONSTRAINT uq_auth_api_key_key_id  UNIQUE (key_id)
);

CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_api_key_id
    ON auth_rbac.auth_api_key (id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_api_key_creator
    ON auth_rbac.auth_api_key (creator);
CREATE INDEX IF NOT EXISTS ix_auth_api_key_creator_user
    ON auth_rbac.auth_api_key (creator, "user");

-- migrate: down
DROP TABLE IF EXISTS auth_rbac.auth_api_key;
