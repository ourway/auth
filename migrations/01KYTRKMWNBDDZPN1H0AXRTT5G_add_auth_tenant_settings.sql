-- migration: add_auth_tenant_settings
-- id: 01KYTRKMWNBDDZPN1H0AXRTT5G
--
-- Per-tenant settings (SPEC 0010, issuedb #15) — one row per creator, absence
-- means defaults. strict_users gates SPEC 0008 strict user identity (opt-in
-- in 2.5.0; default flip is 3.0.0, gated on client confirmations). Mirrors
-- auth.models.sql.AuthTenantSettings; IF NOT EXISTS so create_all(checkfirst)
-- and mg apply converge in either order.

-- migrate: up
CREATE SCHEMA IF NOT EXISTS auth_rbac;

CREATE TABLE IF NOT EXISTS auth_rbac.auth_tenant_settings (
    id            SERIAL PRIMARY KEY,
    creator       VARCHAR(64) NOT NULL,
    strict_users  BOOLEAN NOT NULL DEFAULT FALSE,
    date_created  TIMESTAMP DEFAULT now(),
    modified      TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_auth_tenant_settings_creator UNIQUE (creator)
);

CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_tenant_settings_id
    ON auth_rbac.auth_tenant_settings (id);

-- migrate: down
DROP TABLE IF EXISTS auth_rbac.auth_tenant_settings;
