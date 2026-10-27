-- migration: grandfather_strict_users
-- id: 01KYTX0MKVZ775P62CJ87631Z1
--
-- 3.0.0 flip protection (SPEC 0012, issuedb #18): every creator existing on
-- this database gets an explicit strict_users=false row, so the 3.0.0
-- no-row-means-strict default reaches ONLY tenants created afterwards. A
-- marker row ('__meta:grandfathered-3.0__', reserved) records that the pass
-- ran; the identical marker-guarded pass in auth.database.create_tables()
-- composes idempotently with this migration in either order.
--
-- The three base RBAC tables are created here IF NOT EXISTS (exact
-- create_all parity, like add_auth_api_key did for its table): on a fresh
-- database migrations must be self-sufficient — production already has
-- them, so these are no-ops there.
--
-- down removes the marker only: the grandfather rows are deliberate,
-- auditable tenant state and are kept on rollback.

-- migrate: up
CREATE SCHEMA IF NOT EXISTS auth_rbac;

CREATE TABLE IF NOT EXISTS auth_rbac.auth_group (
    id            SERIAL PRIMARY KEY,
    creator       VARCHAR(64) NOT NULL,
    role          TEXT NOT NULL,
    description   TEXT,
    is_active     BOOLEAN DEFAULT TRUE,
    date_created  TIMESTAMP DEFAULT now(),
    modified      TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_auth_group_creator_role UNIQUE (creator, role)
);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_group_id ON auth_rbac.auth_group (id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_group_creator ON auth_rbac.auth_group (creator);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_group_role ON auth_rbac.auth_group (role);

CREATE TABLE IF NOT EXISTS auth_rbac.auth_membership (
    id            SERIAL PRIMARY KEY,
    "user"        TEXT NOT NULL,
    creator       VARCHAR(64) NOT NULL,
    is_active     BOOLEAN DEFAULT TRUE,
    date_created  TIMESTAMP DEFAULT now(),
    modified      TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_auth_membership_creator_user UNIQUE (creator, "user")
);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_membership_id ON auth_rbac.auth_membership (id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_membership_creator ON auth_rbac.auth_membership (creator);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_membership_user ON auth_rbac.auth_membership ("user");

CREATE TABLE IF NOT EXISTS auth_rbac.auth_permission (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    creator       VARCHAR(64) NOT NULL,
    is_active     BOOLEAN DEFAULT TRUE,
    date_created  TIMESTAMP DEFAULT now(),
    modified      TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_auth_permission_creator_name UNIQUE (creator, name)
);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_permission_id ON auth_rbac.auth_permission (id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_permission_creator ON auth_rbac.auth_permission (creator);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_auth_permission_name ON auth_rbac.auth_permission (name);

INSERT INTO auth_rbac.auth_tenant_settings (creator, strict_users)
SELECT c.creator, FALSE
FROM (
    SELECT creator FROM auth_rbac.auth_group
    UNION SELECT creator FROM auth_rbac.auth_membership
    UNION SELECT creator FROM auth_rbac.auth_permission
    UNION SELECT creator FROM auth_rbac.auth_api_key
) c
WHERE NOT EXISTS (
        SELECT 1 FROM auth_rbac.auth_tenant_settings
        WHERE creator = '__meta:grandfathered-3.0__'
      )
  AND c.creator NOT IN (SELECT creator FROM auth_rbac.auth_tenant_settings);

INSERT INTO auth_rbac.auth_tenant_settings (creator, strict_users)
SELECT '__meta:grandfathered-3.0__', FALSE
WHERE NOT EXISTS (
    SELECT 1 FROM auth_rbac.auth_tenant_settings
    WHERE creator = '__meta:grandfathered-3.0__'
);

-- migrate: down
DELETE FROM auth_rbac.auth_tenant_settings
WHERE creator = '__meta:grandfathered-3.0__';
