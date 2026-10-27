-- migration: add_creator_fp_and_rotate_key
-- id: 01M2Y4SMRCS9PW29AA0TFCVXKR
--
-- Groundwork for database-enforced tenant isolation (issuedb #19). Inert on its
-- own: it adds columns and indexes, enables nothing, and changes no behaviour.
-- RLS is turned on by a separate, later migration so that the application code
-- which binds a tenant to each transaction can ship and run first. Enabling RLS
-- before that code is deployed would answer every authorization question with
-- "no rows", which for this service is a total outage.
--
-- creator_fp is GENERATED rather than maintained by the application. The
-- alternative -- writing it alongside creator -- creates a class of bug where
-- the two disagree and a tenant silently sees the wrong rows. Generated, that
-- bug cannot exist: rotation updates creator and the fingerprint follows.
--
-- It is a plain SHA-256 and deliberately NOT the pepper-based fingerprint used
-- by the audit trail. The purpose is that the session variable, and anything
-- that logs it, is not the credential itself -- a hash of a UUID4 achieves that
-- and cannot be reversed. Using the pepper would tie row visibility to a secret
-- whose rotation already breaks audit reads, so changing it would lock every
-- tenant out of their own data.
--
-- sha256() is a built-in from PostgreSQL 11 (18.4 in this deployment), so no
-- pgcrypto dependency.
--
-- The application's ORM is deliberately unaware of creator_fp: it never reads
-- or writes it, only the RLS policies reference it. That also keeps the SQLite
-- test path working, where neither generated columns of this shape nor RLS
-- exist.

-- migrate: up

DO $fp$
DECLARE
    t text;
BEGIN
    IF to_regclass('auth_rbac.auth_group') IS NULL THEN
        RAISE NOTICE 'auth_rbac tables absent; nothing to do';
        RETURN;
    END IF;

    FOREACH t IN ARRAY ARRAY['auth_group', 'auth_membership', 'auth_permission',
                             'auth_api_key', 'auth_tenant_settings']
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'auth_rbac' AND table_name = t
              AND column_name = 'creator_fp'
        ) THEN
            EXECUTE format(
                'ALTER TABLE auth_rbac.%I ADD COLUMN creator_fp text '
                'GENERATED ALWAYS AS (encode(sha256(creator::bytea), ''hex'')) STORED', t);
        END IF;
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS ix_%s_creator_fp ON auth_rbac.%I (creator_fp)', t, t);
    END LOOP;
END;
$fp$;

-- The recovery credential. Only the SHA-256 of the secret is stored; the secret
-- is returned once at issuance and never again. rotate_key_issued_at is the
-- once-only latch -- NULL means it has never been disclosed, which is why every
-- tenant that exists today can still claim theirs exactly once.
DO $rk$
BEGIN
    IF to_regclass('auth_rbac.auth_tenant_settings') IS NULL THEN
        RAISE NOTICE 'auth_tenant_settings absent; nothing to do';
        RETURN;
    END IF;
    ALTER TABLE auth_rbac.auth_tenant_settings
        ADD COLUMN IF NOT EXISTS rotate_key_hash varchar(64),
        ADD COLUMN IF NOT EXISTS rotate_key_issued_at timestamp without time zone;
    CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_tenant_settings_rotate_key_hash
        ON auth_rbac.auth_tenant_settings (rotate_key_hash)
        WHERE rotate_key_hash IS NOT NULL;
END;
$rk$;

-- migrate: down

DO $d$
DECLARE
    t text;
BEGIN
    IF to_regclass('auth_rbac.auth_group') IS NULL THEN
        RAISE NOTICE 'auth_rbac tables absent; nothing to revert';
        RETURN;
    END IF;
    FOREACH t IN ARRAY ARRAY['auth_group', 'auth_membership', 'auth_permission',
                             'auth_api_key', 'auth_tenant_settings']
    LOOP
        EXECUTE format('DROP INDEX IF EXISTS auth_rbac.ix_%s_creator_fp', t);
        EXECUTE format('ALTER TABLE auth_rbac.%I DROP COLUMN IF EXISTS creator_fp', t);
    END LOOP;
END;
$d$;

DO $d2$
BEGIN
    IF to_regclass('auth_rbac.auth_tenant_settings') IS NULL THEN
        RETURN;
    END IF;
    DROP INDEX IF EXISTS auth_rbac.uq_auth_tenant_settings_rotate_key_hash;
    ALTER TABLE auth_rbac.auth_tenant_settings
        DROP COLUMN IF EXISTS rotate_key_hash,
        DROP COLUMN IF EXISTS rotate_key_issued_at;
END;
$d2$;
