-- migration: add_apply_tenant_rls_function
-- id: 01M2Y9WFEY32ZWDP161SHR1B2M
--
-- enable_row_level_security secured the tables that existed when it ran. On a
-- FRESH database that is only five of them: membership_groups,
-- permission_groups and audit_log are not created by any migration -- the ORM
-- creates them at first boot, after migrations have finished. So a brand new
-- deployment came up with the junction tables holding every tenant's
-- authorization edges and no policy over them at all.
--
-- The same DDL is therefore moved into a function the application calls right
-- after create_all, next to the other idempotent reconciliations
-- (_reconcile_text_columns, _grandfather_strict_users). It is the same block,
-- not a copy of it: every branch already guarded on the table existing and
-- already DROP..CREATEd its policy, so it was idempotent before it was a
-- function.
--
-- Not SECURITY DEFINER. It runs as the caller, which is the role that owns the
-- tables -- the only role whose ALTER TABLE here means anything, and the role
-- FORCE exists to constrain.

-- migrate: up

CREATE OR REPLACE FUNCTION auth_rbac.apply_tenant_rls()
RETURNS text
LANGUAGE plpgsql
AS $fn$
DECLARE
    t     text;
    part  text;
    tenant_tables text[] := ARRAY['auth_group', 'auth_membership', 'auth_permission',
                                  'auth_api_key', 'auth_tenant_settings'];
BEGIN
    IF to_regclass('auth_rbac.auth_group') IS NULL THEN
        RETURN 'auth_rbac tables absent; nothing to secure';
    END IF;

--    USING admits auth.rotating_to_fp as well as the caller's own tenant, and
--    that is NOT belt-and-braces -- it is required. On an UPDATE, PostgreSQL
--    applies the USING clause to the row AFTER the update as well as before:
--    a rotated row no longer satisfies `creator_fp = auth.tenant_fp`, so a
--    USING clause naming only the caller rejects the rotation with "new row
--    violates row-level security policy" even though WITH CHECK would have
--    admitted it. Measured, not assumed: replacing USING with `true` made the
--    same statement succeed.
--
--    WITH CHECK recomputes the fingerprint inline from `creator` rather than
--    reading `creator_fp`, so it never depends on when a generated column is
--    materialised relative to the policy check.
--
--    auth.rotating_to_fp is transaction-local and set only inside
--    rotate_client_key, so outside a rotation both clauses reduce to the
--    caller's own tenant.
    -- 1. The five tables that carry `creator` directly.
    --
    -- WITH CHECK admits auth.rotating_to_fp as well, because key rotation
    -- legitimately moves a namespace from one tenant to another: the USING
    -- clause matches the row as it is, and WITH CHECK has to admit the row as
    -- it will be. Without that second branch rotation would be refused by the
    -- very control meant to protect it, and the alternative -- running rotation
    -- with elevated privilege -- would put the one operation that crosses
    -- tenants outside the policy entirely.
    FOREACH t IN ARRAY tenant_tables
    LOOP
        EXECUTE format('ALTER TABLE auth_rbac.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE auth_rbac.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON auth_rbac.%I', t);
        EXECUTE format($p$
            CREATE POLICY tenant_isolation ON auth_rbac.%I
            FOR ALL
            USING (creator_fp = ANY (ARRAY[
                       current_setting('auth.tenant_fp', true),
                       current_setting('auth.rotating_to_fp', true)]))
            WITH CHECK (encode(sha256(creator::bytea), 'hex') = ANY (ARRAY[
                       current_setting('auth.tenant_fp', true),
                       current_setting('auth.rotating_to_fp', true)]))
        $p$, t);
    END LOOP;

    -- 2. Recovery needs to find one settings row BEFORE the tenant is known,
    --    because the caller has lost the client key and presents only a rotate
    --    key. Policies are permissive and OR together, so this adds exactly one
    --    reachable row -- the one whose stored hash matches what was presented
    --    -- and nothing else. An attacker must already hold a 256-bit secret.
    DROP POLICY IF EXISTS rotate_key_lookup ON auth_rbac.auth_tenant_settings;
    CREATE POLICY rotate_key_lookup ON auth_rbac.auth_tenant_settings
        FOR SELECT
        USING (rotate_key_hash IS NOT NULL
               AND rotate_key_hash = current_setting('auth.recover_fp', true));

    -- 3. The junction tables hold the actual authorization edges and have no
    --    tenant column of their own. The policy reaches through to the parent
    --    by primary key rather than denormalising a fingerprint onto them:
    --    a copied column can drift from its source, and this cannot.
    IF to_regclass('auth_rbac.membership_groups') IS NOT NULL THEN
        ALTER TABLE auth_rbac.membership_groups ENABLE ROW LEVEL SECURITY;
        ALTER TABLE auth_rbac.membership_groups FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS tenant_isolation ON auth_rbac.membership_groups;
        CREATE POLICY tenant_isolation ON auth_rbac.membership_groups
            FOR ALL
            USING (EXISTS (SELECT 1 FROM auth_rbac.auth_membership m
                           WHERE m.id = membership_id
                             AND m.creator_fp = ANY (ARRAY[
                                 current_setting('auth.tenant_fp', true),
                                 current_setting('auth.rotating_to_fp', true)])))
            WITH CHECK (EXISTS (SELECT 1 FROM auth_rbac.auth_membership m
                                WHERE m.id = membership_id
                                  AND m.creator_fp IN (
                                      current_setting('auth.tenant_fp', true),
                                      current_setting('auth.rotating_to_fp', true))));
    END IF;

    IF to_regclass('auth_rbac.permission_groups') IS NOT NULL THEN
        ALTER TABLE auth_rbac.permission_groups ENABLE ROW LEVEL SECURITY;
        ALTER TABLE auth_rbac.permission_groups FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS tenant_isolation ON auth_rbac.permission_groups;
        CREATE POLICY tenant_isolation ON auth_rbac.permission_groups
            FOR ALL
            USING (EXISTS (SELECT 1 FROM auth_rbac.auth_permission p
                           WHERE p.id = permission_id
                             AND p.creator_fp = ANY (ARRAY[
                                 current_setting('auth.tenant_fp', true),
                                 current_setting('auth.rotating_to_fp', true)])))
            WITH CHECK (EXISTS (SELECT 1 FROM auth_rbac.auth_permission p
                                WHERE p.id = permission_id
                                  AND p.creator_fp IN (
                                      current_setting('auth.tenant_fp', true),
                                      current_setting('auth.rotating_to_fp', true))));
    END IF;

    -- 4. audit_log already carries a tenant discriminator: client_id holds the
    --    pepper-based fingerprint and is what GET /api/audit already filters on,
    --    so it needs no new column. Partitions are secured individually as well
    --    as through the parent, so querying a partition directly is not a way
    --    around the policy.
    IF to_regclass('auth_rbac.audit_log') IS NOT NULL THEN
        ALTER TABLE auth_rbac.audit_log ENABLE ROW LEVEL SECURITY;
        ALTER TABLE auth_rbac.audit_log FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS tenant_isolation ON auth_rbac.audit_log;
        CREATE POLICY tenant_isolation ON auth_rbac.audit_log
            FOR ALL
            USING (client_id = current_setting('auth.audit_fp', true))
            WITH CHECK (client_id = current_setting('auth.audit_fp', true));

        FOR part IN
            SELECT c.relname FROM pg_class c
            JOIN pg_inherits i ON i.inhrelid = c.oid
            WHERE i.inhparent = 'auth_rbac.audit_log'::regclass AND c.relkind = 'r'
        LOOP
            EXECUTE format('ALTER TABLE auth_rbac.%I ENABLE ROW LEVEL SECURITY', part);
            EXECUTE format('ALTER TABLE auth_rbac.%I FORCE ROW LEVEL SECURITY', part);
        END LOOP;
    END IF;
    RETURN 'row level security applied';
END;
$fn$;

COMMENT ON FUNCTION auth_rbac.apply_tenant_rls() IS
    'Enable, force and policy row level security on every tenant-scoped table '
    'that currently exists. Idempotent; called at application startup.';

SELECT auth_rbac.apply_tenant_rls();

-- migrate: down

DROP FUNCTION IF EXISTS auth_rbac.apply_tenant_rls();
