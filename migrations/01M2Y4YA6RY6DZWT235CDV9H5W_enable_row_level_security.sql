-- migration: enable_row_level_security
-- id: 01M2Y4YA6RY6DZWT235CDV9H5W
--
-- Turns tenant isolation from a code convention into a database invariant
-- (issuedb #19). Until now every read path filtered on `creator` because each
-- query said so; a single query that forgot would have returned every tenant's
-- rows with nothing underneath to stop it.
--
-- RUN THIS ONLY AFTER the application that binds a tenant to each transaction
-- is deployed (auth/rls.py). The policies below resolve to NULL when no tenant
-- is bound, which matches no row -- so enabling this against older code answers
-- every authorization question with "denied". That is fail-closed, but for this
-- service it is an outage, not a safe default.
--
-- FORCE, not merely ENABLE. The application connects as `auth`, and `auth` owns
-- these tables. PostgreSQL does not apply RLS to a table's owner, so ENABLE
-- alone would leave every row visible while pg_class, the policy list and any
-- casual check all looked correct. FORCE is what makes it real, and the probe
-- in audit/evaluations/ asserts isolation as the app role rather than asserting
-- that policies exist.
--
-- The migration runner (pgadmin) is a superuser and bypasses RLS entirely, so
-- migrations and DBA work are unaffected by design. This protects the
-- application path, which is the leak path.

-- migrate: up

DO $rls$
DECLARE
    t     text;
    part  text;
    tenant_tables text[] := ARRAY['auth_group', 'auth_membership', 'auth_permission',
                                  'auth_api_key', 'auth_tenant_settings'];
BEGIN
    IF to_regclass('auth_rbac.auth_group') IS NULL THEN
        RAISE NOTICE 'auth_rbac tables absent; nothing to secure';
        RETURN;
    END IF;

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
            USING (creator_fp = current_setting('auth.tenant_fp', true))
            WITH CHECK (creator_fp = current_setting('auth.tenant_fp', true)
                        OR creator_fp = current_setting('auth.rotating_to_fp', true))
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
                             AND m.creator_fp = current_setting('auth.tenant_fp', true)))
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
                             AND p.creator_fp = current_setting('auth.tenant_fp', true)))
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
END;
$rls$;

-- migrate: down

DO $undo$
DECLARE
    t text;
BEGIN
    IF to_regclass('auth_rbac.auth_group') IS NULL THEN
        RETURN;
    END IF;
    FOREACH t IN ARRAY ARRAY['auth_group', 'auth_membership', 'auth_permission',
                             'auth_api_key', 'auth_tenant_settings',
                             'membership_groups', 'permission_groups', 'audit_log']
    LOOP
        IF to_regclass('auth_rbac.' || t) IS NOT NULL THEN
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON auth_rbac.%I', t);
            EXECUTE format('ALTER TABLE auth_rbac.%I NO FORCE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE auth_rbac.%I DISABLE ROW LEVEL SECURITY', t);
        END IF;
    END LOOP;
    DROP POLICY IF EXISTS rotate_key_lookup ON auth_rbac.auth_tenant_settings;
END;
$undo$;
