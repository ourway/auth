-- migration: drop_stale_public_tables
-- id: 01M2Y9FNKBJ513W0XVCYFYPDR9
--
-- This deployment moved its tables from public to auth_rbac and left the
-- originals behind. They have not been written to since 2026-07-03, they are
-- not covered by the Row Level Security added in #19, and they still hold
-- plaintext rows from before the schema move. Nothing reads them; they are a
-- copy of tenant data sitting outside every control the service now has.
--
-- Dropping tables is the one thing in this repo that cannot be rolled back, so
-- the guard is deliberately paranoid. Every one of these must hold, per table:
--
--   1. auth_rbac exists at all. AUTH_DATABASE_SCHEMA is unset by default, so a
--      self-hosted install keeps its LIVE tables in public. There, auth_rbac is
--      absent and this migration must do nothing.
--   2. The auth_rbac counterpart exists and is non-empty -- evidence that the
--      move happened and the live data is there.
--   3. The public copy holds no MORE rows than the auth_rbac one. If it does,
--      public is not the stale side and the assumption behind this migration
--      is wrong; raise instead of guessing.
--
-- Failing any guard skips that table with a NOTICE rather than failing the
-- migration, except guard 3, which aborts: it means the premise is false.

-- migrate: up

DO $c$
DECLARE
    t             text;
    v_public_rows bigint;
    v_live_rows   bigint;
    v_dropped     int := 0;
BEGIN
    IF to_regnamespace('auth_rbac') IS NULL THEN
        RAISE NOTICE 'auth_rbac does not exist; public holds the live tables. Nothing to do.';
        RETURN;
    END IF;

    FOREACH t IN ARRAY ARRAY[
        'auth_group', 'auth_membership', 'auth_permission', 'auth_api_key',
        'auth_tenant_settings', 'membership_groups', 'permission_groups', 'audit_log'
    ] LOOP
        IF to_regclass(format('public.%I', t)) IS NULL THEN
            CONTINUE;
        END IF;
        IF to_regclass(format('auth_rbac.%I', t)) IS NULL THEN
            RAISE NOTICE 'public.% kept: no auth_rbac counterpart exists', t;
            CONTINUE;
        END IF;

        EXECUTE format('SELECT count(*) FROM public.%I', t) INTO v_public_rows;
        EXECUTE format('SELECT count(*) FROM auth_rbac.%I', t) INTO v_live_rows;

        IF v_live_rows = 0 AND v_public_rows > 0 THEN
            RAISE NOTICE 'public.% kept: auth_rbac.% is empty while public holds % row(s)',
                t, t, v_public_rows;
            CONTINUE;
        END IF;
        IF v_public_rows > v_live_rows THEN
            RAISE EXCEPTION 'public.% holds % row(s) against auth_rbac.%''s % - public is '
                'not the stale copy and this migration''s premise is wrong',
                t, v_public_rows, t, v_live_rows;
        END IF;

        RAISE NOTICE 'dropping public.% (% stale row(s); auth_rbac.% has %)',
            t, v_public_rows, t, v_live_rows;
        EXECUTE format('DROP TABLE public.%I CASCADE', t);
        v_dropped := v_dropped + 1;
    END LOOP;

    RAISE NOTICE 'dropped % stale table(s) from public', v_dropped;
END;
$c$;

-- migrate: down

DO $d$
BEGIN
    RAISE NOTICE 'not reversible: the dropped tables held stale copies and were '
        'not backed up by this migration. Restore from a database backup if '
        'they are needed.';
END;
$d$;
