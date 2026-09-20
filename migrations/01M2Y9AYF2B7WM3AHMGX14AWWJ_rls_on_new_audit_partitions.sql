-- migration: rls_on_new_audit_partitions
-- id: 01M2Y9AYF2B7WM3AHMGX14AWWJ
--
-- enable_row_level_security protected the audit_log partitions that existed
-- when it ran. provision_audit_log_partition creates new ones every month and
-- knew nothing about RLS, so every partition created after that migration
-- would carry none: a direct query against auth_rbac.audit_log_2027_10 as the
-- application role would return every tenant's entries.
--
-- The partition gets ENABLE and FORCE and no policy of its own. Read through
-- the parent -- which is the only way the application reads it -- the parent's
-- policy applies and scoping is unchanged. Read directly, no policy matches
-- and the answer is no rows. Adding a policy here instead would duplicate the
-- parent's predicate into a function that is not re-run when that predicate
-- changes, which is the sync-bug class this design avoids elsewhere.
--
-- Also backfills any partition that already slipped through.

-- migrate: up

DO $c$
DECLARE
    r record;
BEGIN
    IF to_regclass('auth_rbac.audit_log') IS NULL THEN
        RAISE NOTICE 'audit_log absent; nothing to do';
        RETURN;
    END IF;
    FOR r IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        WHERE i.inhparent = 'auth_rbac.audit_log'::regclass
          AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
    LOOP
        EXECUTE format('ALTER TABLE auth_rbac.%I ENABLE ROW LEVEL SECURITY', r.relname);
        EXECUTE format('ALTER TABLE auth_rbac.%I FORCE ROW LEVEL SECURITY', r.relname);
        RAISE NOTICE 'row level security forced on auth_rbac.%', r.relname;
    END LOOP;
END;
$c$;

CREATE OR REPLACE FUNCTION auth_rbac.provision_audit_log_partition(p_month date)
RETURNS text
LANGUAGE plpgsql
AS $f$
DECLARE
    v_start date := date_trunc('month', p_month)::date;
    v_end   date := (date_trunc('month', p_month) + interval '1 month')::date;
    v_name  text := format('audit_log_%s', to_char(v_start, 'YYYY_MM'));
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'auth_rbac' AND c.relname = v_name
    ) THEN
        RETURN format('auth_rbac.%s already exists', v_name);
    END IF;

    EXECUTE format(
        'CREATE TABLE auth_rbac.%I PARTITION OF auth_rbac.audit_log '
        'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);
    EXECUTE format('ALTER TABLE auth_rbac.%I ENABLE ROW LEVEL SECURITY', v_name);
    EXECUTE format('ALTER TABLE auth_rbac.%I FORCE ROW LEVEL SECURITY', v_name);
    RETURN format('created auth_rbac.%s [%s, %s)', v_name, v_start, v_end);
END;
$f$;

COMMENT ON FUNCTION auth_rbac.provision_audit_log_partition(date) IS
    'Create the monthly audit_log partition covering p_month, with row level '
    'security enabled and forced, if absent. Idempotent.';

-- migrate: down

CREATE OR REPLACE FUNCTION auth_rbac.provision_audit_log_partition(p_month date)
RETURNS text
LANGUAGE plpgsql
AS $f$
DECLARE
    v_start date := date_trunc('month', p_month)::date;
    v_end   date := (date_trunc('month', p_month) + interval '1 month')::date;
    v_name  text := format('audit_log_%s', to_char(v_start, 'YYYY_MM'));
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'auth_rbac' AND c.relname = v_name
    ) THEN
        RETURN format('auth_rbac.%s already exists', v_name);
    END IF;

    EXECUTE format(
        'CREATE TABLE auth_rbac.%I PARTITION OF auth_rbac.audit_log '
        'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);
    RETURN format('created auth_rbac.%s [%s, %s)', v_name, v_start, v_end);
END;
$f$;
