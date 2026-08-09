-- migration: partition_audit_log
-- id: 01KZJWHG32K9X1AFBPPB4YJC6A
--
-- audit_log was the whole growth problem: 175k rows / 52 MB, ~79% of the entire
-- database, growing ~4.8k rows/day on average and ~10.7k/day in the most recent
-- month, with no retention or partitioning of any kind. Pruning it by DELETE
-- would bloat the heap and demand a VACUUM FULL (an exclusive lock on the audit
-- trail); pruning it by DROP PARTITION is O(1) and takes no lock on live data.
--
-- This converts auth_rbac.audit_log to a RANGE partitioned table on "timestamp",
-- one partition per month, preserving every row, the sequence position and the
-- query indexes.
--
-- Shape follows the DATABASE, not auth/audit.py: the model declares
-- user = Column(String(64)) but production carries TEXT (the pre-2.x varchar→TEXT
-- reconciliation noted in the 3.0.1 release). Matching the live column keeps
-- create_all(checkfirst=True) and mg apply convergent, which MIGRATIONS.md requires.
--
-- PRIMARY KEY becomes (id, "timestamp") because PostgreSQL requires the partition
-- key to be part of every unique constraint. id remains unique in practice — it is
-- still fed by the single audit_log_id_seq sequence.
--
-- RETENTION IS NOT AUTOMATED HERE ON PURPOSE. Dropping audit history is a
-- compliance decision, not a housekeeping default. This migration ships the
-- mechanism (drop_audit_log_partitions_before) and leaves the policy to an
-- operator who has decided how long auth history must be kept.

-- migrate: up

CREATE SCHEMA IF NOT EXISTS auth_rbac;

-- ---------------------------------------------------------------- provisioning
-- Create one monthly partition if it does not already exist. Idempotent, so it
-- is safe from cron, from a migration, or by hand.
CREATE OR REPLACE FUNCTION auth_rbac.provision_audit_log_partition(p_month date)
RETURNS text
LANGUAGE plpgsql
AS $$
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
$$;

COMMENT ON FUNCTION auth_rbac.provision_audit_log_partition(date) IS
    'Create the monthly audit_log partition covering p_month, if absent. Idempotent.';

-- ------------------------------------------------------------------- retention
-- Drop whole partitions strictly older than the cutoff. Returns what it dropped
-- so the caller can log it. Never touches the DEFAULT partition.
CREATE OR REPLACE FUNCTION auth_rbac.drop_audit_log_partitions_before(p_cutoff date)
RETURNS SETOF text
LANGUAGE plpgsql
AS $$
DECLARE
    r       record;
    v_upper timestamp;
BEGIN
    FOR r IN
        SELECT c.relname,
               pg_get_expr(c.relpartbound, c.oid) AS bound
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = p.relnamespace
        WHERE n.nspname = 'auth_rbac'
          AND p.relname = 'audit_log'
          AND pg_get_expr(c.relpartbound, c.oid) NOT LIKE '%DEFAULT%'
    LOOP
        -- The bound reads: FOR VALUES FROM ('2026-07-01 00:00:00') TO ('2026-08-01 00:00:00')
        -- Capture the WHOLE quoted upper bound. An earlier version matched only
        -- [0-9-]+ and so stopped at the space before the time, yielding NULL —
        -- the IF was then NULL, nothing was dropped, and the function still
        -- reported success. A retention job that silently retains everything is
        -- worse than none, so a parse failure now raises instead of skipping.
        v_upper := substring(r.bound from 'TO \(''([^'']+)''\)')::timestamp;
        IF v_upper IS NULL THEN
            RAISE EXCEPTION 'cannot parse partition bound for auth_rbac.%: %', r.relname, r.bound;
        END IF;

        IF v_upper <= p_cutoff::timestamp THEN
            EXECUTE format('DROP TABLE auth_rbac.%I', r.relname);
            RETURN NEXT format('dropped auth_rbac.%s %s', r.relname, r.bound);
        END IF;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION auth_rbac.drop_audit_log_partitions_before(date) IS
    'Drop audit_log partitions entirely older than p_cutoff. Invoke deliberately: '
    'audit retention is a compliance decision, not a scheduled default.';

-- --------------------------------------------------------------- the conversion
DO $$
DECLARE
    v_is_partitioned boolean;
    v_month date;
    v_max   date;
    v_owner text;
    r       record;
BEGIN
    SELECT c.relkind = 'p', pg_get_userbyid(c.relowner)
      INTO v_is_partitioned, v_owner
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'auth_rbac' AND c.relname = 'audit_log';

    IF v_is_partitioned IS NULL THEN
        RAISE NOTICE 'auth_rbac.audit_log absent; nothing to convert';
        RETURN;
    END IF;
    IF v_is_partitioned THEN
        RAISE NOTICE 'auth_rbac.audit_log already partitioned; nothing to do';
        RETURN;
    END IF;

    -- 1. the new partitioned parent, shaped exactly like the live table
    CREATE TABLE auth_rbac.audit_log__partitioned (
        id          integer NOT NULL DEFAULT nextval('auth_rbac.audit_log_id_seq'),
        "timestamp" timestamp without time zone NOT NULL,
        client_id   text NOT NULL,
        "user"      text,
        action      character varying(50) NOT NULL,
        resource    text,
        details     text,
        ip_address  character varying(45),
        user_agent  text,
        success     integer,
        PRIMARY KEY (id, "timestamp")
    ) PARTITION BY RANGE ("timestamp");

    -- 2. a DEFAULT partition: a trap, not a home. Rows landing here mean the
    --    provisioner fell behind; monitor it rather than rely on it.
    CREATE TABLE auth_rbac.audit_log_default
        PARTITION OF auth_rbac.audit_log__partitioned DEFAULT;

    -- 3. monthly partitions covering all existing data plus 12 months ahead
    SELECT COALESCE(date_trunc('month', min("timestamp"))::date, date_trunc('month', now())::date)
      INTO v_month FROM auth_rbac.audit_log;
    v_max := (date_trunc('month', now()) + interval '12 months')::date;
    WHILE v_month <= v_max LOOP
        EXECUTE format(
            'CREATE TABLE auth_rbac.%I PARTITION OF auth_rbac.audit_log__partitioned '
            'FOR VALUES FROM (%L) TO (%L)',
            'audit_log_' || to_char(v_month, 'YYYY_MM'),
            v_month,
            (v_month + interval '1 month')::date);
        v_month := (v_month + interval '1 month')::date;
    END LOOP;

    -- 4. move the data
    INSERT INTO auth_rbac.audit_log__partitioned
        (id, "timestamp", client_id, "user", action, resource, details, ip_address, user_agent, success)
    SELECT id, "timestamp", client_id, "user", action, resource, details, ip_address, user_agent, success
    FROM auth_rbac.audit_log;

    -- 5. detach the sequence before dropping its old owner, or the DROP cascades
    --    to the sequence and the id counter restarts at 1.
    ALTER SEQUENCE auth_rbac.audit_log_id_seq OWNED BY NONE;

    DROP TABLE auth_rbac.audit_log;
    ALTER TABLE auth_rbac.audit_log__partitioned RENAME TO audit_log;

    -- 6. restore the ORIGINAL owner. The migration runner is a DDL-capable role
    --    (pgadmin in production) which is not necessarily the table owner, and
    --    PostgreSQL refuses "ALTER SEQUENCE ... OWNED BY" when the sequence and
    --    its table have different owners. ALTER TABLE ... OWNER TO does not
    --    cascade to partitions, so each one is set explicitly.
    EXECUTE format('ALTER TABLE auth_rbac.audit_log OWNER TO %I', v_owner);
    FOR r IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'auth_rbac.audit_log'::regclass
    LOOP
        EXECUTE format('ALTER TABLE auth_rbac.%I OWNER TO %I', r.relname, v_owner);
    END LOOP;

    ALTER SEQUENCE auth_rbac.audit_log_id_seq OWNED BY auth_rbac.audit_log.id;
END;
$$;

-- 6. indexes, recreated on the parent so every partition inherits them.
--    ix_..._id mirrors the model's index=True on the primary key column.
CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_id
    ON auth_rbac.audit_log (id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_client_id
    ON auth_rbac.audit_log (client_id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_user
    ON auth_rbac.audit_log ("user");
-- new: retention and time-range queries scan by timestamp; the old table had no
-- index on it at all.
CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_timestamp
    ON auth_rbac.audit_log ("timestamp");

-- migrate: down
-- Collapse back to a single unpartitioned table, preserving rows and the sequence.
DO $$
DECLARE
    v_is_partitioned boolean;
    v_owner text;
BEGIN
    SELECT c.relkind = 'p', pg_get_userbyid(c.relowner)
      INTO v_is_partitioned, v_owner
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'auth_rbac' AND c.relname = 'audit_log';

    IF v_is_partitioned IS NOT TRUE THEN
        RAISE NOTICE 'auth_rbac.audit_log is not partitioned; nothing to revert';
        RETURN;
    END IF;

    CREATE TABLE auth_rbac.audit_log__plain (
        id          integer NOT NULL DEFAULT nextval('auth_rbac.audit_log_id_seq'),
        "timestamp" timestamp without time zone NOT NULL,
        client_id   text NOT NULL,
        "user"      text,
        action      character varying(50) NOT NULL,
        resource    text,
        details     text,
        ip_address  character varying(45),
        user_agent  text,
        success     integer,
        PRIMARY KEY (id)
    );

    INSERT INTO auth_rbac.audit_log__plain
        (id, "timestamp", client_id, "user", action, resource, details, ip_address, user_agent, success)
    SELECT id, "timestamp", client_id, "user", action, resource, details, ip_address, user_agent, success
    FROM auth_rbac.audit_log;

    ALTER SEQUENCE auth_rbac.audit_log_id_seq OWNED BY NONE;
    DROP TABLE auth_rbac.audit_log;
    ALTER TABLE auth_rbac.audit_log__plain RENAME TO audit_log;
    EXECUTE format('ALTER TABLE auth_rbac.audit_log OWNER TO %I', v_owner);
    ALTER SEQUENCE auth_rbac.audit_log_id_seq OWNED BY auth_rbac.audit_log.id;
END;
$$;

CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_id ON auth_rbac.audit_log (id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_client_id ON auth_rbac.audit_log (client_id);
CREATE INDEX IF NOT EXISTS ix_auth_rbac_audit_log_user ON auth_rbac.audit_log ("user");

DROP FUNCTION IF EXISTS auth_rbac.drop_audit_log_partitions_before(date);
DROP FUNCTION IF EXISTS auth_rbac.provision_audit_log_partition(date);
