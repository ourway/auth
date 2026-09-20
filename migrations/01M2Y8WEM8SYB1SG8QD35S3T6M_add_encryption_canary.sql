-- migration: add_encryption_canary
-- id: 01M2Y8WEM8SYB1SG8QD35S3T6M
--
-- A place to keep a known value encrypted under the deployment's own key, so
-- boot can tell whether that key still reads this deployment's data (#12).
--
-- Why this exists at all: the previous check sampled encrypted rows across
-- tenants. Under Row Level Security it would see none, report "nothing
-- encrypted to verify against", and pass -- silently disabling the check that
-- catches a changed encryption key. A canary under a reserved tenant is
-- readable by binding that tenant explicitly, so the check keeps working with
-- RLS in force.
--
-- The reserved tenant is the nil UUID. It cannot collide with a real namespace
-- because the client-key validator requires a genuine v4, so the nil UUID is
-- refused at the door and can never be a caller's key.

-- migrate: up

DO $c$
BEGIN
    IF to_regclass('auth_rbac.auth_tenant_settings') IS NULL THEN
        RAISE NOTICE 'auth_tenant_settings absent; nothing to do';
        RETURN;
    END IF;
    ALTER TABLE auth_rbac.auth_tenant_settings
        ADD COLUMN IF NOT EXISTS canary text;
END;
$c$;

-- migrate: down

DO $d$
BEGIN
    IF to_regclass('auth_rbac.auth_tenant_settings') IS NULL THEN
        RETURN;
    END IF;
    ALTER TABLE auth_rbac.auth_tenant_settings DROP COLUMN IF EXISTS canary;
END;
$d$;
