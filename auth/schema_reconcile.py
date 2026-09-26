"""Idempotent schema reconciliations run once at startup, after ``create_all``.

These are not migrations. Migrations own the schema of a deployment that runs
them; these exist because the ORM creates three tables that no migration does
-- ``membership_groups``, ``permission_groups`` and ``audit_log`` -- and because
an embedded consumer on SQLite never runs migretti at all. Each one is safe to
run on every boot and non-raising, so a role without DDL rights can still start:
a deployment where they could not run is caught instead by
``keycheck.verify_row_level_security``, which refuses to serve rather than
serving unprotected.

They run in the order they are defined here, and independently: an exception in
one must not skip the rest, which is how a fresh database once came up with its
junction tables holding every tenant's authorization edges under no policy.
"""

import logging
from typing import Any

from sqlalchemy.engine import Engine

from auth.config import DatabaseType, get_settings

logger = logging.getLogger(__name__)

#: What the last audit-partition runway check saw, so /readyz can report it.
#: Logging is not a channel on every deployment -- vm-2 captures no application
#: log line at all, which makes a CRITICAL there unreachable by anyone.
audit_partition_state: dict = {"checked": False, "stranded": None, "newest": None}

def _apply_tenant_rls(target_engine: Engine) -> None:
    """Secure any tenant-scoped table that ``create_all`` has just created.

    Three tables -- ``membership_groups``, ``permission_groups`` and
    ``audit_log`` -- are created by the ORM rather than by a migration, and the
    ORM runs after migrations. On a fresh database the ``enable_row_level_
    security`` migration therefore found them absent and skipped them, and the
    deployment came up with the junction tables holding every tenant's
    authorization edges under no policy at all.

    ``auth_rbac.apply_tenant_rls()`` is the same DDL that migration runs,
    re-applied here once the ORM has finished. It runs as this role, which owns
    the tables, and it is idempotent: every branch guards on the table existing
    and replaces its own policy.

    PostgreSQL only. Non-raising, like the reconciliations beside it, so that a
    runtime role without DDL rights can still start -- but a deployment where
    this could not run is then caught by ``keycheck.verify_row_level_security``
    at boot and refuses to serve rather than serving unprotected.
    """
    from sqlalchemy import text

    settings = get_settings()
    if settings.database_type != DatabaseType.POSTGRESQL:
        return
    schema = settings.database_schema or "public"
    try:
        with target_engine.begin() as conn:
            result: Any = conn.execute(
                text(f'SELECT {schema}.apply_tenant_rls()')  # noqa: S608
            ).scalar_one()
        logger.info("apply_tenant_rls: %s", result)
    except Exception as exc:
        logger.warning(
            "apply_tenant_rls could not run (%s); the boot check will refuse "
            "to serve if row level security is not in force",
            exc.__class__.__name__,
        )


def _ensure_audit_partition_runway(target_engine: Engine, months: int = 6) -> None:
    """Keep monthly audit_log partitions provisioned ahead of now.

    Partitions are finite and nothing renewed them. When they run out, rows do
    not fail -- they land in audit_log_default, which
    drop_audit_log_partitions_before deliberately skips, so retention can never
    reclaim them and the growth problem partitioning solved returns with no
    visible symptom (issuedb #15; production runway ended 2027-08).

    Called here rather than scheduled in-process: create_tables runs pre-fork
    under preload_app, so this executes once per service start, not once per
    worker, and holds no thread across fork. A cron on the database-adjacent
    host is still the durable answer for a deployment that runs longer than its
    runway without restarting; this removes the cliff for one that restarts.

    Non-raising, like everything beside it. A deployment whose role cannot
    create partitions still starts, and rows in the default partition are
    reported loudly below rather than silently absorbed.
    """
    from sqlalchemy import text

    settings = get_settings()
    if settings.database_type != DatabaseType.POSTGRESQL:
        return
    schema = settings.database_schema or "public"
    try:
        with target_engine.begin() as conn:
            if conn.execute(
                text("SELECT to_regproc(:fn) IS NULL"),
                {"fn": f"{schema}.provision_audit_log_partition"},
            ).scalar():
                logger.info(
                    "audit partition runway: provisioner absent, skipping"
                )
                return
            created = []
            for ahead in range(months + 1):
                result: Any = conn.execute(
                    text(
                        f"SELECT {schema}.provision_audit_log_partition("  # noqa: S608
                        "(date_trunc('month', now()) + make_interval(months => :n))::date)"
                    ),
                    {"n": ahead},
                ).scalar_one()
                if "created" in str(result):
                    created.append(str(result))
            stranded: int = conn.execute(
                text(f"SELECT count(*) FROM {schema}.audit_log_default")  # noqa: S608
            ).scalar_one()
            newest = conn.execute(
                text(
                    "SELECT c.relname FROM pg_class c "
                    "JOIN pg_inherits i ON i.inhrelid = c.oid "
                    "WHERE i.inhparent = to_regclass(:p) "
                    "AND c.relname <> 'audit_log_default' "
                    "ORDER BY c.relname DESC LIMIT 1"
                ),
                {"p": f"{schema}.audit_log"},
            ).scalar()
    except Exception as exc:
        logger.warning(
            "audit partition runway could not be ensured (%s); "
            "if partitions run out, rows land in audit_log_default and "
            "retention cannot reclaim them",
            exc.__class__.__name__,
        )
        return

    audit_partition_state.update(
        {"checked": True, "stranded": int(stranded), "newest": newest}
    )
    logger.info(
        "audit partition runway: %d month(s) ahead, %d created this start",
        months,
        len(created),
    )
    if stranded:
        logger.critical(
            "AUDIT PARTITION RUNWAY WAS EXHAUSTED: %d row(s) are in "
            "audit_log_default. Retention skips that partition, so they can "
            "never be reclaimed. They must be moved into a real partition by "
            "hand once one covers their timestamps.",
            stranded,
        )


def _reconcile_text_columns(target_engine: Engine) -> None:
    """Widen live ``character varying`` columns to TEXT where the current models
    declare :class:`~sqlalchemy.Text` (issuedb #21).

    ``create_all(checkfirst=True)`` creates missing tables but never ALTERs an
    existing one, so an embedded database created by a pre-2.x version keeps the
    narrow ``varchar`` widths those versions declared. Encryption made several of
    those columns hold ciphertext far longer than the plaintext they used to, so
    the mismatch surfaces as ``StringDataRightTruncation`` on write — highway hit
    exactly this on ``auth_membership.user`` (varchar(64)) when a longer email
    was encrypted, inside ``add_membership`` (agent-mail thr-d99bb6c79b894ff69f16).

    Only columns the models declare as Text are touched. A bounded ``String`` is
    a deliberate width — ``audit_log.user`` is a 64-char fingerprint, not a user
    identifier — and is left alone. PostgreSQL only: SQLite does not enforce
    varchar length, so there is nothing to reconcile there.

    Non-raising, like everything else in ``create_tables``: a runtime role
    without DDL rights must still be able to start the app.
    """
    from sqlalchemy import Text, inspect, text

    import auth.audit  # noqa: F401  (registers AuditLog in Base.metadata)
    from auth.models.sql import Base

    if target_engine.dialect.name != "postgresql":
        return

    settings = get_settings()
    schema = settings.database_schema or None
    inspector = inspect(target_engine)
    try:
        existing_tables = set(inspector.get_table_names(schema=schema))
    except Exception:
        logger.exception("text-column reconciliation could not list tables")
        return

    widened: list[str] = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        wanted = {c.name for c in table.columns if isinstance(c.type, Text)}
        if not wanted:
            continue
        try:
            live = inspector.get_columns(table.name, schema=schema)
        except Exception:
            logger.exception(
                "text-column reconciliation could not inspect %s", table.name
            )
            continue
        for col in live:
            if col["name"] not in wanted:
                continue
            # VARCHAR carries a length; TEXT does not. Anything already
            # unbounded needs no ALTER, which keeps this pass a no-op on a
            # database that already matches the models.
            if getattr(col["type"], "length", None) is None:
                continue
            qualified = f'"{schema}".' if schema else ""
            stmt = (
                f'ALTER TABLE {qualified}"{table.name}" '
                f'ALTER COLUMN "{col["name"]}" TYPE TEXT'
            )
            try:
                with target_engine.begin() as conn:
                    conn.execute(text(stmt))
                widened.append(f"{table.name}.{col['name']}")
            except Exception:
                logger.exception(
                    "could not widen %s.%s to TEXT; a pre-2.x column width "
                    "remains and long encrypted values may fail to write",
                    table.name,
                    col["name"],
                )

    if widened:
        logger.warning(
            "widened %d pre-2.x varchar column(s) to TEXT to match the current "
            "models: %s",
            len(widened),
            ", ".join(widened),
        )


# Marker creator recording that the one-shot 3.0.0 grandfathering pass ran on
# this database. Reserved — never use it as a real tenant identifier.
GRANDFATHER_MARKER = "__meta:grandfathered-3.0__"


def _tenant_rls_in_force(target_engine: Engine) -> bool:
    """True when ``auth_tenant_settings`` carries a policy this role obeys.

    Read rather than inferred from configuration: a deployment can have the
    migrations applied or not, and the answer decides whether a cross-tenant
    pass is possible at all.
    """
    from sqlalchemy import text

    settings = get_settings()
    if settings.database_type != DatabaseType.POSTGRESQL:
        return False
    schema = settings.database_schema or "public"
    try:
        with target_engine.connect() as conn:
            return bool(
                conn.execute(
                    text(
                        "SELECT c.relrowsecurity AND c.relforcerowsecurity "
                        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = :s AND c.relname = 'auth_tenant_settings'"
                    ),
                    {"s": schema},
                ).scalar()
            )
    except Exception:
        return False


def _grandfather_strict_users(target_engine: Engine) -> None:
    """One-shot 3.0.0 flip protection (SPEC 0012): write explicit
    ``strict_users = false`` rows for every creator that exists on this
    database, then record a marker so the pass never runs again.

    3.0.0 makes no-settings-row tenants strict by default; this pass is what
    guarantees that flip reaches ONLY tenants created after it ran — every
    pre-existing tenant keeps its behavior as an explicit, auditable opt-out
    it can change later. Runs inside create_tables so embedded consumers get
    the same protection our deployment gets from the migretti migration
    (both are marker-guarded, so they compose idempotently).
    """
    from typing import cast

    from sqlalchemy import Table, literal, select, union

    from auth.models.sql import (
        AuthApiKey,
        AuthGroup,
        AuthMembership,
        AuthPermission,
        AuthTenantSettings,
    )

    settings_t = cast(Table, AuthTenantSettings.__table__)
    if _tenant_rls_in_force(target_engine):
        logger.info(
            "strict_users grandfathering skipped: row level security is in "
            "force, so this role cannot see or write another tenant's settings "
            "row. The grandfather_strict_users migration owns this pass on a "
            "database that has policies."
        )
        return
    with target_engine.begin() as conn:
        marker_exists = conn.execute(
            select(settings_t.c.id).where(settings_t.c.creator == GRANDFATHER_MARKER)
        ).first()
        if marker_exists:
            return
        creators = union(
            *(
                select(t.__table__.c.creator)
                for t in (AuthGroup, AuthMembership, AuthPermission, AuthApiKey)
            )
        ).subquery()
        already = select(settings_t.c.creator)
        conn.execute(
            settings_t.insert().from_select(
                ["creator", "strict_users"],
                select(creators.c.creator, literal(False)).where(
                    creators.c.creator.notin_(already)
                ),
            )
        )
        conn.execute(
            settings_t.insert().values(creator=GRANDFATHER_MARKER, strict_users=False)
        )
    logger.info("strict_users grandfathering pass completed (one-shot).")
