import argparse
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, cast

from sqlalchemy import Table, create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from auth.audit import AuditAction, AuditLog, client_fingerprint, record_audit
from auth.models.sql import (
    AuthApiKey,
    AuthGroup,
    AuthMembership,
    AuthPermission,
    AuthTenantSettings,
)
from auth.rls import tenant_fingerprint

ADMIN_URL_VARIABLE = "AUTH_ADMIN_DATABASE_URL"
DRIVER_PREFIXES = ("postgresql+psycopg://", "postgres+psycopg://")
MIN_PREFIX = 12
LIST_PREFIX = 16
ROLE_NAMES_WIDTH = 60
AUDIT_CHUNK = 500

_KINDS = (
    ("roles", cast(Table, AuthGroup.__table__)),
    ("permissions", cast(Table, AuthPermission.__table__)),
    ("memberships", cast(Table, AuthMembership.__table__)),
    ("api_keys", cast(Table, AuthApiKey.__table__)),
    ("settings", cast(Table, AuthTenantSettings.__table__)),
)


class AdminError(Exception):
    pass


def admin_url(environ: Mapping[str, str]) -> Optional[str]:
    value = environ.get(ADMIN_URL_VARIABLE, "").strip()
    if not value:
        return None
    for prefix in DRIVER_PREFIXES:
        if value.startswith(prefix):
            return "postgresql+psycopg://" + value[len(prefix) :]
    if value.startswith(("postgresql://", "postgres://")):
        return "postgresql+psycopg://" + value.split("://", 1)[1]
    raise AdminError(f"{ADMIN_URL_VARIABLE} must name a PostgreSQL database")


def _namespaces(conn) -> Dict[str, Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}
    for kind, table in _KINDS:
        rows = conn.execute(
            select(
                table.c.creator,
                func.count(),
                func.min(table.c.date_created),
                func.max(table.c.date_created),
            ).group_by(table.c.creator)
        )
        for creator, count, first, last in rows:
            entry = found.setdefault(
                creator,
                {kind_name: 0 for kind_name, _ in _KINDS}
                | {"first": first, "last": last, "role_names": []},
            )
            entry[kind] = int(count)
            if first is not None and (entry["first"] is None or first < entry["first"]):
                entry["first"] = first
            if last is not None and (entry["last"] is None or last > entry["last"]):
                entry["last"] = last
    groups = cast(Table, AuthGroup.__table__)
    for creator, role in conn.execute(
        select(groups.c.creator, groups.c.role)
        .where(groups.c.is_active.is_(True))
        .order_by(groups.c.role)
    ):
        if creator in found:
            found[creator]["role_names"].append(role)
    return found


def _last_audit(conn, creators: Sequence[str]) -> Dict[str, Optional[datetime]]:
    audit = cast(Table, AuditLog.__table__)
    by_ref = {client_fingerprint(c): c for c in creators}
    refs = list(by_ref)
    last: Dict[str, Optional[datetime]] = dict.fromkeys(creators)
    for start in range(0, len(refs), AUDIT_CHUNK):
        chunk = refs[start : start + AUDIT_CHUNK]
        for ref, when in conn.execute(
            select(audit.c.client_id, func.max(audit.c.timestamp))
            .where(audit.c.client_id.in_(chunk))
            .group_by(audit.c.client_id)
        ):
            last[by_ref[ref]] = when
    return last


def list_namespaces(
    admin_engine: Engine,
    created_from: Optional[datetime] = None,
    created_to: Optional[datetime] = None,
    role: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with admin_engine.connect() as conn:
        found = _namespaces(conn)
        last_audit = _last_audit(conn, list(found))
    result = []
    for creator, entry in found.items():
        if created_from and (entry["first"] is None or entry["first"] < created_from):
            continue
        if created_to and (entry["first"] is None or entry["first"] > created_to):
            continue
        if role and role not in entry["role_names"]:
            continue
        result.append(
            {
                "fingerprint": tenant_fingerprint(creator)[:LIST_PREFIX],
                **{kind: entry[kind] for kind, _ in _KINDS},
                "first_created": entry["first"],
                "last_created": entry["last"],
                "last_audit": last_audit[creator],
                "role_names": entry["role_names"],
            }
        )
    result.sort(key=lambda r: (r["first_created"] or datetime.min, r["fingerprint"]))
    return result


def resolve_namespace(admin_engine: Engine, prefix: str) -> str:
    prefix = prefix.lower()
    if len(prefix) < MIN_PREFIX or any(c not in "0123456789abcdef" for c in prefix):
        raise AdminError(f"--fp needs at least {MIN_PREFIX} hex characters")
    with admin_engine.connect() as conn:
        creators: Set[str] = set()
        for _, table in _KINDS:
            creators.update(c for (c,) in conn.execute(select(table.c.creator).distinct()))
    matches = [c for c in creators if tenant_fingerprint(c).startswith(prefix)]
    if not matches:
        raise AdminError("no namespace has that fingerprint")
    if len(matches) > 1:
        raise AdminError(f"{len(matches)} namespaces share that prefix; give more characters")
    return str(matches[0])


def purge_resolved(session: Session, creator: str) -> Dict[str, Any]:
    from auth.services.service import AuthorizationService

    service = AuthorizationService(
        session, creator, validate_client=False, manage_transaction=False
    )
    deleted = service.purge_namespace()
    record_audit(
        session,
        client_id=client_fingerprint(creator),
        user=None,
        action=AuditAction.PURGE_NAMESPACE,
        resource="namespace",
        details={**{k: v for k, v in deleted.items() if k != "fingerprint"}, "via": "auth-admin"},
        user_agent="auth-admin",
        success=True,
    )
    session.commit()
    return deleted


def _when(value: Optional[datetime]) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else "-"


def _print_list(rows: List[Dict[str, Any]]) -> None:
    print(
        f"{'fingerprint':16}  roles perms members keys settings  "
        f"{'first_created':20}  {'last_created':20}  {'last_audit':20}  role_names"
    )
    for r in rows:
        names = ",".join(r["role_names"])
        if len(names) > ROLE_NAMES_WIDTH:
            names = names[: ROLE_NAMES_WIDTH - 3] + "..."
        print(
            f"{r['fingerprint']:16}  {r['roles']:5} {r['permissions']:5} {r['memberships']:7} "
            f"{r['api_keys']:4} {'yes' if r['settings'] else 'no':8}  {_when(r['first_created']):20}  "
            f"{_when(r['last_created']):20}  {_when(r['last_audit']):20}  {names}"
        )
    print(f"{len(rows)} namespace(s)")


def _parse_time(value: str) -> datetime:
    from auth.key_expiry import parse_expiry

    return parse_expiry(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auth-admin")
    groups = parser.add_subparsers(dest="group", required=True)
    namespaces = groups.add_parser("namespaces").add_subparsers(dest="command", required=True)
    listing = namespaces.add_parser("list")
    listing.add_argument("--created-from", type=_parse_time)
    listing.add_argument("--created-to", type=_parse_time)
    listing.add_argument("--role")
    purge = namespaces.add_parser("purge")
    purge.add_argument("--fp", required=True)
    purge.add_argument("--confirm", required=True)
    return parser


def run(argv: Sequence[str], admin_engine: Engine, session_factory) -> int:
    args = _parser().parse_args(list(argv))
    try:
        if args.command == "list":
            _print_list(
                list_namespaces(admin_engine, args.created_from, args.created_to, args.role)
            )
            return 0
        if args.confirm.lower() != args.fp.lower():
            raise AdminError("--confirm must repeat --fp exactly; nothing was purged")
        creator = resolve_namespace(admin_engine, args.fp)
        session = session_factory()
        try:
            deleted = purge_resolved(session, creator)
        finally:
            session.close()
    except AdminError as error:
        print(f"auth-admin: {error}", file=sys.stderr)
        return 2
    counts = " ".join(f"{k}={v}" for k, v in deleted.items() if k != "fingerprint")
    print(f"purged {tenant_fingerprint(creator)[:LIST_PREFIX]}: {counts}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        url = admin_url(os.environ)
    except AdminError as error:
        print(f"auth-admin: {error}", file=sys.stderr)
        return 2
    if url is None:
        print(f"auth-admin: set {ADMIN_URL_VARIABLE}", file=sys.stderr)
        return 2
    from auth.database import SessionLocal

    admin_engine = create_engine(url, pool_pre_ping=True)
    try:
        return run(sys.argv[1:] if argv is None else argv, admin_engine, SessionLocal)
    finally:
        admin_engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
