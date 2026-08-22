"""Dump the auth package's externally visible surface as a stable text blob.

Used to prove a refactor changed nothing: run it before the change, run it
after, diff the two. Covers the HTTP route table (path, methods, endpoint) and
the importable symbols at every module path consumers use.
"""

import inspect
import os
import sys

os.environ.setdefault("AUTH_DATABASE_TYPE", "sqlite")
os.environ.setdefault("AUTH_SQLITE_PATH", ":memory:")
os.environ.setdefault("AUTH_JWT_SECRET_KEY", "surface-snapshot-secret-key")
os.environ.setdefault("AUTH_ENABLE_ENCRYPTION", "false")

# Module paths consumers import from, and the names each must keep resolving.
_WATCHED = [
    "auth",
    "auth.client",
    "auth.routes",
    "auth.docs_page",
    "auth.services.service",
]


def _owned_by_auth(value) -> bool:
    """Is this symbol ours, or a re-exported third-party object?"""
    mod = getattr(value, "__module__", "") or ""
    return mod == "auth" or mod.startswith("auth.")


def _signature(value) -> str:
    """Signature text, but only for symbols this package owns.

    Third-party signatures (urllib3's Retry, say) embed frozenset defaults whose
    repr order follows PYTHONHASHSEED, which would make the snapshot differ from
    itself run to run and drown a real regression in noise.
    """
    if not (inspect.isfunction(value) or inspect.isclass(value)):
        return ""
    if not _owned_by_auth(value):
        return "(<foreign>)"
    try:
        return str(inspect.signature(value))
    except (TypeError, ValueError):
        return "<no signature>"


def _members(obj):
    out = []
    for name, value in sorted(vars(obj).items()):
        if name.startswith("__"):
            continue
        out.append((name, type(value).__name__, _signature(value)))
    return out


def main() -> int:
    lines = []

    from auth.main import app

    lines.append("=== ROUTES ===")
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: (str(r), r.endpoint)):
        methods = ",".join(sorted(rule.methods or set()))
        lines.append(f"{rule.rule}  [{methods}]  -> {rule.endpoint}")

    lines.append("")
    lines.append("=== PUBLIC SYMBOLS ===")
    for modname in _WATCHED:
        mod = __import__(modname, fromlist=["*"])
        lines.append(f"--- {modname} ---")
        exported = getattr(mod, "__all__", None)
        if exported is not None:
            lines.append(f"__all__ = {sorted(exported)}")
        for name, kind, sig in _members(mod):
            lines.append(f"{name}: {kind}{sig}")

    lines.append("")
    lines.append("=== CLASS SURFACES ===")
    from auth import Authorization
    from auth.client import Client, EnhancedAuthClient
    from auth.services.service import AuthorizationService

    for cls in (AuthorizationService, EnhancedAuthClient, Client, Authorization):
        lines.append(f"--- {cls.__module__}.{cls.__qualname__} ---")
        for name in sorted(dir(cls)):
            if name.startswith("__"):
                continue
            value = inspect.getattr_static(cls, name, None)
            sig = _signature(getattr(cls, name, None))
            lines.append(f"{name}: {type(value).__name__}{sig}")

    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
