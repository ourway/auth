"""Falsifies: "auth's declared dependencies are the ones it actually runs."

A venv created with ``include-system-site-packages = true`` resolves imports
from the host's site-packages whenever the venv has no copy of its own. The
service then runs code that no deploy installed, no commit pinned and no review
saw, and every ordinary check agrees it is fine: ``pip list`` inside the venv
reports inherited packages as though the venv owned them, and the versions can
sit comfortably inside the ranges in pyproject.toml.

This probe asks each critical dependency where it actually resolved from, and
whether that version satisfies what pyproject declares. Two different failures,
reported separately:

``provenance``
    The module came from outside the venv. Its version is then a property of
    the host, changeable by any other service's operator with one install.
``range``
    The resolved version falls outside the declared specifier -- a dependency
    that pip never had the chance to reject.

Run it against the DEPLOYED interpreter, which is the only place the question
means anything:

    AUDIT_PYTHON=/opt/auth/venv/bin/python \
    AUDIT_PROJECT=/opt/auth/app python3 probe_dependency_provenance.py

``AUDIT_PROJECT`` says where to read pyproject.toml from, so the probe can be
run from anywhere against a deployed tree.

Exit 0 all resolved inside the venv and in range, 1 something did not, 2 the
probe could not determine the answer.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

CRITICAL = ("flask", "sqlalchemy", "psycopg", "pydantic", "cryptography", "werkzeug")

_PROJECT = Path(os.environ.get("AUDIT_PROJECT") or Path(__file__).resolve().parent.parent.parent)


def _declared():
    try:
        import tomllib  # type: ignore[import-not-found,unused-ignore]
    except ModuleNotFoundError:
        return {}
    data = tomllib.loads((_PROJECT / "pyproject.toml").read_text())
    out = {}
    for dep in data.get("project", {}).get("dependencies", []):
        name = ""
        for ch in dep:
            if ch.isalnum() or ch in "-_.":
                name += ch
            else:
                break
        out[name.lower().replace("-", "_")] = dep[len(name):].strip()
    return out


_INTROSPECT = r"""
import importlib, json, os, sys, sysconfig
names = json.loads(sys.argv[1])
out = {"prefix": sys.prefix, "base_prefix": sys.base_prefix, "mods": {}}
for n in names:
    try:
        m = importlib.import_module(n)
    except Exception as exc:
        out["mods"][n] = {"error": type(exc).__name__}
        continue
    try:
        import importlib.metadata as md
        v = md.version(n.replace("_", "-"))
    except Exception:
        v = getattr(m, "__version__", None)
    f = getattr(m, "__file__", None)
    out["mods"][n] = {"version": v, "path": os.path.dirname(f) if f else None}
print(json.dumps(out))
"""


def _introspect(python):
    proc = subprocess.run(
        [python, "-c", _INTROSPECT, json.dumps(list(CRITICAL))],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:200]
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1]), None
    except Exception as exc:
        return None, f"unparseable output: {type(exc).__name__}"


def _in_range(version, spec):
    if not spec or not version:
        return None
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
    except ModuleNotFoundError:
        return None
    try:
        return Version(version) in SpecifierSet(spec)
    except Exception:
        return None


def main():
    python = os.environ.get("AUDIT_PYTHON") or sys.executable
    print(f"interpreter under test: {python}")

    info, err = _introspect(python)
    if info is None:
        print(f"UNKNOWN: could not introspect the interpreter: {err}")
        return 2

    prefix, base = info["prefix"], info["base_prefix"]
    print(f"sys.prefix      {prefix}")
    print(f"sys.base_prefix {base}")
    if prefix == base:
        print("note: not running inside a venv, so every module is a system module")

    declared = _declared()
    if not declared:
        print("UNKNOWN: could not read dependency declarations from pyproject.toml")
        return 2

    # A probe that finds every module outside the venv would report the same
    # thing if the path test were simply broken, so establish that it can say
    # "inside" before any "outside" is believed.
    control = subprocess.run(
        [python, "-c", "import sys, os, sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    print(f"CONTROL venv purelib resolves to: {control or '(unknown)'}")
    if not control:
        print("UNKNOWN: could not establish where this interpreter's own packages live")
        return 2
    if not control.startswith(prefix):
        print(f"UNKNOWN: purelib {control} is not under sys.prefix {prefix}")
        return 2
    print("CONTROL ok: the path test can identify an in-venv location\n")

    bad_provenance, bad_range, unknown = [], [], []
    for name in CRITICAL:
        row = info["mods"].get(name, {})
        if "error" in row:
            unknown.append(f"{name} ({row['error']})")
            print(f"  {name:<14} IMPORT FAILED: {row['error']}")
            continue
        version, path = row.get("version"), row.get("path") or ""
        inside = path.startswith(prefix) and prefix != base
        spec = declared.get(name, "")
        ok_range = _in_range(version, spec)
        loc = "VENV" if inside else "SYSTEM"
        rng = {True: "in range", False: "OUT OF RANGE", None: "range unknown"}[ok_range]
        print(f"  {name:<14} {str(version):<12} {loc:<7} {spec or '(undeclared)':<22} {rng}")
        print(f"                 {path}")
        if not inside:
            bad_provenance.append(name)
        if ok_range is False:
            bad_range.append(f"{name}=={version} violates {spec}")
        if ok_range is None and spec:
            unknown.append(f"{name} (range not evaluated)")

    print()
    if bad_provenance:
        print("FAIL provenance: resolved from OUTSIDE the venv: " + ", ".join(bad_provenance))
        print("  These versions are host state. Another service's operator can change")
        print("  them with one install -- no deploy, no commit, no review, no CI.")
    if bad_range:
        print("FAIL range: " + "; ".join(bad_range))
    if unknown:
        print("NOTE unresolved: " + ", ".join(unknown))

    if bad_provenance or bad_range:
        return 1
    print("PASS: every critical dependency resolved from inside the venv and in range")
    return 0


if __name__ == "__main__":
    sys.exit(main())
