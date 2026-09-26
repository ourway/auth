"""Falsifies: "no package the deployment actually resolves has a known advisory."

Asks OSV about every distribution the target interpreter would import, using the
FIRST distribution of each name on ``sys.path`` -- which is what an import gets,
and which differs from a host package inventory whenever a venv inherits system
site-packages. That difference produced three false findings against auth in one
day (setuptools shadowed by a newer venv copy, h2 and anyio present but never
imported) and one real one (click, reached through Flask from a host package).

Deliberately provenance-agnostic. It answers "is the version we resolve known
vulnerable", not "does the venv own it". Those are different questions with
different owners: the second is ``probe_dependency_provenance.py``. A fix
delivered as a patched HOST package is a legitimate remedy and must not fail
here.

Requires network. Not in ``run_all.sh``'s safe set for that reason -- a probe
that cannot reach OSV would otherwise turn an offline run into a red one.

    AUDIT_PYTHON=/opt/auth/venv/bin/python python3 probe_osv_resolved_set.py

Exit 0 nothing known, 1 at least one advisory, 2 the probe could not answer.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

OSV_BATCH = "https://api.osv.dev/v1/querybatch"

# A version OSV certainly knows about. If this returns nothing, the sweep is not
# working and a clean result below would mean nothing at all.
CONTROL = ("click", "8.3.1")

_ENUMERATE = r"""
import importlib.metadata as m, json
seen = {}
for d in m.distributions():
    try:
        name, ver = (d.metadata["Name"] or "").strip(), (d.version or "").strip()
    except Exception:
        continue
    if not name or not ver:
        continue
    key = name.lower().replace("_", "-")
    if key not in seen:          # first on sys.path is what an import resolves
        seen[key] = (name, ver)
print(json.dumps(sorted(seen.values())))
"""


def _resolved(python):
    proc = subprocess.run([python, "-c", _ENUMERATE], capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:200]
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1]), None
    except Exception as exc:
        return None, f"unparseable output: {type(exc).__name__}"


def _query(pairs):
    body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pairs]}
    req = urllib.request.Request(
        OSV_BATCH, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.load(resp)["results"]


def main():
    python = os.environ.get("AUDIT_PYTHON") or sys.executable
    print(f"interpreter under test: {python}")

    dists, err = _resolved(python)
    if dists is None:
        print(f"UNKNOWN: could not enumerate distributions: {err}")
        return 2
    if not dists:
        # Zero is never a real answer here, and it is exactly what a wrong
        # interpreter path or a missing venv produces.
        print("UNKNOWN: enumerated ZERO distributions, which cannot be true")
        return 2
    print(f"distributions resolved: {len(dists)}")

    try:
        control = _query([CONTROL])
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"UNKNOWN: could not reach OSV: {type(exc).__name__}")
        return 2
    if not (control and control[0].get("vulns")):
        print(f"UNKNOWN: control {CONTROL[0]}=={CONTROL[1]} returned no advisory, so this "
              "sweep cannot detect one either")
        return 2
    print(f"CONTROL {CONTROL[0]}=={CONTROL[1]}: advisory returned, the sweep can see findings\n")

    findings = {}
    for i in range(0, len(dists), 100):
        chunk = dists[i:i + 100]
        try:
            results = _query(chunk)
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"UNKNOWN: OSV became unreachable mid-sweep: {type(exc).__name__}")
            return 2
        for (name, ver), result in zip(chunk, results):
            ids = sorted({v.get("id") for v in (result.get("vulns") or []) if v.get("id")})
            if ids:
                findings[f"{name}=={ver}"] = ids

    if not findings:
        print(f"PASS: no known advisory against any of the {len(dists)} resolved distributions")
        return 0
    for pkg, ids in sorted(findings.items()):
        print(f"FAIL {pkg:<30} {', '.join(ids)}")
    print(f"\n{len(findings)} package(s) with a known advisory. A fix delivered as a patched")
    print("host package is a valid remedy; see probe_dependency_provenance.py for ownership.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
