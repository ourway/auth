"""Falsifies: "no version pinned in auth's lockfiles has a known advisory."

    python3 audit/evaluations/probe_osv_lockfiles.py

Exit 0 nothing known, 1 at least one advisory, 2 the probe could not answer.
"""

import importlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
ROOT = Path(__file__).resolve().parents[2]
CONTROL = ("click", "8.3.1")
MUST_PARSE = "flask"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;#]+)")


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(path):
    pins = []
    for line in path.read_text().splitlines():
        m = PIN.match(line.strip())
        if m:
            pins.append((_norm(m.group(1)), m.group(2)))
    return pins


def _uv_lock(path):
    try:
        tomllib = importlib.import_module("tomllib")
    except ModuleNotFoundError:
        return None
    data = tomllib.loads(path.read_text())
    return [
        (_norm(p["name"]), p["version"])
        for p in data.get("package", [])
        if "version" in p and "registry" in p.get("source", {})
    ]


def _query(pairs):
    body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pairs]}
    req = urllib.request.Request(
        OSV_BATCH, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.load(resp)["results"]


def main():
    sources = {}
    for label, path, parse in (
        ("requirements.txt", ROOT / "requirements.txt", _requirements),
        ("uv.lock", ROOT / "uv.lock", _uv_lock),
    ):
        if not path.is_file():
            print(f"UNKNOWN: {label} not found at {path}")
            return 2
        pins = parse(path)
        if pins is None:
            print(f"UNKNOWN: cannot parse {label} on Python {sys.version.split()[0]} (needs tomllib, 3.11+)")
            return 2
        if MUST_PARSE not in {n for n, _ in pins}:
            print(f"UNKNOWN: {label} parsed {len(pins)} pins without {MUST_PARSE}, so the parser is not reading it")
            return 2
        sources[label] = sorted(set(pins))
        print(f"{label}: {len(sources[label])} pins")

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

    findings = []
    for label, pins in sources.items():
        for i in range(0, len(pins), 100):
            chunk = pins[i:i + 100]
            try:
                results = _query(chunk)
            except (urllib.error.URLError, TimeoutError) as exc:
                print(f"UNKNOWN: OSV became unreachable mid-sweep: {type(exc).__name__}")
                return 2
            if len(results) != len(chunk):
                print(f"UNKNOWN: OSV answered {len(results)} of {len(chunk)} queries")
                return 2
            for (name, ver), result in zip(chunk, results):
                ids = sorted({v.get("id") for v in (result.get("vulns") or []) if v.get("id")})
                if ids:
                    findings.append((label, f"{name}=={ver}", ids))

    total = sum(len(p) for p in sources.values())
    if not findings:
        print(f"PASS: no known advisory against any of the {total} pins")
        return 0
    for label, pkg, ids in findings:
        print(f"FAIL {label:<17} {pkg:<32} {', '.join(ids)}")
    print(f"\n{len(findings)} pinned version(s) with a known advisory")
    return 1


if __name__ == "__main__":
    sys.exit(main())
