import re
from pathlib import Path

import pytest
from packaging.version import Version

tomllib = pytest.importorskip("tomllib")

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "deploy" / "requirements-vm2.txt"
UV_LOCK = ROOT / "uv.lock"

FLOORS = {
    "werkzeug": "3.1.9",
    "certifi": "2026.10.19",
    "urllib3": "2.8.0",
    "setuptools": "84.1.0",
    "click": "8.3.3",
}
EXCLUDED = {"pillow", "pyjwt", "filelock", "brotli", "psycopg-binary"}
REQUIRED = {
    "psycopg",
    "psycopg-c",
    "gunicorn",
    "supervice",
    "migretti",
    "flask",
    "sqlalchemy",
}

REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _entries():
    entries = []
    current = None
    for line in LOCK.read_text().splitlines():
        match = REQUIREMENT.match(line)
        if match:
            current = {
                "name": _norm(match.group(1)),
                "version": match.group(2),
                "hashes": 0,
            }
            entries.append(current)
        elif current is not None and "--hash=sha256:" in line:
            current["hashes"] += 1
    return entries


@pytest.fixture(scope="module")
def entries():
    found = _entries()
    assert {e["name"] for e in found} >= {"flask", "psycopg"}
    return found


def test_every_requirement_is_hash_pinned(entries):
    unhashed = [e["name"] for e in entries if e["hashes"] == 0]
    assert unhashed == []


def test_lock_carries_the_server_runtime(entries):
    assert REQUIRED <= {e["name"] for e in entries}


def test_lock_excludes_packages_auth_does_not_use(entries):
    assert EXCLUDED.isdisjoint({e["name"] for e in entries})


@pytest.mark.parametrize("name,floor", sorted(FLOORS.items()))
def test_fixed_versions_are_pinned(entries, name, floor):
    versions = [Version(e["version"]) for e in entries if e["name"] == name]
    assert versions, f"{name} missing from the deploy lock"
    assert all(v >= Version(floor) for v in versions)


def test_deploy_lock_matches_uv_lock(entries):
    locked: dict[str, set[str]] = {}
    for package in tomllib.loads(UV_LOCK.read_text())["package"]:
        locked.setdefault(_norm(package["name"]), set()).add(package["version"])
    drift = sorted(
        (e["name"], e["version"])
        for e in entries
        if e["version"] not in locked.get(e["name"], set())
    )
    assert drift == []
