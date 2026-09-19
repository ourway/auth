#!/usr/bin/env python3
"""F-2: a changed or lost AUTH_ENCRYPTION_KEY must be detected, not served.

Falsified state: with a different key, every authorization lookup misses and
answers "denied" with HTTP 200, while /health reports healthy. Nothing in the
request path can notice, because the query path compares ciphertext and never
decrypts.

All three states are asserted, because a canary that only ever reports one of
them is the self-confirming check this harness exists to catch:

  correct key   -> serves normally, /health healthy
  changed key   -> /api refused 503, /health unhealthy
  fresh deploy  -> starts normally (nothing encrypted yet to verify against)
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_env  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PYTHON = os.environ.get("AUDIT_PYTHON", os.path.join(REPO, ".venv", "bin", "python"))
KEY_A = "audit-probe-encryption-key-alpha-000001"
KEY_B = "audit-probe-encryption-key-BRAVO-000002"
TENANT = "550e8400-e29b-41d4-a716-446655440000"

STAGE = r'''
import json, logging, os
logging.disable(logging.CRITICAL)
from auth.main import app
try:
    from auth import keycheck
    _ks = keycheck.state()
except Exception:
    _ks = "absent"
c = app.test_client()
H = {"Authorization": "Bearer %s"}
if os.environ["STAGE"] == "setup":
    c.post("/api/role/engineer", headers=H)
    c.post("/api/permission/engineer/deploy", headers=H)
    c.post("/api/membership/alice/engineer", headers=H)
hp = c.get("/api/has_permission/alice/deploy", headers=H)
hl = c.get("/health")
print(json.dumps({
    "keycheck": _ks,
    "api_status": hp.status_code,
    "has_permission": (hp.get_json() or {}).get("data", {}).get("has_permission"),
    "health_status": hl.status_code,
    "health_body": hl.get_json(),
}))
''' % TENANT


def run(db_path, key, stage):
    env = dict(os.environ)
    env.update(local_env(AUTH_SQLITE_PATH=db_path))
    env.update({"AUTH_ENABLE_ENCRYPTION": "true", "AUTH_ENCRYPTION_KEY": key, "STAGE": stage})
    out = subprocess.run([PYTHON, "-c", STAGE], cwd=REPO, env=env, capture_output=True, text=True)
    lines = [ln for ln in out.stdout.splitlines() if ln.startswith("{")]
    if not lines:
        return {"ERROR": (out.stderr or out.stdout)[-300:]}
    return json.loads(lines[-1])


def main():
    p = Probe(
        "encryption key canary",
        "that a changed encryption key is detected rather than served as universal denial",
    )
    db = os.path.join(tempfile.mkdtemp(prefix="auth-canary-"), "probe.sqlite3")

    a = run(db, KEY_A, "setup")
    if "ERROR" in a:
        p.check("stage ran (correct key)", False, a["ERROR"])
        return p.done()
    p.check("correct key: keycheck ok", a.get("keycheck") == "ok", repr(a.get("keycheck")))
    p.check("correct key: authorization answers true", a.get("has_permission") is True, repr(a.get("has_permission")))
    p.check("correct key: /health healthy", a.get("health_status") == 200, f"HTTP {a.get('health_status')}")

    b = run(db, KEY_B, "read")
    if "ERROR" in b:
        p.check("stage ran (changed key)", False, b["ERROR"])
        return p.done()
    p.check("changed key: keycheck mismatch", b.get("keycheck") == "mismatch", repr(b.get("keycheck")))
    p.check("changed key: /api refused with 503", b.get("api_status") == 503, f"HTTP {b.get('api_status')}")
    p.check(
        "changed key: does NOT answer a confident denial",
        b.get("api_status") is not None and b.get("has_permission") is not False,
        f"has_permission={b.get('has_permission')!r} (False would be the silent-denial bug)",
    )
    p.check("changed key: /health unhealthy", b.get("health_status") == 503, f"HTTP {b.get('health_status')}")

    fresh = os.path.join(tempfile.mkdtemp(prefix="auth-canary-fresh-"), "probe.sqlite3")
    f = run(fresh, KEY_B, "read")
    p.check("fresh deployment still starts", f.get("keycheck") == "ok", repr(f.get("keycheck")))
    p.check("fresh deployment serves /api", f.get("api_status") == 200, f"HTTP {f.get('api_status')}")
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
