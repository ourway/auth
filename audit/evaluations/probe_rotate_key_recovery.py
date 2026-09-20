#!/usr/bin/env python3
"""#19: the rotate key is issued exactly once and alone recovers a namespace.

Falsified states:
  * a lost client key means a permanently unreachable namespace (rotation
    authenticates with the key it replaces, so it cannot help);
  * a recovery credential that can be re-read is not a secret.

Every leg is asserted, including the ones that must FAIL: a second issuance, a
replay of the used rotate key, and the old client key after recovery. A probe
that only checked the happy path would pass on a rotate key that was disclosed
on every call.

Runs against an ephemeral in-process instance by default. Set AUTH_PG_URL to
drive a real PostgreSQL deployment with RLS in force.
"""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_client  # noqa: E402


def make_client():
    pg = os.environ.get("AUTH_PG_URL")
    if pg:
        import logging

        os.environ.update({
            "AUTH_DATABASE_TYPE": "postgresql", "AUTH_POSTGRESQL_URL": pg,
            "AUTH_DATABASE_URL": pg, "AUTH_DATABASE_SCHEMA": os.environ.get("AUTH_PG_SCHEMA", "auth_rbac"),
            "AUTH_ENABLE_ENCRYPTION": "false", "AUTH_ENCRYPTION_KEY": "",
            "AUTH_JWT_SECRET_KEY": "j" * 32, "AUTH_AUDIT_PEPPER": "p" * 32,
            "AUTH_ENABLE_RATE_LIMIT": "false", "AUTH_STRICT_USERS_DEFAULT": "false",
        })
        logging.disable(logging.CRITICAL)
        from auth.main import app

        return app.test_client(), str(uuid.uuid4())
    return local_client()


def main():
    p = Probe(
        "rotate key issued once, and recovers a namespace",
        "that a lost client key is unrecoverable, and that the rotate key is re-readable",
    )
    c, tenant = make_client()
    H = {"Authorization": f"Bearer {tenant}"}

    c.post("/api/role/engineer", headers=H)
    c.post("/api/membership/alice/engineer", headers=H)
    before = [r["role"] for r in (c.get("/api/roles", headers=H).get_json() or {}).get("result", [])]
    p.check("control: the namespace has content to recover", before == ["engineer"], repr(before))

    r = c.post("/api/keys/get_rotate_key", headers=H)
    body = (r.get_json() or {}).get("data") or {}
    rotate_key = body.get("rotate_key")
    p.check("rotate key is issued on first request",
            r.status_code == 200 and isinstance(rotate_key, str) and rotate_key.startswith("rrk_"),
            f"HTTP {r.status_code} {str(rotate_key)[:12]}...")

    r2 = c.post("/api/keys/get_rotate_key", headers=H)
    b2 = r2.get_json() or {}
    p.check("a second request is REFUSED, not re-disclosed",
            r2.status_code == 409 and "rotate_key" not in str(b2.get("data", "")),
            f"HTTP {r2.status_code} reason={b2.get('reason')}")

    new_key = str(uuid.uuid4())
    r3 = c.post("/api/keys/recover", json={"rotate_key": rotate_key, "new_client_key": new_key})
    d3 = (r3.get_json() or {}).get("data") or {}
    p.check("recovery succeeds with NO Authorization header",
            r3.status_code == 200 and d3.get("client_key") == new_key,
            f"HTTP {r3.status_code} {d3.get('client_key')}")
    new_rotate = d3.get("rotate_key")
    p.check("recovery returns a NEW rotate key",
            isinstance(new_rotate, str) and new_rotate.startswith("rrk_") and new_rotate != rotate_key,
            f"{str(new_rotate)[:12]}... differs: {new_rotate != rotate_key}")

    HN = {"Authorization": f"Bearer {new_key}"}
    after = [r["role"] for r in (c.get("/api/roles", headers=HN).get_json() or {}).get("result", [])]
    p.check("the namespace moved to the new client key", after == ["engineer"], repr(after))
    old = [r["role"] for r in (c.get("/api/roles", headers=H).get_json() or {}).get("result", [])]
    p.check("the OLD client key now owns nothing", old == [], repr(old))

    # A caller chooses new_client_key, so a valid rotate key must not be usable
    # to merge its namespace into somebody else's.
    victim = str(uuid.uuid4())
    c.post("/api/role/victim_role", headers={"Authorization": f"Bearer {victim}"})
    r_merge = c.post("/api/keys/recover",
                     json={"rotate_key": new_rotate, "new_client_key": victim})
    p.check("cannot recover ONTO an occupied namespace (hostile merge)",
            r_merge.status_code == 400, f"HTTP {r_merge.status_code}")
    still = [r["role"] for r in (c.get("/api/roles", headers={"Authorization": f"Bearer {victim}"}).get_json() or {}).get("result", [])]
    p.check("the targeted namespace is untouched", still == ["victim_role"], repr(still))

    r4 = c.post("/api/keys/recover", json={"rotate_key": rotate_key, "new_client_key": str(uuid.uuid4())})
    p.check("the used rotate key cannot be replayed", r4.status_code == 401, f"HTTP {r4.status_code}")
    r5 = c.post("/api/keys/recover", json={"rotate_key": "rrk_" + "z" * 43, "new_client_key": str(uuid.uuid4())})
    p.check("an unknown rotate key is refused", r5.status_code == 401, f"HTTP {r5.status_code}")
    r6 = c.post("/api/keys/recover", json={"rotate_key": "not-a-key"})
    p.check("a malformed rotate key is refused", r6.status_code == 401, f"HTTP {r6.status_code}")
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
