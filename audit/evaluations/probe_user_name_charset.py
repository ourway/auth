#!/usr/bin/env python3
"""F-6: user identifiers containing '|' or ':' must be accepted end to end.

Falsified state: USER_NAME_PATTERN = ^[a-zA-Z0-9_.@+-]{1,64}$ rejects both, and
also rejects '%', so percent-encoding cannot work around it. Reported by
provenance-50ca06.

'%' is deliberately still rejected: Flask percent-decodes the path before
validation, so an encoded '|' arrives as '|' and needs no literal '%'.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_client  # noqa: E402

ACCEPT = ["alice", "alice@corp.com", "a_b-c.d", "a+b", "tenant|user", "ns:user", "a|b:c"]
REJECT = ["", "with space", "semi;colon", "sla/sh", "quo'te", "x" * 65]


def main():
    p = Probe(
        "user name charset",
        "that '|' and ':' are accepted as user identifiers, without widening to unsafe characters",
    )
    client, key = local_client()
    from auth.validation import validate_user_name

    for u in ACCEPT:
        p.check(f"accepts {u!r}", validate_user_name(u), "validator")
    for u in REJECT:
        p.check(f"still rejects {u!r}", not validate_user_name(u), "validator")

    # End to end, not just the validator: the route must serve it too.
    H = {"Authorization": f"Bearer {key}"}
    client.post("/api/role/engineer", headers=H)
    r = client.post("/api/membership/tenant|user/engineer", headers=H)
    p.check("membership grant for 'tenant|user' succeeds", r.status_code < 400, f"HTTP {r.status_code}")
    r = client.get("/api/user_roles/tenant|user", headers=H)
    roles = [x.get("role") for x in (r.get_json() or {}).get("result", [])]
    p.check("the grant reads back", "engineer" in roles, f"HTTP {r.status_code} roles={roles}")
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
