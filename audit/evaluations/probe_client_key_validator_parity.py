#!/usr/bin/env python3
"""F-1: the request gate and the service must share one definition of client-key
validity, and a malformed key must be refused with 400 rather than raising.

Falsified state: auth/validation.py accepts any hex UUID shape while
auth/services/base.py requires a real v4, so nil/v1/bad-variant keys reach the
service and surface as HTTP 500.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_client  # noqa: E402

CANONICAL_V4 = "550e8400-e29b-41d4-a716-446655440000"
MALFORMED = [
    ("nil uuid", "00000000-0000-0000-0000-000000000000"),
    ("version 1", "550e8400-e29b-11d4-a716-446655440000"),
    ("v4 shape, bad variant", "550e8400-e29b-41d4-0716-446655440000"),
]


def main():
    p = Probe(
        "client-key validator parity",
        "that the gate and the service agree, and malformed keys give 400 not 500",
    )
    # Environment must be set before any `auth` import: auth.config caches
    # settings on first use (the same ordering rule tests/conftest.py documents).
    client, _ = local_client()
    from auth.services.base import validate_client_key as service
    from auth.validation import validate_client_key as gate

    # Known-positive first: the probe must be able to report a good outcome.
    r = client.get("/api/roles", headers={"Authorization": f"Bearer {CANONICAL_V4}"})
    p.check("control: canonical v4 is accepted", r.status_code == 200, f"HTTP {r.status_code}")
    p.check(
        "control: a non-UUID is rejected with 400",
        client.get("/api/roles", headers={"Authorization": "Bearer not-a-uuid"}).status_code == 400,
        "HTTP 400",
    )

    for label, key in MALFORMED:
        g, s = gate(key), service(key.lower())
        p.check(f"validators agree on {label}", g == s, f"gate={g} service={s}")
        code = client.get("/api/roles", headers={"Authorization": f"Bearer {key}"}).status_code
        p.check(f"{label} is refused with 400, not 5xx", code == 400, f"HTTP {code}")

    return p.done()


if __name__ == "__main__":
    sys.exit(main())
