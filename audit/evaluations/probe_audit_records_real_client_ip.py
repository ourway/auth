#!/usr/bin/env python3
"""F-3: the audit trail must record the originating client address, and must not
honour a client-supplied X-Forwarded-For prefix.

Falsified state: no ProxyFix, so every audit row records the reverse proxy
(127.0.0.1) and the real client address is discarded.

Trust model: exactly ONE trusted proxy hop. nginx appends the real peer to
X-Forwarded-For, so the RIGHTMOST entry is trustworthy and anything a client
puts to the left of it must be ignored.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_client  # noqa: E402

REAL = "203.0.113.7"        # what the trusted proxy appends
SPOOF = "198.51.100.99"     # what a malicious client puts in front of it


def last_audit_ip(client, key):
    r = client.get("/api/audit?limit=1", headers={"Authorization": f"Bearer {key}"})
    body = r.get_json() or {}
    data = body.get("data", body)
    entries = data.get("entries", data) if isinstance(data, dict) else data
    return entries[0].get("ip_address") if isinstance(entries, list) and entries else None


def main():
    p = Probe(
        "audit records the real client ip",
        "that the audit trail records the caller's address and ignores a spoofed XFF prefix",
    )
    client, key = local_client()
    H = {"Authorization": f"Bearer {key}"}

    client.get("/api/roles", headers=H)
    baseline = last_audit_ip(client, key)
    p.check("control: an audit row is written and readable", baseline is not None, repr(baseline))

    client.get("/api/roles", headers={**H, "X-Forwarded-For": REAL})
    got = last_audit_ip(client, key)
    p.check("proxy-supplied address is recorded", got == REAL, f"expected {REAL}, got {got!r}")

    client.get("/api/roles", headers={**H, "X-Forwarded-For": f"{SPOOF}, {REAL}"})
    got = last_audit_ip(client, key)
    p.check(
        "a client-supplied XFF prefix is NOT honoured",
        got == REAL and got != SPOOF,
        f"sent '{SPOOF}, {REAL}' -> recorded {got!r}",
    )
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
