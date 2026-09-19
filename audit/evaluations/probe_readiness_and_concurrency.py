#!/usr/bin/env python3
"""F-4: auth must survive a slow database rather than going offline, and must be
able to report that it cannot commit.

Falsified state:
  * worker_class="sync" with workers=2 caps the whole service at 2 concurrent
    requests, so a 20-27s commit stall takes auth fully offline for every
    caller instead of making it slower.
  * /health round-trips a SELECT, which a database serves happily while its
    commit path is stalled, so the outage is invisible to every probe.

statement_timeout does not bound COMMIT, so concurrency -- not a timeout -- is
what keeps capacity available while commits are slow.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_client  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MIN_CONCURRENCY = 8


def effective_concurrency(cfg_text):
    """Concurrent requests the deployed gunicorn config can actually serve."""
    def num(name, default):
        m = re.search(rf"^{name}\s*=\s*(\d+)", cfg_text, re.M)
        return int(m.group(1)) if m else default

    m = re.search(r'^worker_class\s*=\s*"([^"]+)"', cfg_text, re.M)
    klass = m.group(1) if m else "sync"
    workers = num("workers", 1)
    threads = num("threads", 1)
    return klass, workers, (workers * threads if klass == "gthread" else workers)


def main():
    p = Probe(
        "readiness and concurrency",
        "that a slow database degrades auth instead of removing it, and that it can say so",
    )
    cfg = open(os.path.join(REPO, "gunicorn_config.py")).read()
    klass, workers, conc = effective_concurrency(cfg)
    p.check("worker class is not blocking-sync", klass != "sync", f"worker_class={klass!r}")
    p.check(
        f"effective concurrency >= {MIN_CONCURRENCY}",
        conc >= MIN_CONCURRENCY,
        f"{klass} workers={workers} -> {conc} concurrent",
    )

    client, _ = local_client()
    r = client.get("/readyz")
    p.check("/readyz exists and is ready", r.status_code == 200, f"HTTP {r.status_code} {r.get_json()}")
    p.check("/readyz answers HEAD (load balancers use it)", client.head("/readyz").status_code == 200, "HTTP 200")

    h = client.get("/health")
    p.check(
        "/health semantics unchanged for existing consumers",
        h.status_code == 200 and (h.get_json() or {}).get("status") == "healthy",
        f"HTTP {h.status_code} {h.get_json()}",
    )

    # Known-negative: readiness must be able to report NOT ready.
    from auth import keycheck

    keycheck.reset_for_tests("mismatch")
    try:
        r = client.get("/readyz")
        p.check(
            "control: /readyz can report unready",
            r.status_code == 503,
            f"HTTP {r.status_code} {r.get_json()}",
        )
    finally:
        keycheck.reset_for_tests()
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
