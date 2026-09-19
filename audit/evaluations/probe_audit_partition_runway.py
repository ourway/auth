#!/usr/bin/env python3
"""F-5: audit_log must keep future monthly partitions provisioned.

Falsified state: the partition migration created twelve months of runway and
nothing extended it. When it lapses, rows land in ``audit_log_default``, which
``drop_audit_log_partitions_before`` deliberately skips — so writes keep
succeeding, retention can never reclaim them, and nothing notices.

Needs a real PostgreSQL deployment: set AUDIT_DB_URL. Without it this probe
reports SKIPPED, which is NOT evidence that the runway is healthy.
"""

import os
import subprocess
import sys
from datetime import date

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe  # noqa: E402

MIN_MONTHS = 3


def main():
    if not os.environ.get("AUDIT_DB_URL"):
        print("== audit partition runway")
        print("   SKIPPED: AUDIT_DB_URL is not set.")
        print("   This is NOT a pass - the runway was not checked.")
        return 0

    p = Probe(
        "audit partition runway",
        f"that at least {MIN_MONTHS} months of audit_log partitions exist and nothing is in DEFAULT",
    )
    script = os.path.join(REPO, "scripts", "provision_audit_partitions.py")
    out = subprocess.run(
        [sys.executable, script, "--months", str(MIN_MONTHS), "--dry-run"],
        capture_output=True,
        text=True,
    )
    text = out.stdout + out.stderr
    p.check("provisioning script ran", out.returncode in (0, 1), f"exit {out.returncode}")
    p.check("default partition is empty", "rows in default partition: 0" in text,
            [ln for ln in text.splitlines() if "default partition" in ln] or text[-160:])

    newest = [ln for ln in text.splitlines() if "newest partition" in ln]
    p.check("a newest partition was reported", bool(newest), newest or "none")
    if newest:
        stamp = newest[0].strip().split()[-1]  # audit_log_YYYY_MM
        try:
            y, m = int(stamp.split("_")[-2]), int(stamp.split("_")[-1])
            today = date.today()
            months = (y - today.year) * 12 + (m - today.month)
            p.check(f"runway >= {MIN_MONTHS} months", months >= MIN_MONTHS,
                    f"newest={stamp} -> {months} months ahead")
        except (ValueError, IndexError):
            p.check("newest partition name is parseable", False, stamp)
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
