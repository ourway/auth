import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "provision_audit_partitions.py"
SENTINEL = "Zq7SentinelPw9xK"

MALFORMED = {
    "typod_scheme": f"postgres!!!://u:{SENTINEL}@127.0.0.1:1/db",
    "sqlalchemy_url": f"postgresql+psycopg://u:{SENTINEL}@127.0.0.1:1/db",
    "unreachable": f"postgresql://u:{SENTINEL}@127.0.0.1:1/db",
}


def _run(dsn):
    env = {k: v for k, v in os.environ.items() if k not in ("AUDIT_DB_URL", "MG_DATABASE_URL", "AUTH_DATABASE_URL", "DATABASE_URL")}
    env["AUTH_DATABASE_URL"] = dsn
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--months", "1"],
        capture_output=True, text=True, env=env, timeout=60,
    )


def test_the_trigger_still_exists():
    """Known-positive control.

    psycopg must still quote a malformed conninfo string back in full, or the
    assertions below pass because the danger vanished rather than because the
    script defends against it -- a check that cannot go red.
    """
    psycopg = pytest.importorskip("psycopg")
    with pytest.raises(psycopg.Error) as caught:
        psycopg.connect(MALFORMED["typod_scheme"], connect_timeout=1)
    assert SENTINEL in str(caught.value)


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_script_never_prints_the_dsn(name):
    pytest.importorskip("psycopg")
    proc = _run(MALFORMED[name])
    assert SENTINEL not in proc.stdout
    assert SENTINEL not in proc.stderr
    assert proc.returncode == 2


def test_failure_is_still_diagnosable():
    pytest.importorskip("psycopg")
    proc = _run(MALFORMED["typod_scheme"])
    assert "AUTH_DATABASE_URL" in proc.stderr
    assert "Error" in proc.stderr
