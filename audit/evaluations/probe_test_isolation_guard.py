#!/usr/bin/env python3
"""#9: the test suite's database-isolation guard must be able to refuse.

Falsified state: the guard compared the engine URL against a string built from
the SAME environment variable that produced the engine, so both sides moved
together for any value and the assertion could not fail. Pointing the suite at
a decoy database left the run green. The postgres branch asserted only the URL
scheme, which a production DSN satisfies as readily as a disposable container.

Both legs are asserted here, and the ACCEPT leg runs first: a guard that always
raises would produce the refusal and prove nothing.
"""

import importlib.util
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe, local_client  # noqa: E402


def load_conftest():
    path = os.path.join(REPO, "tests", "conftest.py")
    spec = importlib.util.spec_from_file_location("auth_tests_conftest", path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["auth_tests_conftest"] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    p = Probe(
        "test-database isolation guard",
        "that the guard accepts the real test database AND refuses anything else",
    )
    local_client()  # sets the environment before auth/ is imported
    from sqlalchemy import create_engine

    cf = load_conftest()

    # ACCEPT leg first — a guard that always raises must not pass this.
    legit = create_engine(f"sqlite:///{os.path.join(cf._TEST_DB_DIR, 'ok.sqlite3')}")
    try:
        p.check("accepts this run's own temporary database", True, cf.assert_test_database(legit))
    except cf.TestDatabaseIsolationError as exc:
        p.check("accepts this run's own temporary database", False, f"refused: {exc}")

    # REFUSE leg — the exact decoy that defeated the previous guard.
    decoy = create_engine("sqlite:////tmp/decoy-not-the-test-db.sqlite3")
    try:
        cf.assert_test_database(decoy)
        p.check("refuses a database outside the run's temp dir", False, "ACCEPTED the decoy")
    except cf.TestDatabaseIsolationError as exc:
        p.check("refuses a database outside the run's temp dir", True, str(exc)[:110])

    other = create_engine(f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'elsewhere.sqlite3')}")
    try:
        cf.assert_test_database(other)
        p.check("refuses another process's temp database", False, "ACCEPTED it")
    except cf.TestDatabaseIsolationError:
        p.check("refuses another process's temp database", True, "refused")

    # Postgres leg: decision level (no live server here).
    p.check("production database name is NOT allowlisted",
            "auth" not in cf.ALLOWED_TEST_DATABASES,
            f"allowlist={sorted(cf.ALLOWED_TEST_DATABASES)}")
    p.check("the CI test database IS allowlisted",
            "auth_test" in cf.ALLOWED_TEST_DATABASES,
            f"allowlist={sorted(cf.ALLOWED_TEST_DATABASES)}")
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
