"""Shared harness for audit probes.

Default target is an ephemeral in-process instance on throwaway SQLite, so
``run_all.sh`` is safe against a live system. Set AUTH_BASE_URL (and
AUTH_CLIENT_KEY) to drive a deployed service instead.
"""

import os
import tempfile
import uuid

SAFE_SECRETS = {
    "AUTH_JWT_SECRET_KEY": "probe-jwt-secret-not-for-production-0001",
    "AUTH_AUDIT_PEPPER": "probe-audit-pepper-not-for-production-01",
}


def local_env(**overrides):
    """Environment for an ephemeral instance: new temp database per call."""
    d = tempfile.mkdtemp(prefix="auth-probe-")
    env = {
        "AUTH_DATABASE_TYPE": "sqlite",
        "AUTH_DATABASE_URL": "",
        "AUTH_SQLITE_PATH": os.path.join(d, "probe.sqlite3"),
        "AUTH_POSTGRESQL_URL": "",
        "AUTH_DATABASE_SCHEMA": "",
        "AUTH_ENABLE_ENCRYPTION": "false",
        "AUTH_ENCRYPTION_KEY": "",
        "AUTH_ENABLE_RATE_LIMIT": "false",
        "AUTH_ENABLE_AUDIT_LOGGING": "true",
        "AUTH_STRICT_USERS_DEFAULT": "false",
        "AUTH_DEBUG_MODE": "false",
    }
    env.update(SAFE_SECRETS)
    env.update(overrides)
    return env


def local_client(**overrides):
    """An in-process test client plus a fresh tenant key."""
    import logging

    os.environ.update(local_env(**overrides))
    logging.disable(logging.CRITICAL)
    from auth.main import app

    return app.test_client(), str(uuid.uuid4())


def remote_target():
    """(base_url, client_key) when the operator points at a deployment."""
    base = os.environ.get("AUTH_BASE_URL")
    if not base:
        return None, None
    return base.rstrip("/"), os.environ.get("AUTH_CLIENT_KEY") or str(uuid.uuid4())


class Probe:
    """Collects checks and prints PASS/FAIL with the evidence observed."""

    def __init__(self, name, falsifies):
        self.name = name
        self.falsifies = falsifies
        self.failures = []
        self.checks = 0
        print(f"== {name}")
        print(f"   falsifies: {falsifies}")

    def check(self, label, ok, evidence):
        self.checks += 1
        print(f"   [{'PASS' if ok else 'FAIL'}] {label}: {evidence}")
        if not ok:
            self.failures.append(label)
        return ok

    def done(self):
        if self.checks == 0:
            print(f"   [FAIL] {self.name}: VACUOUS - no checks ran")
            return 1
        if self.failures:
            print(f"   RESULT: FAIL ({len(self.failures)}/{self.checks}) -> {self.failures}")
            return 1
        print(f"   RESULT: PASS ({self.checks} checks)")
        return 0
