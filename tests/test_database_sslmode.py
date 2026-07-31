"""sslmode precedence for the PostgreSQL engine factory (SPEC 0011, highway
report thr-7745c815fd0a425cabac).

Contract: explicit URL sslmode wins, then PGSSLMODE, then secure-by-default
``require`` for genuinely remote hosts — decided by host component, never by
URL substring.
"""

import pytest

from auth.database import _forced_sslmode

REMOTE = "postgresql+psycopg://app:pw@db:5432/x"


@pytest.fixture(autouse=True)
def _no_pgsslmode(monkeypatch):
    monkeypatch.delenv("PGSSLMODE", raising=False)


def test_remote_host_defaults_to_require():
    # Known-positive first: the default CAN fire.
    assert _forced_sslmode(REMOTE) == "require"
    assert _forced_sslmode("postgresql://u@10.0.0.5/db") == "require"


def test_explicit_url_sslmode_is_never_overridden():
    assert _forced_sslmode(REMOTE + "?sslmode=disable") is None
    assert _forced_sslmode(REMOTE + "?sslmode=verify-full") is None


def test_pgsslmode_env_is_respected(monkeypatch):
    monkeypatch.setenv("PGSSLMODE", "disable")
    assert _forced_sslmode(REMOTE) is None


def test_local_hosts_get_no_forced_sslmode():
    assert _forced_sslmode("postgresql://u@localhost/db") is None
    assert _forced_sslmode("postgresql://u@127.0.0.1:5432/db") is None


def test_host_is_compared_as_component_not_substring():
    # The old substring test skipped SSL for this remote URL; it must not.
    tricky = "postgresql://app@db:5432/x?fallback_application_name=localhost"
    assert _forced_sslmode(tricky) == "require"
    # And a host merely CONTAINING 'localhost' is remote.
    assert _forced_sslmode("postgresql://u@localhost.attacker.net/db") == "require"
