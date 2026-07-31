"""
Config hardening: the audit pepper must be strong before the SERVER serves —
but importing the package as a client library must never require it.

The pepper keys the HMAC that fingerprints client keys in the audit trail, so a
placeholder pepper makes those fingerprints computable. The hard check therefore
runs at server boot (``create_app``), not at ``Settings`` construction: ``pip
install auth; from auth import Client`` talks to a remote service and needs no
server-side secrets at all.
"""

import os
from pathlib import Path

import pytest

from auth.config import Settings, audit_pepper_is_weak, verify_audit_pepper


def _mk(
    *,
    enable_audit_logging: bool = True,
    debug_mode: bool = False,
    audit_pepper: str = "a-sufficiently-long-strong-pepper",
    jwt_secret_key: str = "a-sufficiently-long-strong-secret",
) -> Settings:
    return Settings(  # type: ignore[call-arg]
        enable_audit_logging=enable_audit_logging,
        debug_mode=debug_mode,
        audit_pepper=audit_pepper,
        jwt_secret_key=jwt_secret_key,
    )


# --- constructing Settings must never raise (library use) ------------------


@pytest.mark.parametrize(
    "weak", ["", "changeme", "your_secure_jwt_secret_key_here", "short"]
)
def test_settings_construction_never_raises_on_a_weak_pepper(weak):
    """Regression: a fail-closed check here broke `import auth` for clients."""
    s = _mk(audit_pepper=weak, jwt_secret_key=weak)
    assert audit_pepper_is_weak(s) is True


def test_importing_the_package_does_not_require_server_secrets():
    import importlib

    import auth

    importlib.reload(auth)  # must not raise
    assert hasattr(auth, "Client")


# --- the server boot check fails closed ------------------------------------


def test_strong_pepper_passes_server_check():
    verify_audit_pepper(_mk())  # does not raise


@pytest.mark.parametrize(
    "weak", ["", "changeme", "your_secure_jwt_secret_key_here", "short"]
)
def test_weak_or_short_pepper_fails_closed_at_server_boot(weak):
    with pytest.raises(ValueError) as exc:
        verify_audit_pepper(_mk(audit_pepper=weak, jwt_secret_key=weak))
    assert "pepper" in str(exc.value).lower()


def test_debug_mode_bypasses_the_check_for_local_use():
    verify_audit_pepper(_mk(audit_pepper="", jwt_secret_key="", debug_mode=True))


def test_audit_off_does_not_require_a_pepper():
    verify_audit_pepper(
        _mk(audit_pepper="", jwt_secret_key="", enable_audit_logging=False)
    )


def test_create_app_refuses_to_boot_with_a_weak_pepper(monkeypatch):
    """The real server entry point must fail closed."""
    from auth import main

    monkeypatch.setattr(
        main,
        "get_settings",
        lambda: _mk(audit_pepper="changeme", jwt_secret_key="changeme"),
    )
    with pytest.raises(ValueError):
        main.create_app()


# --- weak-secret WARNINGS belong to the server/embedded paths, not to import --
#
# issuedb #20: `import auth` in a client-only process printed two secrets-shaped
# lines to stderr. They are unactionable for a consumer that signs no JWTs and
# writes no audit rows, and they read as THAT consumer's misconfiguration in
# their boot logs (tokengate thr-b7e8b0c2c7914d56b6f1, runflow
# thr-44794b4bbb6448c2bc01). The warnings moved to the paths that use the
# secrets; the fail-closed check above is unchanged.

JWT_WARNING = "AUTH_JWT_SECRET_KEY is a weak/placeholder value"
PEPPER_WARNING = "AUTH_AUDIT_PEPPER is unset, a placeholder, or too short"


@pytest.fixture
def fresh_warn_flag(monkeypatch):
    """Reset the emit-once latch so each test observes a virgin process."""
    from auth import config

    monkeypatch.setattr(config, "_weak_secret_warnings_emitted", False)
    return config


def test_warn_on_weak_secrets_fires_for_weak_values(fresh_warn_flag, caplog):
    """Known-positive: the check must be able to say YES before it says NO."""
    with caplog.at_level("WARNING", logger="auth.config"):
        fresh_warn_flag.warn_on_weak_secrets(
            _mk(audit_pepper="changeme", jwt_secret_key="changeme")
        )
    assert any(JWT_WARNING in r.message for r in caplog.records)
    assert any(PEPPER_WARNING in r.message for r in caplog.records)


def test_warn_on_weak_secrets_silent_for_strong_values(fresh_warn_flag, caplog):
    with caplog.at_level("WARNING", logger="auth.config"):
        fresh_warn_flag.warn_on_weak_secrets(_mk())
    assert caplog.records == []


def test_warn_on_weak_secrets_emits_at_most_once_per_process(fresh_warn_flag, caplog):
    weak = _mk(audit_pepper="changeme", jwt_secret_key="changeme")
    with caplog.at_level("WARNING", logger="auth.config"):
        fresh_warn_flag.warn_on_weak_secrets(weak)
        first = len(caplog.records)
        fresh_warn_flag.warn_on_weak_secrets(weak)
        fresh_warn_flag.warn_on_weak_secrets(weak)
    assert first == 2
    assert len(caplog.records) == first


def test_pepper_warning_respects_the_audit_and_debug_gates(fresh_warn_flag, caplog):
    """Only the JWT line applies when audit logging is off."""
    with caplog.at_level("WARNING", logger="auth.config"):
        fresh_warn_flag.warn_on_weak_secrets(
            _mk(
                audit_pepper="changeme",
                jwt_secret_key="changeme",
                enable_audit_logging=False,
            )
        )
    assert any(JWT_WARNING in r.message for r in caplog.records)
    assert not any(PEPPER_WARNING in r.message for r in caplog.records)


def test_bare_import_is_silent_in_a_client_only_process(tmp_path):
    """The reporters' exact reproduction: `python -c "import auth"`.

    Runs in a subprocess because the warnings are a property of a fresh
    interpreter, and from tmp_path with AUTH_* scrubbed so neither the repo's
    .env nor the ambient shell can mask the defect.
    """
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if not k.startswith("AUTH_")}
    env["AUTH_DATABASE_URL"] = f"sqlite:///{tmp_path}/probe.db"
    env["AUTH_JWT_SECRET_KEY"] = "changeme"  # deliberately weak
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

    proc = subprocess.run(
        [sys.executable, "-c", "import auth"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )

    assert proc.returncode == 0, proc.stderr
    assert JWT_WARNING not in proc.stderr
    assert PEPPER_WARNING not in proc.stderr


def test_embedded_create_tables_still_warns(tmp_path):
    """The counterpart negative control: the same weak config DOES warn once an
    embedded consumer actually initializes the server side."""
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if not k.startswith("AUTH_")}
    env["AUTH_DATABASE_URL"] = f"sqlite:///{tmp_path}/probe.db"
    env["AUTH_JWT_SECRET_KEY"] = "changeme"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from auth.database import create_tables; create_tables()",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )

    assert proc.returncode == 0, proc.stderr
    assert JWT_WARNING in proc.stderr
    assert PEPPER_WARNING in proc.stderr
