"""
Config hardening: the audit pepper must be strong before the SERVER serves —
but importing the package as a client library must never require it.

The pepper keys the HMAC that fingerprints client keys in the audit trail, so a
placeholder pepper makes those fingerprints computable. The hard check therefore
runs at server boot (``create_app``), not at ``Settings`` construction: ``pip
install auth; from auth import Client`` talks to a remote service and needs no
server-side secrets at all.
"""

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


@pytest.mark.parametrize("weak", ["", "changeme", "your_secure_jwt_secret_key_here", "short"])
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


@pytest.mark.parametrize("weak", ["", "changeme", "your_secure_jwt_secret_key_here", "short"])
def test_weak_or_short_pepper_fails_closed_at_server_boot(weak):
    with pytest.raises(ValueError) as exc:
        verify_audit_pepper(_mk(audit_pepper=weak, jwt_secret_key=weak))
    assert "pepper" in str(exc.value).lower()


def test_debug_mode_bypasses_the_check_for_local_use():
    verify_audit_pepper(_mk(audit_pepper="", jwt_secret_key="", debug_mode=True))


def test_audit_off_does_not_require_a_pepper():
    verify_audit_pepper(_mk(audit_pepper="", jwt_secret_key="", enable_audit_logging=False))


def test_create_app_refuses_to_boot_with_a_weak_pepper(monkeypatch):
    """The real server entry point must fail closed."""
    from auth import main

    monkeypatch.setattr(main, "get_settings", lambda: _mk(audit_pepper="changeme", jwt_secret_key="changeme"))
    with pytest.raises(ValueError):
        main.create_app()
