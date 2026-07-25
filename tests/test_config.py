"""
Config hardening: the audit pepper must be strong in production.

The pepper keys the HMAC that fingerprints client keys in the audit trail. A
placeholder/empty pepper makes those fingerprints computable, so the service
must refuse to start with one when audit logging is on and debug is off.
"""

import pytest

from auth.config import Settings


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


def test_strong_pepper_boots():
    s = _mk()
    assert s.audit_pepper == "a-sufficiently-long-strong-pepper"


@pytest.mark.parametrize("weak", ["", "changeme", "your_secure_jwt_secret_key_here", "short"])
def test_weak_or_short_pepper_fails_closed(weak):
    with pytest.raises(Exception) as exc:
        _mk(audit_pepper=weak, jwt_secret_key=weak)
    assert "pepper" in str(exc.value).lower()


def test_debug_mode_bypasses_the_check_for_local_use():
    # Local/dev: an empty pepper is allowed only when debug is on.
    s = _mk(audit_pepper="", jwt_secret_key="", debug_mode=True)
    assert s.debug_mode is True


def test_audit_off_does_not_require_a_pepper():
    s = _mk(audit_pepper="", jwt_secret_key="", enable_audit_logging=False)
    assert s.enable_audit_logging is False
