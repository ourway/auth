import os
import traceback

import pytest

from auth.config import Settings

SENTINEL = "Zq7SentinelSecret9xK"

SECRET_FIELDS = ("database_url", "postgresql_url", "jwt_secret_key", "audit_pepper", "encryption_key")


def test_secret_fields_are_plain_str():
    """The reason a secret cannot reach a ValidationError, asserted directly.

    pydantic appends ``input_value=<raw value>`` to a validation error. Settings
    are populated from the environment, where every value is a string, so a
    plain ``str`` field cannot fail and cannot be echoed. Give one of these a
    constrained type or a validator and that stops being true silently -- so the
    property itself is the test, not the symptom.
    """
    for name in SECRET_FIELDS:
        field = Settings.model_fields[name]
        assert field.annotation is str, (
            f"{name} is no longer a plain str. A constrained secret field can fail "
            f"validation, and pydantic will echo its value. Set "
            f"hide_input_in_errors=True on Settings.model_config before changing this."
        )


def test_a_failure_elsewhere_does_not_echo_secrets(monkeypatch):
    for key in [k for k in os.environ if k.startswith("AUTH_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AUTH_DEBUG_MODE", "true")
    monkeypatch.setenv("AUTH_DATABASE_URL", f"postgresql://u:{SENTINEL}@h:5432/db")
    monkeypatch.setenv("AUTH_ENCRYPTION_KEY", SENTINEL)
    monkeypatch.setenv("AUTH_AUDIT_PEPPER", SENTINEL)
    monkeypatch.setenv("AUTH_DATABASE_TYPE", "not-a-valid-enum-value")

    with pytest.raises(Exception) as caught:
        Settings()  # type: ignore[call-arg]

    exc = caught.value
    rendered = str(exc) + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    assert "not-a-valid-enum-value" in str(exc)
    assert SENTINEL not in rendered


def test_the_echo_mechanism_is_real():
    """Known-positive control.

    If pydantic ever stops echoing input values, the assertions above would pass
    because the danger vanished rather than because Settings avoids it -- and
    the guard in the first test would be protecting nothing.
    """
    with pytest.raises(Exception) as caught:
        Settings(encryption_key=[SENTINEL])  # type: ignore[call-arg,arg-type]
    assert SENTINEL in str(caught.value)
