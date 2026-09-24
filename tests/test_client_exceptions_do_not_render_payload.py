import pytest

from auth.client._transport import AuthRefused, AuthTransportError

SENTINEL = "Zq7SentinelCredential9xK"
PAYLOAD = {"message": "denied", "details": {"echoed": SENTINEL}}


def test_refusal_renders_only_its_message():
    """auth ships this client; other platforms run it and log its exceptions.

    A three-argument exception normally renders its whole args tuple through
    Exception.__str__, which would put the upstream response body into every
    ``log.error(e)`` a consumer writes. AuthRefused passes only the message to
    super().__init__ and keeps status and payload as attributes, so the safe
    rendering is the default one and the body is opt-in.
    """
    exc = AuthRefused("auth refused the request: HTTP 401", 401, PAYLOAD)

    assert SENTINEL not in str(exc)
    assert SENTINEL not in repr(exc)
    assert SENTINEL not in str(exc.args)
    assert str(exc) == "auth refused the request: HTTP 401"


def test_the_payload_is_still_reachable_deliberately():
    """The other direction: redaction must not cost the caller the detail.

    A guard that only proved the body is absent would pass equally if payload
    were dropped entirely, which would break the 409 hints this argument exists
    to carry.
    """
    exc = AuthRefused("auth refused the request: HTTP 409", 409, PAYLOAD)
    assert exc.payload == PAYLOAD
    assert exc.status == 409


def test_the_detector_would_see_a_leak():
    """Known-positive control.

    If Exception.__str__ ever stopped rendering extra args, the assertions
    above would hold for a reason that has nothing to do with AuthRefused, and
    the guard would be protecting nothing.
    """
    leaky = AuthTransportError("upstream said", PAYLOAD)
    assert SENTINEL in str(leaky)


def test_refusal_is_still_a_transport_error_subclass():
    assert issubclass(AuthRefused, AuthTransportError)
    with pytest.raises(AuthTransportError):
        raise AuthRefused("m", 400, None)
