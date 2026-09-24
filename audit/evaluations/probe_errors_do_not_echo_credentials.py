"""Falsifies: "auth never returns a submitted credential in an error response."

A validation or rejection path that renders the offending input back to the
caller puts that input everywhere the response goes -- a proxy log, a monitoring
capture, a screenshot in a ticket. uptime-service found four such routes in
their own service, where a framework default serialised the raw input into a
422 body. auth hand-rolls its validation rather than using that framework, so
the question is open rather than answered by construction.

The credential that matters most is the rotate key: it is a bearer secret which
alone owns a namespace, it arrives in a REQUEST BODY rather than a header, and
the route that takes it is exempt from the Bearer gate by design.

Every check carries a known-positive: an endpoint that legitimately echoes a
value the probe submitted, proving the detector can see an echoed string at all.
Without it, a 404 from a renamed route would report "no credential echoed" with
full confidence.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import Probe, local_client  # noqa: E402

SENTINEL = "Zq7SentinelCredential9xK"


def _body(resp):
    try:
        return resp.get_data(as_text=True)
    except Exception:
        return ""


def main():
    probe = Probe(
        "errors do not echo submitted credentials",
        "auth never returns a submitted credential in an error response",
    )
    client, client_key = local_client()
    auth_header = {"Authorization": f"Bearer {client_key}"}

    # Registered BEFORE the first request: Flask refuses new routes afterwards.
    # The global @app.errorhandler(Exception) was asserted safe by READING it --
    # it returns a fixed string. Reading is not calling, so an unhandled
    # exception carrying the sentinel is raised through it further down.
    from auth.main import app as flask_app

    @flask_app.route("/__probe_unhandled__", methods=["GET"])
    def _probe_unhandled():
        raise RuntimeError(f"internal failure carrying {SENTINEL}")

    # Known-positive first: a role name is a submitted value the API is MEANT to
    # return, so finding it proves the detector can see an echoed string. An
    # earlier version of this probe used the /api/audit filter and appeared to
    # pass -- it was matching audit rows written by preceding requests, not an
    # echo, and it stopped passing the moment it ran first. A control that
    # depends on test ordering is not a control.
    client.post(f"/api/role/role-{SENTINEL}", headers=auth_header, json={})
    listed = client.get("/api/roles", headers=auth_header)
    probe.check(
        "CONTROL: a value the API does echo IS found by this detector",
        SENTINEL in _body(listed),
        f"status={listed.status_code} sentinel_present={SENTINEL in _body(listed)}",
    )

    cases = [
        (
            "recover with a MALFORMED rotate key",
            "/api/keys/recover",
            None,
            {"rotate_key": f"not-a-valid-key-{SENTINEL}"},
        ),
        (
            "recover with a well-formed but UNKNOWN rotate key",
            "/api/keys/recover",
            None,
            {"rotate_key": "rrk_" + SENTINEL + "A" * (43 - len(SENTINEL))},
        ),
        (
            "recover with rotate key of the wrong TYPE",
            "/api/keys/recover",
            None,
            {"rotate_key": [SENTINEL]},
        ),
        (
            "validate an API key that cannot be one",
            "/api/apikeys/validate",
            auth_header,
            {"api_key": f"not-a-key-{SENTINEL}"},
        ),
        (
            "validate a well-formed but unknown API key",
            "/api/apikeys/validate",
            auth_header,
            {"api_key": "rak_" + SENTINEL + "A" * (43 - len(SENTINEL))},
        ),
        (
            "validate an API key of the wrong type",
            "/api/apikeys/validate",
            auth_header,
            {"api_key": [SENTINEL]},
        ),
    ]

    for label, path, headers, payload in cases:
        resp = client.post(path, headers=headers or {}, json=payload)
        body = _body(resp)
        probe.check(
            label,
            SENTINEL not in body,
            f"status={resp.status_code} len={len(body)} echoed={SENTINEL in body}",
        )

    # An unhandled error must not render the exception text to the caller.
    resp = client.post("/api/keys/recover", headers={}, data=b"not json at all",
                       content_type="application/json")
    body = _body(resp)
    leaked = "Traceback" in body or "Exception" in body
    probe.check(
        "malformed JSON does not return a traceback or exception text",
        not leaked,
        f"status={resp.status_code} body={body[:120]!r}",
    )

    resp = client.get("/__probe_unhandled__", headers=auth_header)
    body = _body(resp)
    probe.check(
        "an UNHANDLED exception does not render its message to the caller",
        SENTINEL not in body and "RuntimeError" not in body,
        f"status={resp.status_code} echoed={SENTINEL in body} body={body[:80]!r}",
    )

    return probe.done()


if __name__ == "__main__":
    sys.exit(main())
