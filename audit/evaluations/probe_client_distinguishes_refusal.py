#!/usr/bin/env python3
"""#18: the client must distinguish "auth refused this" from "auth was unreachable".

Falsified state: base.py called raise_for_status(), caught every
RequestException alike and raised AuthTransportError — whose own docstring
claims it "distinguishes 'we could not ask' from a genuine negative answer"
while listing non-2xx as a cause. A consumer's platform-admin check therefore
logged "auth unreachable at login" while auth was up, answering, and simply
rejecting a subject containing '|'.

Both directions are asserted: a 4xx must raise AuthRefused, and a genuine
transport failure must still raise plain AuthTransportError.
"""

import http.server
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Probe  # noqa: E402


class Handler(http.server.BaseHTTPRequestHandler):
    status = 400
    body = b'{"error":"invalid user name","code":"bad_request"}'

    def do_GET(self):
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


def serve(status, body):
    Handler.status, Handler.body = status, body
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    p = Probe(
        "client distinguishes refusal from unreachability",
        "that a 4xx raises AuthRefused while a real transport failure still raises AuthTransportError",
    )
    from auth import AuthTransportError, Client

    try:
        from auth import AuthRefused
    except ImportError:
        # Absent on the unfixed client. Bind to a class that can never be
        # raised so the probe measures BEHAVIOUR instead of dying on an import
        # and reporting a vacuous red.
        class AuthRefused(AuthTransportError):  # type: ignore[no-redef]
            status = None
            payload = None

    # 4xx: auth answered and refused.
    srv = serve(400, b'{"error":"invalid user name","code":"bad_request"}')
    port = srv.server_address[1]
    c = Client(api_key="550e8400-e29b-41d4-a716-446655440000",
               service_url=f"http://127.0.0.1:{port}", circuit_breaker_enabled=False)
    try:
        c.get_user_roles("auth0|abc")
        p.check("a 4xx raises", False, "no exception at all")
    except AuthRefused as exc:
        p.check("a 4xx raises AuthRefused", True, f"status={exc.status} payload={exc.payload}")
        p.check("AuthRefused still satisfies existing handlers",
                isinstance(exc, AuthTransportError), "subclasses AuthTransportError")
        p.check("the refusal body survives for actionable errors",
                isinstance(exc.payload, dict) and "code" in exc.payload, repr(exc.payload))
    except AuthTransportError as exc:
        p.check("a 4xx raises AuthRefused", False, f"got plain AuthTransportError: {exc}")
    srv.shutdown()

    # Genuine transport failure: nothing listening.
    c2 = Client(api_key="550e8400-e29b-41d4-a716-446655440000",
                service_url="http://127.0.0.1:1", circuit_breaker_enabled=False,
                max_retries=0, timeout=2)
    try:
        c2.get_user_roles("alice")
        p.check("control: an unreachable service raises", False, "no exception")
    except AuthRefused as exc:
        p.check("control: unreachable is NOT reported as a refusal", False, f"got AuthRefused: {exc}")
    except AuthTransportError:
        p.check("control: unreachable still raises AuthTransportError", True, "plain AuthTransportError")
    return p.done()


if __name__ == "__main__":
    sys.exit(main())
