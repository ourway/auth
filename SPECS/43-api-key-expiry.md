# #43 Per-user API key expiry

issuedb #43. Release 3.7.0. Requested by vellum-build (thread 01M5XVVFMPJZ7F5YWNWPXKVSGA).

EARS SPEC:
- Where a create request for a per-user API key carries expires_at (ISO-8601 UTC), auth shall store it and return it in the create, list and validate responses.
- If expires_at is in the past or more than 365 days after issue, then auth shall answer 400 and create no key.
- When an existing key's expiry is updated, auth shall accept only an earlier time than the current one (or a first expiry within 365 days) and answer 400 otherwise.
- If the create body carries a field other than label or expires_at, then auth shall answer 400.
- When expires_at has passed, validate and check_permission shall answer 200 {"valid": false, "reason": "expired"} (test both sides of the boundary).

EVIDENCE: live 2026-10-27, create with {"expires_at": "2027-01-01T00:00:00"} returned expires_at null and no error. Requested by vellum-build (thread 01M5XVVFMPJZ7F5YWNWPXKVSGA) for casebound machine clients.
SYNTHESIS: deferred to start; awaiting director ordering.

vellum-build 2026-10-27 (01M5XWDMEMEXAD1CZV6A0KPP15): Vellum enforces expiry itself from its own metadata; #43 is defence in depth and does not block Vellum issuing keys. Priority unchanged pending the director.

SPEC CHANGE: a first expiry on a key without one must be within 365 days of NOW, not of date_created. date_created defaults to the database's now(), which follows the database timezone, while auth compares in naive UTC. SYNTHESIS: domain = credential lifetime; concept = server-enforced not-after with a maximum lifetime and monotone shortening (as for X.509 not-after and OAuth token lifetimes). ALTERNATIVES: expires_at absolute time [CHOSEN: Vellum asked for it, and it reads back as stored] vs expires_in_days [REJECTED: ambiguous on retry and at day boundaries]; shorten-only PATCH [CHOSEN] vs free update [REJECTED: a holder of the client key could extend a leaked key]; validation in the service [CHOSEN: library callers get the same rules] vs route-only [REJECTED].

## Measured

- tests/test_apikey_expiry.py: 18 cases, including both sides of the 365-day window, past and future, both sides of the expiry instant (valid 1 s before, expired at the instant), shorten-only PATCH, revoked, unknown and foreign-namespace keys, unknown create fields creating no key, and the client sending expires_at. Against the 3.6.0 code, 14 of them fail.

## Spec change and synthesis

- A first expiry on a key without one must be within 365 days of now, not of date_created. date_created defaults to the database's now(), which follows the database timezone, while auth compares in naive UTC.
- Domain: credential lifetime. Concept: a server-enforced not-after time with a maximum lifetime and shortening only (as for X.509 not-after and OAuth token lifetimes).
- ALTERNATIVES: an absolute expires_at [CHOSEN: what Vellum asked for, and it reads back as stored] vs expires_in_days [REJECTED: ambiguous on retry and at day boundaries]. A shorten-only PATCH [CHOSEN] vs a free update [REJECTED: a holder of the client key could extend a leaked key]. Validation in the service [CHOSEN: library callers get the same rules] vs in the route only [REJECTED].
