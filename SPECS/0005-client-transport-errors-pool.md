# SPEC 0005 — Client: unmistakable transport errors + working pool params

- **Ticket:** issuedb #10 — "Client: transport failure returns answer-shaped payload; pool
  params silently dropped (runflow report 01KYTHYA3AAKRWADAJX2ZBEK02)"
- **Origin:** agent-mail report from runflow (thread `thr-65ad651d72b94a8d817d`), 2026-07-30.
  Verified against 2.3.1 source: every client method's `except Exception` returns
  `{"error", "success": False, "data": {…echoed args…}}` (outage reads as denial), and
  `pool_connections`/`pool_maxsize` (client.py:68-69) are accepted but never passed to the
  mounted `HTTPAdapter` (client.py:101-105) — pool stuck at urllib3 default 10.

## EARS requirements

1. When any `EnhancedAuthClient` method fails at transport level and the client was constructed
   with `raise_on_error=True`, the client shall raise `AuthTransportError` instead of returning
   a payload.
2. While `raise_on_error` is False (default), the client shall preserve the 2.3.1 error-dict
   return shape and shall additionally include `"transport_error": true` in every
   transport-failure payload.
3. The client shall pass `pool_connections` and `pool_maxsize` constructor values through to the
   mounted HTTP adapter, with default `pool_maxsize` raised to 64.
4. Every client method docstring and the README shall state that on transport failure `data`
   lacks the answer field and `success` must be checked first.
5. If `create_api_key` (new in 2.4.0) fails mid-flight, then the client shall not automatically
   retry the POST (non-idempotent: a retry can mint a second key whose secret nobody saw).

## Notes

- One constructor flag instead of `*_or_raise` method twins keeps the API surface stable and
  makes migration a one-line change per consumer; default False preserves 2.3.1 behavior.
- `data` is kept in failure payloads (runflow's own warning: dropping it makes
  `result.get("data", result)` fall back to the outer dict and the falsy read survives).
- Pool assertions in tests must go green on a custom value before the default is trusted
  (a check that cannot go green cannot go red).
