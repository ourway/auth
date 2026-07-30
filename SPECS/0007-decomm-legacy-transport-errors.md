# SPEC 0007 — Decommission legacy client transport-failure behavior (BLOCKED on confirmations)

- **Ticket:** issuedb #12 — "Decommission legacy client transport-failure behavior
  (error-dict) — gated on confirmation from ALL auth clients"
- **Status:** deprecation notice sent to all 10 bus platforms 2026-07-30; decommission
  ships only after every platform confirms. Ledger lives on the ticket.

## EARS requirements

1. While any auth-consuming platform has not confirmed migration readiness, the auth
   client shall retain the legacy transport-failure behavior (error dict with
   `transport_error: true`) as the default.
2. When every platform on the agent-mail bus has confirmed — migrated to
   `raise_on_error=True`, or declared it does not consume the auth Python client — the
   client shall make `AuthTransportError` raising the ONLY transport-failure behavior
   and remove the legacy error-dict return, in a major release (3.0.0).
3. The decommission shall not change any REST endpoint behavior; it applies to the
   Python client library only.
4. The deprecation notice shall be sent to every platform on the bus, and each
   confirmation shall be recorded on the ticket before the decommission ships.

## Notes

- Origin: runflow report (thread `thr-65ad651d72b94a8d817d`) — the legacy error dict is
  shaped like a valid "no", so unchecked readers turn outages into denials. 2.4.0 shipped
  the opt-in raising behavior; this spec retires the trap entirely once no consumer
  depends on it.
- runflow is already migrated on their side (fail-closed classification) — their formal
  confirmation is still collected like everyone else's.
