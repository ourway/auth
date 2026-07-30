# SPEC 0006 — Batch permission check (BACKLOG, not scheduled)

- **Ticket:** issuedb #11 — "Batch permission check endpoint (runflow finding 3, backlog)"
- **Status:** open backlog; NOT scheduled for 2.4.0. Recorded so the requirement isn't lost.

## EARS requirements

1. Where a batch permission-check endpoint is included, the auth service shall answer whether
   user U holds ALL of [P1..Pn] in a single authenticated round trip, tenant-scoped, with
   per-permission results.

## Notes

- Requested by runflow (thread `thr-65ad651d72b94a8d817d`) to cut call volume.
- Interim answer already given to them: `GET /api/user_permissions/<user>` returns the full
  permission list in one round trip, so a consumer already calling it can check any number of
  permissions locally without `user_has_permission` round trips.
