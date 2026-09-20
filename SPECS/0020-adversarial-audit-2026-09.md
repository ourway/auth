# SPEC 0020 — Adversarial audit (3 passes) and remediation

- **Tickets:** issuedb #12 (F-2), #13 (F-4), #14 (F-3), #15 (F-5), #16 (F-1), #17 (F-6)
- **Status:** in-progress — Steps 0-4 landed (unmerged, undeployed); #11 and deployment open
- **Plan:** `~/.claude/plans/ok-run-two-passes-linear-quiche.md`
- **Method:** `mission-critical-audit` skill, single-threaded, non-destructive (read-only mode)

## Context

Three adversarial passes over a tier-0 authorisation service whose answers are
cited in an NCSC self-assessment awaiting signature. Pass 1 attacked the highest
blast radius; Pass 2 tried to refute Pass 1's own findings; Pass 3 attacked the
remediation plan and reordered it.

## EARS requirements (Step 1 — landed)

- The auth service shall apply exactly one definition of client-key validity.
- If a presented client key is not a valid UUID4, then the auth service shall
  return 400 and shall not open a database session.
- When a request arrives through the reverse proxy, the auth service shall record
  the originating client address in the audit row.
- If a client supplies its own `X-Forwarded-For`, then the auth service shall not
  honour it (exactly one trusted proxy hop).
- Where a caller supplies a user identifier containing `|` or `:`, the auth
  service shall accept it.

## EARS requirements (open)

- When the configured encryption key cannot decrypt the deployment's stored
  canary, the auth service shall refuse `/api/*` with 503 and report `/health`
  unhealthy, and shall not hard-crash (#12).
- When the database is slow but reachable, the auth service shall shed load rather
  than holding a worker until timeout, and shall sustain more than 2 concurrent
  requests (#13).
- The auth deployment shall keep at least 3 months of future `audit_log`
  partitions provisioned, and shall alert if rows land in the default
  partition (#15).

## Findings

| | Severity | Finding | Status |
|---|---|---|---|
| F-2 | critical | Changing/losing `AUTH_ENCRYPTION_KEY` silently denies every authorisation; `/health` stays healthy; key loss is unrecoverable | CONFIRMED, **fixed** (#12) |
| F-4 | critical | 2 sync workers ⇒ estate-wide concurrency of 2; a DB latency event becomes a total outage; `/health` probes reads only | CONFIRMED config / SUSPECTED cause, **fixed** (#13) |
| F-3 | high | Every audit row records `127.0.0.1` — no ProxyFix | CONFIRMED LIVE, **fixed** (#14) |
| F-5 | medium | Audit partitions exhaust 2027-09-01; nothing provisions more; retention cannot reclaim the default partition | CONFIRMED, **fixed** (#15) |
| F-1 | medium | Two divergent client-key validators ⇒ 500 instead of 400 | CONFIRMED LIVE, **fixed** (#16) |
| F-6 | medium | `USER_NAME_PATTERN` rejects `\|` and `:` | CONFIRMED, **fixed** (#17) |
| F-7 | low | `BackgroundScheduler` started pre-fork under `preload_app` | CONFIRMED, **fixed** (lazy start) |

## Falsifications that failed (positive results)

- Tenant isolation holds — all 22 query sites scoped; detector proven able to flag.
- Cross-tenant API-key validation is correct; the only timing distinction requires
  already holding the 256-bit secret.
- The API-key cap works in **both** directions (blocks at 25, releases on revoke).
- The client-key regex is properly anchored.
- `verify_audit_pepper` fails closed at boot.
- The CORS wildcard is **not** a credential-exposure risk — no
  `Access-Control-Allow-Credentials`, no ambient authority. This refutes an
  earlier claim of ours given to procurement-desk-95465d.

## Harness

`audit/evaluations/` — one probe per finding, driving the service through its own
HTTP interface against an ephemeral instance, printing PASS/FAIL plus evidence.
`run_all.sh` is safe against a live host; destructive probes require
`AUDIT_ALLOW_DESTRUCTIVE=1`. **Every probe was demonstrated red on the unfixed
code before being trusted green.**

## Not exercised

No failure injection (read-only audit mode): the database was never stopped,
slowed or filled; no process killed mid-operation; no clock skew. The 09:21Z
commit stall was never reproduced, so F-4's causal link is reasoned, not shown.
No sustained load beyond an 8-request burst. Key rotation was never run against
production. The retention path has never run in production. F-7 is unresolved —
the thread probe could not distinguish absence from naming.


## Implementation notes discovered while fixing

- **`statement_timeout` does not bound `COMMIT`.** The reported failure is a
  commit stall, so no statement timeout can shed it. Concurrency, not timeouts,
  is the mitigation for F-4 — this inverted Step 3's planned ordering.
  `tcp_user_timeout` would bound it at the socket and was **rejected**: dropping
  a connection mid-COMMIT leaves the outcome ambiguous, and an ambiguous
  permission grant is worse than a slow one.
- **Connection headroom measured**: `max_connections=200`, ~40 in use across 11
  roles, auth using 3. The concurrency raise (2 → 16) is comfortably within it.
- **Key rotation measured** at 0.12 ms/row — about 1s for the largest namespace
  on this deployment (4,139 memberships + 4,181 API keys), so a 10s
  `statement_timeout` leaves 10× headroom. Pass 3's concern that a lower timeout
  could make rotation impossible is refuted by measurement.
- **The test suite shared one SQLite database** across modules that deliberately
  enable encryption, so the new key check correctly reported a mismatch that no
  deployment could be in. Cleared between tests rather than weakening the check.
- **My own first canary probe went red for the wrong reason** — the stage
  subprocess crashed, every value was `None`, and one check passed vacuously.
  Hardened to fail loudly on a dead stage.
