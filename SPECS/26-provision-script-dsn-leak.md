# 26 — provision_audit_partitions must not print the DSN

Ticket: issuedb #26

## EARS spec

- If psycopg raises while PARSING the DSN, then `provision_audit_partitions.py`
  shall report the exception TYPE and the source environment variable, and shall
  not emit the exception body or traceback.
- When the DSN is well-formed and the database is unreachable, the script shall
  still report the exception type and the DSN variable name.
- If the DSN cannot be parsed or connected, then the script shall exit 2.

## Technical problems

1. Credential disclosure through a third-party exception body on an unhandled
   path. The script runs from cron, and cron mails stderr — so the traceback has
   a delivery mechanism, not just a log file.
2. Diagnosability must survive the redaction. A rule that leaves an operator
   unable to debug a failed connection is a rule they will remove.

## Solution domains

libpq error semantics. A psycopg exception raised while **parsing** a conninfo
string quotes that string back in full, password included; one raised while
**connecting** describes only the endpoint (host, port, user, dbname) and never
the password, even when the server has just rejected that password.

Both reach the caller as the same exception class from the same call, so the
caller cannot branch on which it has. Measured locally with a known-positive
control, and independently by mail-api, uptime-service and infra-manager on
AgentBus thread 01M36DWW2F5BDVJZTQ58DF3HYB.

Measured here (psycopg 3.3.4, impl=python), sentinel password:

| case | outcome | leaked |
|---|---|---|
| `postgresql+psycopg://` via `_dsn()` (vm-2's real shape) | OperationalError | no — the `+psycopg` strip already covered it |
| `postgres!!!://` typo'd scheme | ProgrammingError | **yes, full DSN** |
| missing `@` separator | OperationalError | no |
| control: `+psycopg` with the strip removed | ProgrammingError | yes |

auth's application paths were measured at the same time and are clean:
`_forced_sslmode`, `make_url`, `create_engine` and `engine.connect()` disclose
nothing on any malformed or unreachable input, because SQLAlchemy parses the URL
itself and strips the dialect prefix before psycopg sees a conninfo string. auth
does not use `psycopg_pool`, so the pool-logging disclosure mail-api found does
not apply here.

## Alternatives

- **Catch `psycopg.Error` around connect, print `type(e).__name__` + the variable
  name [CHOSEN]** — cannot leak, and names both what failed and where the DSN
  came from.
- Redact the body with a regex [REJECTED] — a redactor that misses one shape
  discloses with full confidence, and the type name already carries the
  diagnostic value.
- Suppress output entirely [REJECTED] — trades a latent disclosure for a
  permanent blind spot on the one script whose job is to discover a bad DSN.

## Verification

`tests/test_provision_script_no_dsn_leak.py`, five cases, demonstrated red
before green: with the fix reverted, 4 of 5 fail and the captured stderr
contains the sentinel password verbatim. The suite includes
`test_the_trigger_still_exists`, a known-positive control asserting psycopg
still quotes a malformed conninfo string — without it the leak assertions would
pass if the danger merely disappeared, rather than because the script defends
against it.

## What this does not cover

The exposure is latent, not live: it needs a malformed DSN, and production's is
well-formed because the service runs. It fires on misconfiguration — which is
exactly when someone is tailing output and pasting it into a ticket.
