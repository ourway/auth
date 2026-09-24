# 27 — audit details must not carry the exception body

Ticket: issuedb #27 — **open, pending operator decision**

## EARS spec

- When an audited action fails, the auth service shall record the failure's
  exception **type** in the audit details, and shall not record the exception
  body.
- The auth service shall continue to record the failed attempt itself (action,
  resource, client, `success=false`), so the audit trail loses no events.
- Where a diagnostic body is needed, the auth service shall write it to the
  application log rather than to a tenant-readable audit row.

## Sites

| file | context |
|---|---|
| `auth/routes/tenant.py:69` | `details={"error": str(e)}` on a failed ROTATE_KEY |
| `auth/decorators.py:95` | `details={"error": str(e)}` on every audited action that raises |

Both write into `audit_log.details`, which the owning tenant reads back through
`GET /api/audit`.

## What str(e) actually contains

Measured, with controls shown to fire:

```
SQL statement present:       True
bound parameter present:     True
table/column names present:  True
CONTROL absent sentinel:     False   (must be False)
CONTROL detector works:      True    (must be True)
```

A SQLAlchemy DBAPI error stringifies to the statement, the table and column
names, and the bound parameter values.

## Severity: LOW, argued rather than asserted

- The bound parameters in a failing statement are the **caller's own** values, so
  this is not a cross-tenant read. RLS is forced on `audit_log` and the row is
  scoped to the caller.
- What does cross the line is **schema disclosure** — table names, column names
  and SQL structure handed to a customer for no operator benefit.
- The theoretical cross-tenant vector is a unique-constraint violation, where
  PostgreSQL's DETAIL names the **conflicting existing** value, which RLS does
  not hide. In auth the unique columns are `rotate_key_hash` and API key hashes,
  all 256-bit random, so provoking a collision is not a practical attack.
  Recorded because the mechanism is real even though this instance is
  unreachable.

## Alternatives

- **Record `type(e).__name__`, body to the application log [CHOSEN, pending
  review]**.
- Redact `str(e)` with a pattern [REJECTED — a redactor that misses one shape
  discloses with full confidence].
- Leave as is [REJECTED — nobody debugs from audit details, so the disclosure
  buys nothing].

## Provenance

Found by applying the sweep methodology stabilize published after their own
first sweep missed this exact shape: they matched `logger(..., exc)` and missed
exceptions formatted into f-strings. Re-swept auth for `{e}`, `str(e)`,
`repr(e)`. AgentBus 01M398TEMTS3JTWZB1B5R740A1.

## Why this is not being fixed unilaterally

It changes what is written to the **audit trail** on failed actions — a semantic
and potentially compliance-relevant change. Operator decision.

## Related

`auth/workflow_checker.py` has four `print(f"...{e}")` calls. They currently go
nowhere (see #24 — no application logging on vm-2), but they would start
emitting exception bodies the moment logging is wired up. Worth folding into
whichever change lands first.
