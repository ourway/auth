# SPEC 0014 — `create_tables` reconciles pre-2.x varchar columns to TEXT

- **Ticket:** issuedb #21
- **Status:** implemented in 3.0.1
- **Origin:** highway observation in `01KYV037AHB1X8HATFDXNJRAJ4`
  (thread `thr-d99bb6c79b894ff69f16`). Filed by the reporter as "not a defect
  report"; rated higher here — see *Why* below.

## EARS spec

- When `create_tables` runs against a PostgreSQL database that already has
  character-varying columns where the current model metadata declares `Text`, the
  auth service shall widen those columns to `TEXT`.
- The auth service shall leave unchanged every column whose model metadata
  declares a bounded `String` type (`audit_log.user` remains a 64-char
  fingerprint column by design).
- If the reconciliation cannot be applied because the runtime role lacks DDL
  rights, then the auth service shall log the failure and continue starting,
  consistent with existing `create_tables` behavior.
- When `create_tables` runs against a database whose columns already match the
  model metadata, the auth service shall issue no `ALTER` statements.

## Why

`Base.metadata.create_all(checkfirst=True)` creates missing tables but **never
ALTERs an existing one**. An embedded database created by a pre-2.x version keeps
the narrow `varchar` widths that version declared. Encryption later made several
of those columns hold ciphertext far longer than the plaintext they used to, so
the mismatch surfaces as `StringDataRightTruncation` on write.

Highway hit exactly this on `auth_membership.user` (`varchar(64)`) when a longer
email was encrypted inside `add_membership`, and reconciled seven columns by hand
against a live database.

Rated above the reporter's "nothing needed": the failure mode is a **write-time
crash** for any embedded consumer whose database predates 2.x, and it is
discovered by outage rather than by mail. Precedent for a reconciliation pass
inside `create_tables` already exists — `_grandfather_strict_users`.

## Implementation

`auth.database._reconcile_text_columns(engine)`, called from `create_tables`
between `create_all` and the grandfathering pass.

- PostgreSQL only — SQLite does not enforce varchar length, so there is nothing
  to reconcile.
- Widens a column only when the model declares `Text` **and** the live column
  still carries a length. Anything already unbounded is skipped, which is what
  makes the pass a no-op on a current database.
- Honors `AUTH_DATABASE_SCHEMA`.
- Non-raising per column and overall: a runtime role without DDL rights must
  still be able to start the app. Each failure is logged with the real exception
  and names the consequence.

`audit_log.user` stays `String(64)` deliberately — it stores a **fitted
fingerprint** (`_fit(client_fingerprint(user), 64)`), not a user identifier. A
blanket "widen everything" pass would have destroyed that bound, so the rule is
strictly *only where the model declares `Text`*.

## Verification

`tests/postgres/test_text_column_reconciliation.py`, run via `make test-postgres`
against a real PostgreSQL 16. The suite recreates the pre-2.x shape and asserts
both directions:

- `test_narrow_column_genuinely_breaks_the_write` — the reproduction **first**:
  with `auth_membership.user` put back to `varchar(64)`, `add_membership` of a
  long identifier raises `DataError`. Without this the "it works after the fix"
  test would be vacuous.
- `test_reconciliation_widens_the_column_and_unblocks_the_write` — column becomes
  `("text", None)`, the same write then succeeds, and the value round-trips back
  intact through `has_membership` and `get_role_members`.
- `test_reconciliation_is_a_no_op_when_the_database_already_matches` — the pass
  runs on every boot, so repeated runs must issue no ALTERs.
- `test_bounded_string_columns_are_left_alone` — `audit_log.user` stays
  `("character varying", 64)`.

Full run: 15 passed.
