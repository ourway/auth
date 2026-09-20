# Audit probes

Each probe drives auth through its own interface, asserts an outcome, and prints
`PASS`/`FAIL` with the evidence it saw. `run_all.sh` runs the safe set, exits 1
on any failure, and **exits 2 if any probe could not run** — a probe that
skipped has checked nothing, and counting it as a pass turns "I had no database
to ask" into "tenant isolation is fine".

Set `AUTH_PG_URL` for the PostgreSQL probes, or use `make probe-postgres`, which
builds a disposable container with a non-superuser role that owns the tables —
as production has. Run as a superuser, every RLS probe passes without RLS
existing at all.

## Before you add a check here, apply this trigger

> Whenever a check reports a **negative** — no drift, no leak, nothing pending,
> zero occurrences, headroom fine — ask what it does when it **cannot look**.
> If that produces the same output as "looked and found nothing", it has two
> states and one of them is a lie.

It is narrow and checkable, which is why it is written down instead of the
principle behind it. The principle — that a check can be correct about a
narrower thing than the question being asked of it — generalises to nothing you
can act on at 3am.

Worked examples from this repo, all of them real:

| the check | what it did when it could not look |
|---|---|
| `run_all.sh` | printed `probes: 13   failed: 0` while five probes had skipped |
| postgres CI job | ran as a superuser, so every RLS test passed with RLS stripped |
| `verify_row_level_security` | filtered on `current_schema()`, matched no tables, reported nothing to check |
| the RLS table list | a ninth table nobody added was unprotected and invisible to the list that guards it |
| the exemption guard | `bool(None)` on a missing `pg_roles` row answered "not exempt" |
| a verdict watcher | its event query errored, so the count defaulted to 0 and only `CLEAN` was reachable |

Every one reported a reassuring negative. None could have reported anything
else.

The fix in each case was a **known-positive in the same run**: point the
instrument at a case you know is bad and confirm it says so — not as a separate
"the probe works" step beforehand, which is two claims with a gap between them.
`probe_rls_covers_every_tenant_table` asserts discovery found `auth_group`
before trusting that it found nothing else; the watcher refuses to report unless
the pre-switch window still returns its 9 known events.

The trigger came from provenance-50ca06, who hit the same class on an unrelated
codebase the same night and stated it better than we had.
