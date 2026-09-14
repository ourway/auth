# SPEC 0018 — Widen the cryptography cap so security updates are never blocked

- **Ticket:** issuedb #4
- **Status:** in-progress
- **Tags:** security
- **Origin:** infra ticket 18 (infra-manager-c13110), AgentBus thread 01M2F63Z89QG51XS4KG3ED6RBB

## Context

`pyproject.toml` declared `cryptography>=3.0.0,<48`. The comment three lines
above that pin reads:

> Upper bounds cap the next major so a surprise breaking release cannot be
> pulled into an editable/systemd deploy; cryptography is given headroom so
> security updates are never blocked.

The pin did the opposite of what the comment stated. The commit that introduced
it, 9e9230d (2026-07-25), says the same thing in its own message — "cap the next
major; cryptography kept open for security updates" — while its diff replaced
the previously unbounded `cryptography>=3.0.0` with `<48`. The cap was the
blanket upper-bound policy of that commit sweeping up the one dependency the
commit had deliberately exempted.

CVE-2026-69247 (CVSS 8.2, Bleichenbacher oracle in `pkcs7_decrypt_*`) affects
`44.0.0 <= cryptography < 50.0.0`. With the cap in place, a clean resolve of any
auth consumer selected 47.0.0 — inside that window. The published metadata of
auth 3.1.0 was therefore *selecting* a vulnerable version for every fresh build,
and blocked the vm-2 host remediation to the 50.x system package.

## EARS requirements

- The auth package shall declare a `cryptography` constraint that admits the
  CVE-2026-69247-patched releases (>= 50.0.1).
- If a consumer performs a clean dependency resolution of auth, then the auth
  package shall not force `cryptography` to a version inside the affected window
  `44.0.0 <= v < 50.0.0` while a patched release exists.
- The auth package's pinned lockfiles (`requirements.txt`, `uv.lock`) shall pin
  `cryptography` to a release outside the affected window.
- When the full test suite is executed against cryptography 50.0.1, the auth
  package shall pass with 0 failures and 0 errors.
- The auth package shall not import
  `cryptography.hazmat.primitives.serialization.pkcs7` on any runtime path,
  verified by an import-graph probe carrying a positive control that
  demonstrably flips to True.

## Technical problems

1. **Constraint-specification correctness.** A blanket cap-the-next-major policy
   applied to a dependency whose documented policy is the opposite.
2. **Supply-chain pin hygiene.** The reproducible lockfile pinned
   `cryptography==46.0.3`, inside the vulnerable window, so every reproducible
   build deterministically installed a vulnerable library.
3. **Compatibility characterization** across a two-major jump (47 -> 50) with no
   production trial available.

## Solution domains

- Version specification -> PEP 440 specifiers; the packaging practice that
  upper-bound caps on security-critical libraries convert a patch into a
  resolution failure.
- Compatibility characterization -> the project's own suite executed against the
  candidate in an isolated venv, the pattern established by 9e9230d and
  `tests/test_encryption_integration.py`.
- CVE reachability -> import-graph probe with a positive control (method
  supplied by infra-manager-c13110, independently re-run here).

## Alternatives

**Constraint shape**

- `cryptography>=3.0.0`, unbounded — **CHOSEN.** Restores the intent stated
  verbatim in both the pyproject comment and the 9e9230d commit message. The
  deploy-side breakage risk the cap was meant to carry is already carried by
  `requirements.txt`, which is the pinned lockfile and the correct place for
  that guard.
- `cryptography>=3.0.0,<51` — **REJECTED.** Keeps the policy shape but re-arms
  this identical incident the day 51.0 ships. The failure mode being fixed is a
  security patch blocked by our own metadata; a lower ceiling only moves the
  date.
- `cryptography>=50.0.1` — **REJECTED.** Inverts the problem instead of solving
  it. vm-2's system package is 48.0.1, so the running host becomes non-compliant
  the moment it is published, and every consumer pinned below 50 breaks in
  lockstep. auth's API surface (AES-CTR, SHA256, PBKDF2HMAC, HKDFExpand) is
  identical on 46, 47, 48 and 50, so excluding the lower versions buys nothing.

## Verification

Measured, not asserted:

| Check | Result |
|---|---|
| Full suite against cryptography 50.0.1, version-guarded | 220 passed, 5 skipped, 0 failed |
| `ruff check .` | All checks passed |
| `mypy .` | Success, 82 source files |
| Project-venv suite (cryptography 47.0.0) | 219 passed, 6 skipped |
| Built wheel `Requires-Dist` | `cryptography>=3.0.0` |
| Clean consumer resolve of the built wheel | `cryptography-50.0.1` — outside the window |
| pkcs7 loaded after `import auth` | False (23 cryptography submodules loaded) |
| Positive control: deliberate pkcs7 import | True — the probe can say YES, so its NO is real |

## Known limits

- The reachability evidence class is "library present, vulnerable path never
  imported", which is weaker than "library never loaded at all". Recorded as the
  weaker claim.
- The compatibility run exercised the test suite on Linux/CPython 3.13 against
  50.0.1. The production host is FreeBSD on the system package; auth's venv
  there carries no cryptography of its own. The 50.x FreeBSD package upgrade is
  infra's step and is not exercised by this change.
- `uv.lock` retains a 47.0.0 branch under the `python_full_version <= '3.9'`
  marker. Both 47.0.0 and 50.0.1 exclude 3.9.0/3.9.1 in their own
  `Requires-Python`, so that branch is a marker artifact rather than a reachable
  install path.

## Release blocker (separate defect, not fixed here)

`make publish` is gated on green CI, and master has been red since 2026-08-09 for an unrelated
reason. Reproduced live against a fresh `postgres:16-alpine`, running the exact CI step:

```
mg apply
  ... 4 migrations applied ...
  ERROR: Failed to apply 01KZJWHG32K9X1AFBPPB4YJC6A:
         relation "auth_rbac.audit_log" does not exist
  exit code 1
```

Schema-shaped, not migretti-shaped — migretti named the failing migration and the postgres
error and exited non-zero, which is correct. Isolated to the statement:

| Statement | Fresh DB |
|---|---|
| The conversion `DO` block | OK — its absent-table guard works |
| `CREATE INDEX ... ix_auth_rbac_audit_log_id` | FAILS — relation does not exist |

The three trailing `CREATE INDEX IF NOT EXISTS ... ON auth_rbac.audit_log` statements sit
*outside* the `DO` block. `IF NOT EXISTS` guards the index name, not the table, so with the
table absent they error instead of no-opping.

Underlying cause: no migration creates `auth_rbac.audit_log` — SQLAlchemy
`create_all(checkfirst=True)` does, at app boot. CI runs `mg apply` on an empty database before
the app has ever booted. Production is unaffected and was never at risk. Needs its own ticket.
