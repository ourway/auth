# SPEC 0013 — Weak-secret warnings belong to the server/embedded paths, not to import

- **Ticket:** issuedb #20
- **Status:** implemented in 3.0.1
- **Origin:** tokengate report `01KYTYXAW498XK3Q0MDYYHRHG9` (thread `thr-b7e8b0c2c7914d56b6f1`,
  reply expected) and runflow incidental note `01KYTZQKCDP2WPBMNE04K4MA5X`
  (thread `thr-44794b4bbb6448c2bc01`). Two independent consumers, same finding.

## EARS spec

- While the auth package is imported by a process that initializes neither the
  embedded server nor an embedded database session, the auth package shall emit
  no secret-configuration warnings.
- When the embedded server is initialized via `create_app`, the auth service
  shall emit the weak-JWT-secret and weak-audit-pepper warnings if the effective
  values are weak.
- When an embedded consumer constructs the `Authorization` wrapper or calls
  `create_tables`, the auth package shall emit those same warnings if the
  effective values are weak.
- The auth package shall emit each secret-configuration warning at most once per
  process.
- If the audit pepper is weak when the server starts, then the auth service shall
  continue to refuse to start (fail-closed behavior unchanged).

## Why

`auth/__init__.py` imports `auth.database`, which builds the `DatabaseEngine`
singleton at module scope. That constructs `Settings`, which fired two warnings
from its validators. So `python -c "import auth"` printed:

```
AUTH_JWT_SECRET_KEY is a weak/placeholder value. Set a strong secret for production.
AUTH_AUDIT_PEPPER is unset, a placeholder, or too short; audit key fingerprints are not offline-guess resistant. Set a strong value before serving traffic.
```

A client-only consumer signs no JWTs and writes no audit rows, so neither line is
actionable for them. Worse, the lines land in *their* boot logs where they read
as *their* misconfiguration — and two scary secrets-shaped lines on every boot is
exactly how operators are trained to ignore secret warnings.

The server path never needed them: `create_app` already calls
`verify_audit_pepper`, which **fails closed**. The import-time warnings were
duplication there and noise everywhere else.

## Implementation

- Deleted the `validate_secret_key` field validator and the
  `warn_on_weak_audit_pepper` model validator. `Settings` construction is silent.
- Added `config.warn_on_weak_secrets(settings)` — idempotent per process via a
  module-level latch — plus `config.jwt_secret_is_weak(settings)`.
- Called from the three paths that actually use these secrets:
  `main.create_app` (server boot), `database.create_tables` and
  `Authorization.__init__` (embedded).

## Verification

Subprocess probe, fresh interpreter per case, stderr captured separately from
stdout, `AUTH_*` scrubbed, run from a temp cwd so the repo `.env` cannot mask the
result. Both directions:

| Case | JWT warning | Pepper warning |
|---|---|---|
| bare `import auth`, WEAK secrets | no | no |
| `Client(api_key=…, service_url=…)`, WEAK secrets | no | no |
| embedded `create_tables`, WEAK secrets | **yes** | **yes** |
| embedded `Authorization(…)`, WEAK secrets | **yes** | **yes** |
| `create_app`, WEAK jwt, debug on | **yes** | no (debug gate) |
| embedded `create_tables`, STRONG secrets | no | no |
| `create_app`, weak pepper, debug OFF | rc=1, `Refusing to start` (fail-closed intact) |

Tests live in `tests/test_config.py`. The absence assertion is non-vacuous:
`test_embedded_create_tables_still_warns` asserts the **same** warning strings are
**present** through the **same** subprocess/stderr mechanism that
`test_bare_import_is_silent_in_a_client_only_process` uses to assert absence.
