# SPEC 0002 — GitHub Actions CI

- **Ticket:** issuedb #4
- **File:** `.github/workflows/ci.yml`

## EARS requirements

1. When a commit is pushed to `master` or a pull request targets `master`, the CI shall run ruff lint, mypy type-check, and the sqlite unit suite, and fail the run on any error.
2. The CI shall run the PostgreSQL integration suite with field encryption enabled against a real PostgreSQL service container, so the encrypt/decrypt and key-rotation paths are exercised on every change.
3. The CI shall install the project and its dev tools from declared dependencies (`.[dev,ratelimit,migrations]`) so runs are reproducible.
4. The CI shall run the unit suite on the deployed Python (3.11) and one forward version (3.12).
5. If any gate fails, then the CI shall report a failing status suitable for branch protection.

## Jobs

- **quality** (3.11): `ruff check .` + `mypy .`.
- **test** (matrix 3.11, 3.12): `pytest` (sqlite; the `not postgres` marker is the pyproject default; encryption-on is exercised by `tests/test_encryption_integration.py`).
- **postgres** (3.11 + `postgres:16-alpine` service, `AUTH_ENABLE_ENCRYPTION=true`): waits for a real DB connection (avoids the transient-init-server race), then `pytest tests/postgres/ -m postgres`.

## Notes

- The sqlite job needs no `.env`: `tests/conftest.py` sets the `AUTH_*` test env (including a non-placeholder audit pepper) before `import auth`, so the fail-closed config validator is satisfied.
- Secrets in the postgres job are throwaway CI values, not real secrets.
