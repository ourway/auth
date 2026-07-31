# Contributing

Thanks for helping improve `auth`. This service gates access for other systems,
so correctness, security, auditability, and test rigor are held to a high bar.

## Local setup

Requires Python 3.11 (the deployed version; 3.12 is also tested in CI).

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev,ratelimit,migrations]"
```

The `Makefile` pins every tool to `.venv/bin`, so the targets below work whether
or not the venv is activated.

## The gates (run these before pushing)

```bash
make lint          # ruff check .
make type-check    # mypy .
make test          # sqlite unit suite (fast; encryption-on is exercised too)
make test-postgres # PostgreSQL integration + rotation + encrypted suites (Docker)
make check         # format + lint + type-check
```

- **`make test`** runs the SQLite suite. `tests/conftest.py` isolates every test
  to a throwaway SQLite DB and provides the `AUTH_*` env, so no `.env` is needed.
  Encryption-on paths are covered by `tests/test_encryption_integration.py` (it
  flips the field-encryption singleton on), so a crypto regression fails here.
- **`make test-postgres`** starts a disposable `postgres:16` container and runs
  `tests/postgres/` with `AUTH_ENABLE_ENCRYPTION=true`. If the container’s
  `pg_isready` wait is flaky locally, start it yourself and loop on a real
  `psql -c 'select 1'` before running `pytest tests/postgres/ -m postgres`.
- Postgres tests are marked `@pytest.mark.postgres` and excluded from the default
  run (`addopts = -m "not postgres"`).

## CI

`.github/workflows/ci.yml` runs on every push and PR to `master`:

- **quality** — `ruff check` + `mypy` (3.11)
- **test** — SQLite suite on 3.11 and 3.12
- **postgres** — the integration suite against a real PostgreSQL service, with
  encryption on

All jobs must be green. See [SPECS/0002-github-ci.md](SPECS/0002-github-ci.md).

## Coding standards

- **Style & imports**: `ruff` (includes import sorting). Keep new code matching
  the surrounding style — comment density, naming, idioms.
- **Types**: `mypy` must pass. Prefer real types over `Any`; narrow with
  `isinstance` rather than casting where practical.
- **Tenant scoping is non-negotiable**: every read/write must be scoped by
  `creator == self.client`. Never add a query path that could cross namespaces.
- **Secrets never leak**: never log or return the raw client key, encryption key,
  or JWT secret. Log the `client_fingerprint(...)`. Human identifiers in the
  audit trail are fingerprinted.
- **Fail closed**: don't mask a database error as a legitimate `False`; let it
  raise (it becomes a 500 and a failed audit). Encryption/decryption errors must
  raise, not return garbage.
- **Audit stays atomic**: mutating HTTP paths must let `with_db_session` own the
  single commit (service constructed with `manage_transaction=False`), so the
  audit row commits with the mutation. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#auditing--transactions).

## Tests

- Assert through the **product interface** (the Flask app / real DB / real
  crypto), not by re-implementing the logic under test.
- Test guards in **both directions** — e.g. a cap that blocks *and* releases; a
  write that succeeds *and* one that fails/rolls back.
- New `/api/` endpoints must be documented (a test asserts every route appears in
  the rendered docs) and covered by tests in both key states where relevant.

## Migrations

PostgreSQL migrations use **migretti** (SQL-first) — see
[MIGRATIONS.md](MIGRATIONS.md). Schema *creation* stays with `create_all` at boot;
migrations own *changes*. (The project's pre-migretti history lives in git
history only.)

## Commits & pull requests

- Small, focused commits with a clear subject (`type(scope): summary`) and a body
  explaining the *why*.
- Reference the issue where applicable.
- Open a PR against `master`; CI must pass. Include what you exercised and what
  you did not.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please do not open a public issue for
vulnerabilities.
