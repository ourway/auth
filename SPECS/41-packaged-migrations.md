# #41 Ship migrations inside the package

issuedb #41. Release 3.6.0.

EARS SPEC:
- The auth wheel and sdist shall contain every migretti migration and the configuration needed to apply them.
- When an operator installs auth[migrations]==<version> from PyPI and runs one documented command against an empty PostgreSQL database, the auth package shall apply every migration for that version without any file fetched from git.
- When those migrations have been applied and auth starts with AUTH_DATABASE_SCHEMA=auth_rbac as a non-superuser owner role, GET and HEAD /readyz shall return 200 within 5 s of start.
- If AUTH_DATABASE_SCHEMA is not auth_rbac on PostgreSQL, then auth shall fail with a message naming AUTH_DATABASE_SCHEMA, not only the generic "row level security is not in force" 503.

EVIDENCE (2026-10-25, local postgres:18, auth 3.5.1 from PyPI):
- wheel and sdist: 0 .sql files (sdist lists 110 entries, auth/main.py present as the known positive).
- create_all only, public schema: every route 503 "row level security is not in force on: ...". apply_tenant_rls ProgrammingError (function is hard-wired to auth_rbac).
- mg apply from c4ebd9b, no AUTH_DATABASE_SCHEMA: same 503.
- mg apply + AUTH_DATABASE_SCHEMA=auth_rbac + non-superuser owner: readyz GET/HEAD 200 after 0.6 s, 120 MB RSS for 1 worker; role/permission/grant/has_permission and cross-namespace isolation correct.
- Requested by uptime-service (thread 01M5SP8CKP69PA7S48H5ETEDVT) to run auth inside a ci.rodmena.co.uk job with no egress.

TECHNICAL PROBLEMS:
1. Distributing schema migrations with a Python package.
2. Failing loudly on a schema misconfiguration.

SOLUTION DOMAINS: Python packaging package-data (setuptools); migretti (house migration tool).

ALTERNATIVES: to be recorded when work starts (package-data + migretti invoked with the packaged path, vs a separate migrations artifact).

## Synthesis

TECHNICAL PROBLEMS:
1. Distribute schema migrations with the Python package.
2. Run them from an installed package without knowing install paths.
3. Name the misconfigured setting when row level security cannot be in force.

SOLUTION DOMAINS: setuptools package-data; migretti (house tool; reads ./migrations and ./mg.yaml relative to the working directory, MG_DATABASE_URL overrides); keycheck boot verdicts (codebase pattern).

ALTERNATIVES:
- Packaging: SQL as package data in auth/migrations, with a root `migrations` symlink so the Makefile, CI and the vm-2 runbook keep working [CHOSEN] vs copying into the wheel at build time [REJECTED: two copies that drift] vs a separate migrations artifact [REJECTED: still fetched outside pip].
- Runner: `auth-migrate` console script running migretti in a subprocess with the working directory at the installed auth package [CHOSEN] vs an in-process chdir [REJECTED: process-global side effect; migretti loads .env from the working directory at import] vs documenting `cd site-packages/auth && mg apply` [REJECTED: consumers must know install paths].
- Schema hint: extend the RLS boot verdict to name AUTH_DATABASE_SCHEMA when it is not auth_rbac [CHOSEN] vs refusing any other schema at config load [REJECTED: library-mode embedders that never run keycheck would break].

## Measured

- scripts/fresh_install_check.sh, 2026-10-27, postgres:18, wheel built from the branch: auth-migrate apply applied 12 migrations, verify matched; without AUTH_DATABASE_SCHEMA readyz 503 naming AUTH_DATABASE_SCHEMA 'public'; with auth_rbac readyz GET 200 and HEAD 200; strict 409, key, grant, allow, deny and namespace isolation as expected.
- Unit tests: tests/test_migrate_cli.py (URL precedence, refusals, subprocess cwd, module entry point, schema hint).
- smoke_install.sh asserts the wheel carries every .sql in auth/migrations and that the installed auth-migrate prints usage with exit 2.
