# 35 — Configurable database pool for embedded auth (auth 3.4.0)

Ticket: issuedb #35. Requested by highway-903357 on AgentBus threads 01M5JVCJ9MS5E18JQZTC1VT4EP and 01M5C4004MYDGDDG1WJWWDWH79 (blocks Highway's pg-nano-03 cutover: highway_app CONNECTION LIMIT 60, auth budget 1 connection per process).

EARS SPEC:
- The auth library shall read the PostgreSQL/SQLite QueuePool parameters from AUTH_DATABASE_POOL_SIZE, AUTH_DATABASE_MAX_OVERFLOW, AUTH_DATABASE_POOL_TIMEOUT (seconds) and AUTH_DATABASE_POOL_RECYCLE (seconds).
- Where a pool variable is unset, the auth library shall use the 3.3.0 value: PostgreSQL 2 / 2 / 10 s / 3600 s; file SQLite 5 / 10 / 30 s / 300 s.
- If AUTH_DATABASE_POOL_SIZE < 1, AUTH_DATABASE_MAX_OVERFLOW < 0, AUTH_DATABASE_POOL_TIMEOUT <= 0 or AUTH_DATABASE_POOL_RECYCLE is neither -1 nor >= 1, then the auth library shall refuse to build settings (import of auth.database raises ValidationError) without echoing AUTH_DATABASE_URL.
- When the engine is initialised, the auth library shall log the effective pool_size, max_overflow, pool_timeout and pool_recycle.
- While pool_size + max_overflow connections are checked out, the auth library shall fail a further checkout within pool_timeout (+1 s tolerance) with a pool TimeoutError; when a connection is returned, the next checkout shall succeed (0 deadlock).
- The auth library shall pass sslmode, sslrootcert, sslcert and sslkey from a URL query to psycopg unchanged, and shall not override a URL sslmode.
- When Authorization.close() is called, or a `with Authorization(...)` block exits, the auth library shall release the connection held by a session the instance opened, and shall not close a caller-supplied db_session.
- When 3.4.0 is released, PyPI shall serve auth 3.4.0 and auth.rodmena.app / auth.rodmena.co.uk /docs shall report 3.4.0.

TECHNICAL PROBLEMS:
1. Externalised configuration of a connection-pool resource bound, with fail-closed validation.
2. Bounded-pool admission: block-then-fail at the bound, resume on release.
3. TLS parameter pass-through from DSN to libpq.
4. Connection lifetime of the embedded wrapper (found during synthesis: a read leaves the session transaction open and holds a connection).
5. Release + deploy with served-artifact verification.

SOLUTION DOMAINS:
- Config -> pydantic-settings Settings with env_prefix AUTH_ (codebase pattern; names follow database_url/database_type/database_schema).
- Pool -> SQLAlchemy QueuePool (pool_size, max_overflow, pool_timeout, pool_recycle), already the engine's pool class.
- TLS -> libpq conninfo keywords via psycopg; SQLAlchemy's psycopg dialect forwards URL query items as connect kwargs.
- Session lifetime -> SQLAlchemy Session autobegin; connection returns to the pool on commit/rollback/close. Context-manager protocol for scoped release.

ALTERNATIVES:
- Surface: env settings [CHOSEN] vs caller-owned engine injection [REJECTED: the engine is a module-level singleton built at import, before caller code runs; injection is a new public API and lifecycle change for every embedder] vs pool args in the URL query [REJECTED: SQLAlchemy forwards URL query to psycopg as conninfo, so pool_size= would reach libpq as an invalid keyword].
- Names: AUTH_DATABASE_* [CHOSEN: matches AUTH_DATABASE_URL/TYPE/SCHEMA] vs AUTH_DB_* [REJECTED: a second prefix for one subsystem; Highway offered either].
- Validation: pydantic Field constraints at Settings construction [CHOSEN: fails at import, before any connection] vs a check inside DatabaseEngine [REJECTED: later, and a second copy of the rules].
- Defaults: Optional None => per-backend default [CHOSEN: keeps SQLite and PostgreSQL defaults distinct, no behaviour change] vs one numeric default [REJECTED: changes the SQLite pool from 5/10].
- Read-held connection: additive close() + context manager [CHOSEN: no behaviour change for existing callers] vs ending the read transaction after every wrapper call [REJECTED for this release: rollback expires loaded objects and changes semantics callers may rely on; recorded as follow-up candidate] vs documentation only [REJECTED: the only release path today is reaching into .db].

DEFAULT RATIONALE (moved from the database.py comment the change replaced):
PostgreSQL 2/2 is sized for ONE request per sync gunicorn worker. Served requests can hold two connections at once: the request session, plus the separate committed session audit.log_audit_event opens on the audit_log decorator's failure path and on the rotate/recover failure paths in routes/tenant.py. Two plus two spare, so 8 workers reach at most 32 connections against max_connections=200. These paths exist only under the Flask app; an embedder calling Authorization/AuthorizationService directly never opens the second session.

VERIFICATION:
- tests/test_database_pool_settings.py: defaults for both backends, full and partial overrides read back from engine.pool, 8 invalid values refused without the DSN password, boundary values accepted, subprocess import refused on AUTH_DATABASE_POOL_SIZE=0 (with a green control importing the worktree's own auth), effective values logged, SQLite cap times out in 0.4-1.5 s and resumes on release, TLS params captured at psycopg.connect (with a known-positive showing forced sslmode=require is captured when the URL has none), embedded read holds 1 connection until close(), with-block releases, caller-supplied session left open.
- tests/postgres/test_pool_settings_postgres.py: real PostgreSQL, pool 1+1 opens 2 distinct backends, third checkout times out in 0.9-2.5 s, resumes on release.
- audit/evaluations/probe_tls_dsn_params_reach_libpq.py: disposable PostgreSQL (hostssl cert only). verify-full + right CA + client cert connects as /CN=auth_tls over TLSv1.3; foreign CA refused (certificate verify failed); 127.0.0.1 not in SAN refused (proves verify-full, not verify-ca); no client cert refused by server.
