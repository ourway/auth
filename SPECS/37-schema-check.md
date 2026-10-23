# 37 — Name missing columns at startup instead of failing on the first query (auth 3.5.0)

Ticket: issuedb #37. Raised by highway-903357 on AgentBus thread 01M5JVCJ9MS5E18JQZTC1VT4EP (message 01M5JY75YWRPXC08DYG0FKWZHG): an embedded database created by auth 3.1.0 lacks auth_tenant_settings.rotate_key_hash, rotate_key_issued_at and canary, which 3.2.0 added, and create_all never adds a column to an existing table.

EARS SPEC:
- The auth library shall provide check_schema(bind=None), taking an Engine or Connection (default: the configured engine), which compares every column declared by the installed ORM models against the live database tables in the configured schema.
- If one or more declared columns or tables are missing from the live database, then check_schema shall raise SchemaMismatchError whose message names every missing table and table.column, and shall not include credentials or the DSN.
- When create_tables() has created missing tables, the auth library shall run check_schema; if a declared column is still missing, then create_tables(raise_on_error=True) shall raise SchemaMismatchError, and create_tables() with the default shall log "create_tables failed" at ERROR with the missing names and return (unchanged non-raising default, which the server's import-time call relies on).
- While the live schema contains every declared column (extra columns allowed), check_schema shall return without error and without writing to the database.
- The auth library shall issue only read-only catalog queries (SQLAlchemy inspector) from check_schema; it shall issue no DDL.
- Where a release adds, alters or removes a column on a model, the changelog entry for that release shall list the exact DDL an embedder must run, with the matching migretti migration file name.
- check_schema shall complete within 500 ms against a local PostgreSQL holding every auth table.

TECHNICAL PROBLEMS:
1. Schema drift detection between declared ORM metadata and a live database (read-only introspection).
2. Fail-fast placement: surface drift at startup instead of at the first query.
3. Communicating required DDL per release to embedders who do not run our migretti migrations.

SOLUTION DOMAINS:
- Database introspection -> SQLAlchemy Inspector (get_table_names, get_columns), already a dependency.
- Fail-fast startup checks -> codebase pattern in auth/main.py (verify_row_level_security, verify_encryption_key).
- Release communication -> docs/changelog.rst (served on /docs), migretti migration files as source of truth.

ALTERNATIVES:
- Drift detection: Inspector column-name diff [CHOSEN] vs. ship migretti migrations inside the wheel and run them [REJECTED: the wheel would then issue DDL against an embedder's database and own their migration history; Highway runs its own migrations] vs. auto ALTER TABLE ADD COLUMN in create_tables [REJECTED: silent DDL against an embedder's live database, no review step, and type/index choices diverge from ours].
- Comparison depth: names only [CHOSEN] vs. names + types [REJECTED for now: dialect type reflection differs between SQLite and PostgreSQL and would produce false positives; missing columns are the failure seen].
- Placement: explicit helper + create_tables call [CHOSEN] vs. check inside Authorization.__init__ [REJECTED: adds a catalog round trip to every Authorization construction].

Origin: Highway (highway-903357) thread 01M5JVCJ9MS5E18JQZTC1VT4EP, message 01M5JY75YWRPXC08DYG0FKWZHG. Reproduced 2026-10-23 on PostgreSQL 16: auth 3.1.0 seed then 3.4.0 -> ProgrammingError column auth_tenant_settings.rotate_key_hash does not exist; after Highway DDL -> allowed True.
