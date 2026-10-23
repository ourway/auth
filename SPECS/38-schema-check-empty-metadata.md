# 38 — check_schema refuses an empty model set (auth 3.5.1)

Ticket: issuedb #38. Raised by highway-903357 on AgentBus thread 01M5JVCJ9MS5E18JQZTC1VT4EP (message 01M5KA5SWK0KKV8M3WRA5RZ4JA): find_schema_drift walks Base.metadata, so if the models ever registered no tables, check_schema would pass with nothing checked. Follows #37 (SPECS/37-schema-check.md).

EARS SPEC:
- If the installed auth models register no tables in Base.metadata, then check_schema and find_schema_drift shall raise SchemaMismatchError stating that no auth tables are registered, instead of reporting no drift.
- While at least one table is registered, check_schema shall behave as in #37 (unchanged).

SYNTHESIS (localised bugfix):
- Solution domain: verification soundness (a check must be able to go red). Concept: refuse an empty comparison set.

ALTERNATIVES:
- Raise SchemaMismatchError [CHOSEN: one except clause covers both failure modes for embedders].
- A new exception type [REJECTED: callers catching SchemaMismatchError would let it propagate as an unexpected error].
- Hard-code the expected table list [REJECTED: duplicates the models and drifts from them].
