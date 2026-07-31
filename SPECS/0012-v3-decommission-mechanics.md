# SPEC 0012 — auth 3.0.0 decommission mechanics

- **Ticket:** issuedb #18. Delivers SPEC 0007 (client error dict) and SPEC 0008 req 7
  (strict default) — gate basis: all responding platforms confirmed (ledgers on tickets
  #12/#13); operator declared the non-responding platforms (stabilize, migretti,
  datashard, supervice; futex for #13) non-consumers on 2026-07-31.

## EARS requirements

1. When any client method fails at transport level, the client shall raise
   `AuthTransportError`; the legacy error-dict return shall not exist. The
   `raise_on_error` constructor parameter shall remain accepted as a deprecated no-op
   (warning) so 2.x constructor calls do not break.
2. When a tenant has an `auth_tenant_settings` row, its `strict_users` value shall
   govern, unchanged.
3. When a tenant has no settings row, the service shall apply
   `AUTH_STRICT_USERS_DEFAULT`, which shall default to true in 3.0.0.
4. Before 3.0.0 code serves decisions on an existing database, every creator present
   shall receive an explicit `strict_users = false` row (grandfathering), applied
   exactly once per database via a reserved marker row
   (`__meta:grandfathered-3.0__`): by migretti migration `grandfather_strict_users`
   in our deployment and by a marker-guarded pass in `create_tables()` for embedded
   databases — so no existing tenant's behavior changes at upgrade, and creators
   appearing after the marker are never grandfathered.
5. The grandfathering pass shall never modify an existing explicit setting.
6. The mechanics shall be announced on the bus before the release is published,
   including guidance for embedded consumers with floor-only pins (cap `<3` or set
   `AUTH_STRICT_USERS_DEFAULT=false` until key-backing lands).
7. The release shall follow the full gate: local checks, hosted CI green, migration
   before restart, live probes covering the new-tenant strict default in both
   directions and the grandfathered/opted-out paths, PyPI publish only after live
   verification, tag and GitHub release.

## Notes

- Test suites run with `AUTH_STRICT_USERS_DEFAULT=false` to model the grandfathered
  reality of every pre-3.0 consumer; `tests/test_strict_default.py` covers the true
  default and the one-shot grandfather pass explicitly.
- The marker creator name is reserved; it is excluded from nothing (it simply never
  matches a real tenant's key format in practice) and documented here and in
  `auth/database.py`.
