# #46 get_rotate_key and recover silently turned strict_users off

issuedb #46 (critical, security). Release 3.7.1. First shipped in 3.2.0 (2026-09-20, commit 4e770c4).

EARS SPEC:
- When a recovery key is issued for a namespace with no settings row, auth shall create the row with the namespace's effective strict_users value (the server default), never a fixed false.
- When a namespace is recovered and the settings row has to be created, auth shall use the effective value, not false.
- The audit entry for GET_ROTATE_KEY shall record the namespace's strict_users value and whether a settings row was created.
- Issuing a recovery key or recovering shall never change strict_users (both directions tested: default-strict stays strict, explicitly non-strict stays non-strict).

ROOT CAUSE: auth/services/tenant.py:89-91 issue_rotate_key and auth/services/recovery.py:116-118 created AuthTenantSettings(strict_users=False). Shipped 2026-09-20 in 4e770c4 (#19).
IMPACT: cmi5 console namespace non-strict from 2026-10-25T13:17:18Z to 2026-10-27T07:28:30Z, with no members in that window (cmi5-audit). The access log since 3 Aug shows the other successful calls: this workstation's test runs, and one unknown caller on 2026-10-22 09:48Z from 87.81.x (asked infra).
REPORTED BY: cmi5-audit, thread 01M5Y44790RHXWXFFF4N912GHK.
SYNTHESIS: localized fix in the two writers; concept = a side-effect write must preserve the observable value it materialises. Alternative of changing the model default to True rejected: the grandfathering and sentinel inserts pass explicit values, and a default that differs from AUTH_STRICT_USERS_DEFAULT is the same class of bug.

## Why the suite never caught it

tests/conftest.py sets AUTH_STRICT_USERS_DEFAULT=false, the opposite of production. Every test namespace started non-strict, so a write of false changed nothing a test could see. tests/test_rotate_key_preserves_strict.py pins the production default (true) in an autouse fixture.

## Measured

- Reproduced on released 3.7.0 code: settings true, get_rotate_key 200, settings false, audit GET_SETTINGS, GET_ROTATE_KEY, GET_SETTINGS with no UPDATE_SETTINGS.
- tests/test_rotate_key_preserves_strict.py: 5 cases; against 3.7.0 code 3 fail (default-strict stays strict, recovery stays strict, audit records the value), 2 pass (the opted-out namespace stays non-strict and the configured default is followed, both true before the fix too).
- Restart reproduction on 3.7.0 with RLS in force: two restarts change neither strict_users nor memberships.
- Scope from the vm-2 access log (complete since 3 Aug): successful get_rotate_key/recover calls were this workstation's test runs (93.89.141.229, throwaway namespaces), cmi5 on 25 Oct (57.129.187.239, restored 27 Oct 07:28:30Z by infra, no members while non-strict), and an outside evaluator on 22 Oct from a Fastly pool running the published quickstart in its own namespace (infra, thread 01M5Y591MB7WCDMVKZ2E9EYM59).
