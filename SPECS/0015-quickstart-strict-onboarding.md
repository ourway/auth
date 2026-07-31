# SPEC 0015 — The documented quickstart must succeed on a post-3.0.0 namespace

- **Ticket:** issuedb #22
- **Status:** implemented in 3.0.1
- **Origin:** found while releasing 3.0.1 — `make publish` aborted because the
  pre-publish smoke test failed at `add_membership`. Confirmed **not** a 3.0.1
  regression: the released 3.0.0 wheel reproduces it identically.

## EARS spec

- The auth documentation shall present an onboarding sequence that succeeds on a
  namespace created after 3.0.0.
- When the documented quickstart grants a membership, the auth documentation
  shall first issue a per-user API key for that user, because a namespace created
  after 3.0.0 is strict by default.
- Where a consumer's users cannot hold auth API keys, the auth documentation
  shall show the explicit per-tenant opt-out as the alternative first step.
- The pre-publish smoke test shall exercise the same sequence the README
  documents, so a quickstart that cannot succeed fails the release.

## Why

3.0.0 made strict user identity the default for namespaces created after the
flip (SPEC 0008/0012). Grandfathering protected every *existing* tenant, and it
worked — 181 tenants, 0 changed. But the **documented onboarding path** predates
the flip: it tells a brand-new user to generate a fresh UUID key and immediately
grant a membership. On a post-3.0.0 namespace that call is refused.

Reproduced against the live service exactly as the README instructed:

```
POST /api/role/engineers              -> 200
POST /api/permission/engineers/deploy -> 200
POST /api/membership/alice/engineers  -> 409 {"reason":"user_not_key_backed","result":false}
```

The 409 is **correct** — it is the contract SPEC 0008 specifies and the shape
runflow asked for in 2.5.1. The defect is that the docs never taught the step
that satisfies it, so every brand-new user hit a wall on step 3.

This is the consumer-facing instance of the hazard runflow described on
`thr-00ea026de72c4dcab1d9`: *"any FRESH environment … is therefore strict from
birth. Every membership grant would 409 and RBAC would be dead on arrival, in an
environment nobody would think to check."* They found it in their rebuild path;
the same blind spot existed in our own front door.

## Implementation

Both supported paths are now documented, in `README.md` and in all three
quickstart blocks of `auth/docs_page.py` (landing `/`, `/claude`, and the Python
client section):

1. **Key-first** (default): issue `POST /api/apikeys/user/<user>` before the
   membership grant. The returned secret need not be kept if only the identity
   must exist.
2. **Opt-out** (for consumers whose users can never hold auth keys):
   `PUT /api/settings` with `{"strict_users": false}`, once per namespace.

Each block explains *why* the step exists and that the 409 is a permanent
refusal — not a transport fault — so retrying never helps.

`scripts/smoke_install.sh` now mirrors the documented sequence and asserts
**both directions**: the keyless grant must be refused, and key issuance must
release exactly that block.

## Verification

Endpoint shapes were verified against the **served** API before being written
down, not read off the source. That caught a real error in the first draft:
`/api/settings` is **PUT**, not POST.

Live on fresh namespaces:

- Key-first: role 200 → permission 200 → apikeys 200 → membership `200
  {"result":true}` → has_permission `200 has_permission:true`.
- Opt-out: `PUT /api/settings` `200 {"strict_users":false}` → role/permission/
  membership/has_permission all 200 with **no** key ever issued.

Smoke test passes against the built 3.0.1 wheel. ruff, mypy, 214 unit tests,
15 postgres tests green.
