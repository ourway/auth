# auth — RBAC authorization service

Authorization (not authentication) over HTTP. Version __VERSION__.
Base URL: `https://auth.rodmena.app`

auth answers one question — *may user X do Y* — so services don't reinvent roles
and permissions. It does **not** log anyone in; it trusts you already know who
the user is. Model: `user` → (member of) → `role` → (holds) → `permission`.

## 30-second quickstart

Your **client key is any UUID4** — it is also your private namespace. Generate
one, keep it secret, reuse it for every call. Roles, users and permissions are
created implicitly, but a role must exist before you add members or permissions
to it.

    KEY=$(python3 -c "import uuid; print(uuid.uuid4())")
    BASE=https://auth.rodmena.app
    curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/role/engineers
    curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/permission/engineers/deploy
    curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/apikeys/user/alice
    curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/membership/alice/engineers
    curl        -H "Authorization: Bearer $KEY" $BASE/api/has_permission/alice/deploy
    # -> {"success": true, "data": {"has_permission": true}, ...}

**Do not drop the `apikeys` line.** A namespace created after 3.0.0 is strict by
default: a user must hold a key in your namespace before it can be given a role,
so without it the membership call answers `409 user_not_key_backed`. If your
users can never hold auth keys, opt the namespace out once instead:
`curl -X PUT -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"
-d '{"strict_users": false}' $BASE/api/settings`.

**The one gotcha to remember:** a write to a missing role returns
`200 {"result": false}`, not a 4xx — check the `result`/`data` field, never just
the status code. The full reference lists three more surprises like it.

**Leaked a key?** `POST /api/keys/rotate` with your current key mints a fresh one
and moves your whole namespace onto it in one shot — capture the returned key, it
is the only copy. See `/docs`.

## Per-user API keys & strict identity

auth also manages **API keys for your end users** (since 2.4). Same
`Authorization: Bearer <your-client-key>` header as every `/api/` call; the
path names the END USER the key is for (methods are uppercase — `-X POST`):

    curl -X POST -H "Authorization: Bearer $KEY" \
         $BASE/api/apikeys/user/alice
    # -> {"data": {"api_key": "rak_<43 chars — shown ONCE, store it>", ...}}

    curl -X POST -H "Authorization: Bearer $KEY" \
         -H "Content-Type: application/json" \
         -d '{"api_key": "rak_..."}' $BASE/api/apikeys/validate
    # -> {"data": {"valid": true, "user": "alice", ...}}

The secret is shown exactly once — only its SHA-256 is stored. Validate AND
check a permission in one round trip with `POST /api/apikeys/check_permission`
(body: `{"api_key": ..., "permission": ...}`). Revoking a key
(`DELETE /api/apikeys/user/alice/<key_id>`) cuts that user's access end to end.

Since **3.0.0, new tenants are strict by default**: authorization decisions
answer only for key-backed users (create the key first, then grant roles — a
key-less grant answers **409** `user_not_key_backed`), and
`PUT /api/settings {"strict_users": false}` is the audited per-tenant opt-out
for platforms that authenticate their own users. Tenants that existed before
3.0.0 were grandfathered with an explicit opt-out row and saw no change. The
Python client raises `AuthTransportError` on transport failure (3.0) — an
outage can never read as a denial. Full detail: `/docs` sections 3–6.

## Guides

| Path | For |
|---|---|
| `/docs` | the full API reference — every endpoint and exact response shape |
| `/llms.txt` | the same reference as Markdown, for LLM ingestion |
| `/claude` | using auth from Claude Code |
| `/opencode` | *(coming soon)* |
| `/codex` | *(coming soon)* |

`/ping` and `/health` need no auth. Everything under `/api/` needs your
`Authorization: Bearer <uuid4>` header.
