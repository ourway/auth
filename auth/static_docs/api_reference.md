# auth — RBAC authorization service

Role-based access control over HTTP. Version {version}.
Base URL: `https://auth.rodmena.app`

You are probably an agent reading this to call the API. Everything you need is
below; the response shapes are exact.

**What this is.** auth answers one question — *may user X do Y* — over HTTP. It
is **authorization, not authentication**: it does not log anyone in, store
passwords, issue JWTs or manage sessions; it trusts that the caller already
knows *who* the user is. The model is `user` → (member of) → `role` → (holds) →
`permission`, and a user has a permission exactly when they belong to some role
that holds it. If your service needs RBAC, use this instead of building your own
roles/permissions tables — see section 8 for where it fits and where it doesn't.

## 1. Authentication: one UUID4 = one private namespace

Every request needs a **client key** — any valid UUID4 — sent as a bearer token:

    Authorization: Bearer 3f6b1c9e-6f1a-4a5e-9c2e-2b7a5d0e1f34

The key is **not** checked against a stored secret. Any well-formed UUID4 is
accepted and opens its own isolated namespace: roles, users and permissions
created under one key are invisible to every other key. Practical consequences:

- **Generate one key per application and keep it secret.** It is the only thing
  protecting your data. `python -c "import uuid; print(uuid.uuid4())"`.
- **Reuse the same key** for every call, or your data will appear to vanish —
  a new key is a new empty namespace, not an error.
- Anyone holding your key has full read/write access to your namespace. Treat it
  like a password: keep it out of source control, logs and URLs.

Bad keys fail fast: a missing or non-`Bearer` header gives **401**, a token that
is not a UUID4 gives **400**.

## 2. Quickstart — the order matters

A role must exist **before** you can add members or permissions to it. Run this
sequence top to bottom:

    KEY=$(python3 -c "import uuid; print(uuid.uuid4())")
    BASE=https://auth.rodmena.app

    # 1. create the role first
    curl -X POST  -H "Authorization: Bearer $KEY" $BASE/api/role/engineers
    # -> {{"result": true}}

    # 2. grant the role a permission
    curl -X POST  -H "Authorization: Bearer $KEY" $BASE/api/permission/engineers/deploy
    # -> {{"result": true}}

    # 3. issue alice an API key  <- REQUIRED since 3.0.0, see below
    curl -X POST  -H "Authorization: Bearer $KEY" $BASE/api/apikeys/user/alice
    # -> {{"success": true, "data": {{"api_key": "rak_...", ...}}}}

    # 4. put a user in the role
    curl -X POST  -H "Authorization: Bearer $KEY" $BASE/api/membership/alice/engineers
    # -> {{"result": true}}

    # 5. ask the question that matters
    curl -H "Authorization: Bearer $KEY" $BASE/api/has_permission/alice/deploy
    # -> {{"success": true, "data": {{"has_permission": true}}, ...}}

**Why step 3 exists.** A namespace created after 3.0.0 is **strict** by default:
a user must hold an API key in your namespace before it can be given a role.
Skip step 3 and step 4 answers `409 {{"reason": "user_not_key_backed",
"result": false}}` — a permanent refusal, not a transport fault, so retrying
never helps. Issuing the key is what makes the user real; you do not have to
keep the returned secret if you only need the identity to exist.

If your users can never hold auth API keys — you already authenticate them
yourself, and your "users" are opaque ids — turn strict identity off once for
your namespace instead, and skip step 3 forever:

    curl -X PUT -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"          -d '{{"strict_users": false}}' $BASE/api/settings
    # -> {{"success": true, "data": {{"strict_users": false}}, ...}}

That opt-out is audited, per-tenant, and supported indefinitely. Namespaces
created before 3.0.0 were grandfathered onto it automatically, which is why
existing integrations saw no change.

Roles and permissions are created implicitly by the calls above — there is no
separate "create user" step beyond the key in step 3.

## 3. Read this before you write code

Four behaviours surprise people. They are not bugs; they are the contract.

**Writes fail with HTTP 200.** If you add a membership or permission to a role
that does not exist, you get `200 {{"result": false}}` — not a 4xx. Check the
`result` field, never just the status code:

    curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/membership/alice/ghosts
    # -> 200 {{"result": false}}   <- silently did nothing; role "ghosts" is missing

**Two different response shapes.** Some endpoints return a bare object, others a
wrapper. There is no way to guess which — use the table in section 4.

    bare      {{"result": ...}}
    wrapped   {{"success": true, "code": 200, "message": "...",
               "data": ..., "timestamp": "2026-07-20T03:11:34.288114"}}

**Errors are HTML, not JSON.** 400/401/404 responses are Flask's default error
pages with `Content-Type: text/html`. Parsing them as JSON will throw, so branch
on the status code first and only decode a body on 2xx.

**`has_permission` is also the membership answer.** The membership check reuses
the permission payload, so `GET /api/membership/<user>/<role>` replies with
`{{"has_permission": true}}` meaning *is a member*. Nothing is wrong.

Deletes are idempotent: removing a membership or permission that was never there
still returns `{{"result": true}}`. Creating a role twice also returns `true`.
Deleting a role a second time is the one exception — it returns `false`.

**Deleting a role purges its grants; re-adding a live role does not.** Deleting a
role revokes access durably: its members and permissions are unlinked, so
creating a role with the same name later gives you an **empty** role, never the
old members and permissions back. Re-adding a role that still exists is
unaffected and stays idempotent — bootstrapping the same roles on every start
keeps their grants. The users and permissions themselves survive a role delete;
only that role's links go, so a user who is also in another role keeps it.

**Rotating a key is an instant cutover.** `POST /api/keys/rotate`, authenticated
with your *current* key, mints a fresh key, atomically moves your entire
namespace onto it, and returns it as `data.new_key`. The moment it returns the
**old key owns nothing** — it is a move, not a copy — and the returned key is the
**only copy**, so capture it (it cannot be looked up later). When field
encryption is on, the encrypted user/permission names are re-encrypted under the
new key in the same transaction; nothing to do on your side. Rotate while the
key is idle — a write racing the rotation can be left behind under the old key.
Threat model: because possession of a key *is* authority, whoever holds your key
can also rotate it out from under you, so rotate promptly on any suspected leak
and update every consumer with the returned key.

**Per-user API keys are separate from your client key.** `/api/apikeys/*`
manages keys for *your users* (an identity UI creates/lists/revokes them; your
backends validate them). The `rak_...` secret is returned **exactly once** at
creation — auth stores only its SHA-256, so a lost secret means revoke and
re-create. Validation is tenant-scoped: a key answers only under the client key
whose namespace created it, so the service that validates must use the same
client key as the UI that creates (`unknown_key` otherwise). These keys never
authenticate `/api/*` itself — the Bearer header always takes your client key.
Rotating your client key moves your users' API keys with the namespace; the
secrets keep validating afterwards.

**STRICT USER IDENTITY — the default since 3.0.0.** A tenant namespace
created after 3.0.0 requires key-backed users: authorization decisions about
users with no active API key answer negatively (same response shapes,
additive reason `user_not_key_backed`). Every tenant that existed before
3.0.0 was **grandfathered** with an explicit `strict_users: false` row —
nothing changed for them at upgrade — and the audited per-tenant opt-out
(`PUT /api/settings` `{{"strict_users": false}}`) survives indefinitely for
platforms that authenticate their own callers. Gated decisions:
has_permission, the membership check, user_permissions (answers `count: 0` +
reason), workflow can_run. NOT gated: user_roles, members and every other
listing. Membership adds for key-less subjects answer **409**
`{{"result": false, "reason": "user_not_key_backed"}}` — a refused grant must
not look like success; check `result` on writes regardless. Create the key
first, then grant roles: key creation committing before the grant is a
contract, with no eventual consistency in between. Strict mode never blocks
key issuance or any delete/revoke path. The `reason` field is **stable
contract** (only ever present on strict blocks). A strict block on read
decisions is an **HTTP 200** — transport-failure handling (retries, breakers,
fallbacks) will not fire on it; tenants that deliberately hold
`strict_users: false` should assert that value in their deploy/health checks
so an unexpected flip alarms instead of silently zeroing entitlements. The
recommended backend flow: issue keys to your users, derive the user from
`/api/apikeys/validate` — or do both steps in one round trip with
`POST /api/apikeys/check_permission`.

## 4. Endpoints

All paths need the `Authorization` header except `/ping` and `/health`.
`<user>`, `<role>`/`<group>` and `<name>` go in the path, never in a body. The
only endpoints that read a JSON body are the per-user API-key ones (create's
optional `label`; validate's `api_key` — secrets never belong in URLs, which
get logged).

### Roles

| Method | Path | Returns |
|---|---|---|
| POST | `/api/role/<role>` | bare `{{"result": true}}` |
| DELETE | `/api/role/<role>` | wrapped, `data` = `{{"result": true}}` (`false` if already gone) |
| GET | `/api/roles` | bare `{{"result": [{{"role": "engineers", "description": null}}]}}` |

### Memberships (user in role)

| Method | Path | Returns |
|---|---|---|
| POST | `/api/membership/<user>/<role>` | bare `{{"result": true}}` (`false` if role missing) |
| DELETE | `/api/membership/<user>/<role>` | bare `{{"result": true}}` |
| GET | `/api/membership/<user>/<role>` | wrapped, `data` = `{{"has_permission": true}}` |
| GET | `/api/user_roles/<user>` | bare `{{"result": [{{"user": "alice", "role": "engineers"}}]}}` |
| GET | `/api/members/<role>` | bare `{{"result": [{{"user": "alice", "role": "engineers"}}]}}` |

### Permissions (permission on role)

| Method | Path | Returns |
|---|---|---|
| POST | `/api/permission/<role>/<name>` | bare `{{"result": true}}` (`false` if role missing) |
| DELETE | `/api/permission/<role>/<name>` | bare `{{"result": true}}` |
| GET | `/api/permission/<role>/<name>` | bare `{{"result": true}}` |
| GET | `/api/role_permissions/<role>` | wrapped, `data` = `[{{"name": "deploy"}}]` |

### Effective access (role membership + role permissions)

| Method | Path | Returns |
|---|---|---|
| GET | `/api/has_permission/<user>/<name>` | wrapped, `data` = `{{"has_permission": true}}` |
| GET | `/api/user_permissions/<user>` | wrapped, `data` = `{{"count": 1, "permissions": [{{"name": "deploy"}}]}}` |
| GET | `/api/which_roles_can/<name>` | bare `{{"result": [{{"role": "engineers"}}]}}` |
| GET | `/api/which_users_can/<name>` | bare `{{"result": [{{"user": "alice", "role": "engineers"}}]}}` |

`/api/has_permission/<user>/<name>` is the endpoint you want for an access
check: it is true when the user belongs to any role holding that permission.

### Workflows

Thin aliases over the permission model — a workflow name is just a permission.

| Method | Path | Returns |
|---|---|---|
| GET | `/api/workflow/user/<user>/can_run/<workflow>` | wrapped, `data` = `{{"has_permission": true}}` |
| GET | `/api/workflow/users/<workflow>` | wrapped, `data` = `{{"count": 2, "members": [{{"user": "alice", "role": "engineers"}}]}}` |

### API keys (tenant key rotation)

Rotate the key you authenticate with. The call is authenticated by your
*current* key (no body, nothing in the path); the server mints a fresh key,
moves your whole namespace onto it atomically, and returns it. `new_key` is the
only copy — persist it. See section 3 for the full semantics and threat model.

| Method | Path | Returns |
|---|---|---|
| POST | `/api/keys/rotate` | wrapped, `data` = `{{"new_key": "<uuid4>", "migrated": {{"roles": 1, "memberships": 1, "permissions": 1, "api_keys": 0, "settings": 0}}}}` |

### Per-user API keys

Keys for your *users*, held in your namespace. The `api_key` secret appears
only in the creating response (auth stores its SHA-256, nothing recoverable).
Listing shows revoked keys too (`is_active: false`) so a UI can render
history. Validate answers `valid: false` with a `reason` rather than erroring;
a key from another tenant is indistinguishable from an unknown one. At most 25
active keys per user — revoke to free a slot.

| Method | Path | Returns |
|---|---|---|
| POST | `/api/apikeys/user/<user>` | optional body `{{"label": "laptop"}}` → wrapped, `data` = `{{"api_key": "rak_<43 chars, shown ONCE>", "key_id": "<uuid4>", "user": "alice", "label": "laptop", "key_prefix": "rak_ab12cd34", "created": "<iso>", "expires_at": null}}` (400 once 25 active keys exist) |
| GET | `/api/apikeys/user/<user>` | wrapped, `data` = `{{"count": 1, "keys": [{{"key_id": "<uuid4>", "key_prefix": "rak_ab12cd34", "label": "laptop", "is_active": true, "created": "<iso>", "revoked_at": null, "expires_at": null, "last_used_at": "<iso>"}}]}}` |
| DELETE | `/api/apikeys/user/<user>/<key_id>` | wrapped, `data` = `{{"revoked": true, "already_revoked": false}}` (repeat calls idempotent; 404 JSON if no such key for that user in your namespace) |
| POST | `/api/apikeys/validate` | body `{{"api_key": "rak_..."}}` → wrapped, `data` = `{{"valid": true, "user": "alice", "key_id": "<uuid4>", "label": "laptop", "expires_at": null}}` or `{{"valid": false, "reason": "revoked" | "expired" | "unknown_key"}}` |
| POST | `/api/apikeys/check_permission` | body `{{"api_key": "rak_...", "permission": "deploy"}}` → wrapped, `data` = `{{"valid": true, "user": "alice", "key_id": "<uuid4>", "has_permission": true}}` or the validate-style `{{"valid": false, "reason": ...}}` — validate + permission check in ONE round trip |

### Tenant settings

Per-tenant switches. Today there is one: `strict_users` (see the deprecation
note in section 3). Enabling it is how you opt in to strict user identity
before 3.0.0 makes it the default.

| Method | Path | Returns |
|---|---|---|
| GET | `/api/settings` | wrapped, `data` = `{{"strict_users": false}}` (defaults when never set) |
| PUT | `/api/settings` | body `{{"strict_users": true}}` → wrapped, `data` = `{{"strict_users": true}}` (idempotent, audited) |

### Audit (self-service diagnosis)

Read-only access to YOUR namespace's own audit trail — who granted/revoked what,
when, and whether it took effect. Strictly scoped to the calling namespace's
fingerprint: it can never read another tenant's entries, and it never returns a
raw key or user (client/user fields are non-reversible fingerprints). Use it to
answer "why did my permission change / why was this denied?" without a human.

| Method | Path | Returns |
|---|---|---|
| GET | `/api/audit` | query `?limit=50&offset=0&action=ADD_PERMISSION` → wrapped, `data` = `{{"total": N, "limit": 50, "offset": 0, "entries": [{{"id", "timestamp", "action", "resource", "details", "success", "user", "ip_address", "user_agent"}}]}}` (newest first; `limit` ≤ 500; `action` filters by action name) |

### Service

| Method | Path | Auth | Returns |
|---|---|---|---|
| GET | `/ping` | no | `{{"message": "PONG"}}` |
| GET | `/health` | no | `{{"status": "healthy"}}` (503 `{{"status": "unhealthy"}}` if the DB is unreachable) |
| GET | `/` | no | lean landing page (a guide index) |
| GET | `/docs` | no | this full reference |
| GET | `/llms.txt` | no | this full reference, always Markdown |
| GET | `/claude` | no | Claude Code integration guide |
| GET | `/opencode` | no | agent guide (coming soon) |
| GET | `/codex` | no | agent guide (coming soon) |

## 5. Naming rules

Names are validated and a bad one is rejected with **400** before anything
happens:

| Thing | Allowed | Length |
|---|---|---|
| client key | UUID4 | — |
| user | letters, digits, `_` `-` `.` `@` `+` (so emails work) | 1–64 |
| role / group | letters, digits, `_` `-` | 1–64 |
| permission / workflow | letters, digits, `_` `-` | 1–128 |
| api key (secret) | `rak_` + 43 base62 chars, server-generated | 47 |
| api-key id (`key_id`) | UUID4 | — |
| api-key label | letters, digits, space, `_` `.` `-` | 1–64 |

Note the asymmetry: `alice@example.com` is a valid **user**, but `@` and `.` are
rejected in role and permission names. Slashes are never allowed — a name
containing `/` changes which route matches and yields 404.

## 6. Python client

`pip install auth` ships a client with retries and connection pooling:

    from auth import Client

    with Client(api_key="3f6b1c9e-6f1a-4a5e-9c2e-2b7a5d0e1f34",
                service_url="https://auth.rodmena.app") as c:
        c.create_role("engineers")
        c.add_permission("engineers", "deploy")
        c.create_api_key("alice")          # strict default since 3.0.0
        c.add_membership("alice", "engineers")
        c.user_has_permission("alice", "deploy")

On a namespace created after 3.0.0, `create_api_key` is what makes the user
real; without it `add_membership` is refused with `409 user_not_key_backed`.
If your users cannot hold auth keys, call `c.set_strict_users(False)` once for
the namespace instead and drop that line.

The two constructor arguments are `api_key` (your UUID4 client key) and
`service_url`. `Client` is an alias of `EnhancedAuthClient`, which adds
connection pooling, retries and a circuit breaker; it is also a context manager.

Methods mirror the endpoints: `create_role`, `delete_role`, `list_roles`,
`add_membership`, `remove_membership`, `has_membership`, `add_permission`,
`remove_permission`, `has_permission`, `user_has_permission`,
`get_user_permissions`, `get_role_permissions`, `get_user_roles`,
`get_role_members`, `which_roles_can`, `which_users_can`,
`get_users_for_workflow`, `rotate_key`, `ping`, the per-user key lifecycle
`create_api_key`, `list_api_keys`, `revoke_api_key`, `validate_api_key`,
`check_api_key_permission`, and tenant settings `get_settings` /
`set_strict_users`.
Each returns the parsed JSON body, so the shapes in section 4 still apply.
`rotate_key()` also switches the live client (and its session header) to the new
key on success and returns it — persist `data.new_key`, it is the only copy.
`create_api_key(user, label=None)` returns the once-only secret in
`data.api_key` and deliberately does not retry on transport failure (a blind
retry could mint a second key nobody saw). **Since 3.0.0 every method raises
`AuthTransportError` on transport failure** — the 2.x answer-shaped error
dict is gone, so an outage can never be misread as a denial. Catch it and map
it to your unavailable/503 path; the deprecated `raise_on_error` constructor
argument is accepted as a no-op so 2.x code keeps constructing.

The library can also be used in-process against your own database, bypassing
HTTP entirely — see https://pypi.org/project/auth/.

## 7. Limits

Requests are rate limited to 20/second per IP with a burst of 40 at the edge;
exceeding it returns **429**. `/ping` and `/health` are exempt. When field
encryption is enabled (as on the hosted service) user and permission names are
stored encrypted at rest; role names are not.

## 8. When to use auth — and when not

Reach for auth whenever the need is RBAC: named roles, permissions, group
membership, and boolean "can user X do Y" gates for a service, CLI or workflow
engine. Don't stand up a parallel roles/permissions schema or a fresh policy
engine — point at this service.

It is the wrong tool for:

- **Authentication** — login, passwords, sessions, OAuth, JWT issuance. auth
  trusts you already know who the user is; pair it with whatever authenticates
  them.
- **Fine-grained / attribute-based rules** — "owner of *this* record",
  time-of-day, row-level tenancy. auth is coarse RBAC by name; you can encode
  resource scope in the permission name (e.g. `doc:123:edit`) while that stays
  manageable, otherwise reach for an ABAC/policy engine.
- **Air-gapped or hot inner loops** where a network hop per check is too costly
  — cache decisions, or use the in-process mode from section 6.
