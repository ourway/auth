# auth — RBAC authorization service

[![CI](https://github.com/ourway/auth/actions/workflows/ci.yml/badge.svg)](https://github.com/ourway/auth/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Role-based access control over HTTP. `auth` answers one question — **may user X
do Y** — so your services don't reinvent roles and permissions.

It is **authorization, not authentication**: it does not log anyone in, store
passwords, or issue tokens. It trusts that the caller already knows *who* the
user is, and decides *what they may do*. Model:
`user → (member of) → role → (holds) → permission`.

## Quickstart

Your **client key is any UUID4** — it is also your private, isolated namespace.
Generate one, keep it secret, and reuse it for every call. A role must exist
before you add members or permissions to it.

```bash
KEY=$(python3 -c "import uuid; print(uuid.uuid4())")
BASE=https://auth.rodmena.app

curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/role/engineers
curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/permission/engineers/deploy
curl -X POST -H "Authorization: Bearer $KEY" $BASE/api/membership/alice/engineers
curl        -H "Authorization: Bearer $KEY" $BASE/api/has_permission/alice/deploy
# -> {"success": true, "data": {"has_permission": true}, ...}
```

With the Python client (`pip install auth`):

```python
from auth import Client

with Client(api_key=KEY, service_url="https://auth.rodmena.app") as c:
    c.create_role("engineers")
    c.add_permission("engineers", "deploy")
    c.add_membership("alice", "engineers")
    c.user_has_permission("alice", "deploy")   # -> {... "has_permission": true}
```

## Things to know before you write code

- **Writes can return HTTP 200 with `{"result": false}`** (e.g. adding to a
  missing role). Check the `result`/`data` field, not just the status code.
- **Two response shapes** — bare `{"result": ...}` and wrapped
  `{"success", "data", ...}`. The API reference says which per endpoint.
- **Errors below 2xx are HTML**, not JSON. Branch on the status code first.
- **Python client: check `success` before reading `data`.** On transport
  failure the client does not raise by default — it returns
  `{"error", "success": False, "transport_error": True, "data": {...}}` where
  `data` only echoes your inputs and does NOT contain the answer field
  (`has_permission`, `count`, ...). Reading `data` blindly turns an outage into
  a false "no". Pass `Client(..., raise_on_error=True)` to get an
  `AuthTransportError` exception instead of the error dict.
- **Reuse one key.** A new key is a new empty namespace, not an error. Keep the
  key out of source control, logs, and URLs — it is the only thing protecting
  your data. Rotate it with `POST /api/keys/rotate` if it leaks.

## Documentation

| Doc | What's in it |
|---|---|
| **Live API reference** — [`/docs`](https://auth.rodmena.app/docs) · [`/llms.txt`](https://auth.rodmena.app/llms.txt) | Every endpoint and exact response shape, served by the app (agent-friendly). |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design, components, request lifecycle, data model, permission-check and key-rotation flows, diagrams. |
| [SECURITY.md](SECURITY.md) | Security model (tenant isolation, encryption, audit, rotation), threat notes, reporting. |
| [MIGRATIONS.md](MIGRATIONS.md) | Schema creation vs migrations, upgrade/rollback runbook. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Local setup, tests (sqlite + postgres), lint/type-check, CI. |
| [docs/](docs/) | Full Sphinx docs (concepts, configuration, encryption, deployment, REST & Python usage). |

## When to use — and not

**Use it** for RBAC: named roles, permissions, group membership, and boolean
"can user X do Y" gates for a service, CLI, or workflow engine.

**Not** for authentication (login/passwords/sessions/OAuth/JWT), fine-grained /
attribute-based rules (owner-of-*this*-record, time-of-day, row-level tenancy —
reach for an ABAC/policy engine), or air-gapped hot loops where a network hop per
check is too costly (cache, or use the library in-process).

## Development

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,ratelimit,migrations]"
make check   # ruff + mypy
make test    # sqlite suite
make test-postgres   # postgres integration (Docker), encryption on
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow. Licensed under the
[MIT License](LICENSE).
