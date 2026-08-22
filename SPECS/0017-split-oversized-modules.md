# SPEC 0017 — Split four oversized modules below the 500-line cap

- **Ticket:** issuedb #3
- **Status:** closed — merged as bb4e29b and deployed to vm2 on 2026-08-22
- **Tags:** refactor

## Context

Four source files exceed the house hard cap of 550 lines:

| Lines | File |
|------:|------|
| 977 | `auth/services/service.py` |
| 806 | `auth/routes.py` |
| 701 | `auth/docs_page.py` |
| 640 | `auth/client.py` |

The split is behaviour-preserving: no route, response, or public symbol changes.

## EARS requirements

- The auth codebase shall keep every source file at or below 500 lines.
- The auth package shall expose, after the split, the same public API it exposed
  before it: `auth.Authorization`, `auth.Client`, `auth.EnhancedAuthClient`,
  `auth.AuthTransportError`, `auth.SessionLocal`,
  `auth.services.service.AuthorizationService`,
  `auth.services.service.API_KEYS_PER_USER_CAP`, `auth.routes.register_routes`
  and `auth.docs_page.register_docs_routes`.
- When a consumer imports a symbol from a **public** module path it lived in
  before the split (`auth`, `auth.client`, `auth.services.service`,
  `auth.docs_page`), the auth package shall resolve that import to the same
  object as before the split.
- Where a module is internal wiring rather than a public import path
  (`auth.routes`), the auth package shall preserve only its documented entry
  point, `register_routes`.
- If a symbol has moved to a sibling module, then the auth package shall NOT
  re-export it from the module that a `monkeypatch.setattr` would target,
  because a re-export makes the patch silently ineffective instead of raising.
- The auth service shall serve every HTTP route with the same path, method,
  status codes and response body as before the split.
- If a source file would grow past 500 lines, then the contributor shall split it
  rather than extend it.
- While the split is in progress, the auth build shall keep the test suite, ruff
  and mypy passing with no change to the assertions.
- Where a module is composed only of documentation blobs, the auth package shall
  store those blobs as package data files rather than as Python source.

## Accepted deviations

`auth.routes` no longer re-exports the ~30 names it happened to import at module
scope (`engine`, `AuthorizationService`, `get_settings`, the `validate_*`
helpers, Flask's `request`/`g`/`jsonify`, …). These were incidental imports of an
internal module, never its API: nothing outside `auth/main.py` imports anything
from `auth.routes` but `register_routes`, and no documentation references them.

`engine` in particular is deliberately **not** re-exported from
`auth/routes/__init__.py`. `/health` now resolves it in `auth.routes.public`, so
a re-export would let `monkeypatch.setattr("auth.routes.engine", ...)` appear to
succeed while patching an object the handler never reads — a test that silently
stops testing anything. The `AttributeError` is the correct, loud failure; the
one in-repo caller (`tests/test_routes_errors.py`) was re-pointed at
`auth.routes.public.engine`, with its assertions unchanged.

The public paths lost nothing auth-owned: `auth.services.service` and
`auth.client` re-export every model, helper and symbol they previously exposed;
only stdlib and third-party incidentals (`json`, `uuid`, `Retry`, `Session`, …)
are gone from them.

## Verification

- `pytest` — baseline 219 passed / 6 skipped must be matched exactly.
- `ruff check .` and `mypy .` clean.
- Route inventory (path, method) diffed before/after against the live Flask app.
- Public-symbol identity diffed before/after via `audit/surface_snapshot.py`,
  which is proven non-vacuous: deterministic across repeated runs, and shown to
  go red on a one-character route rename before being trusted.
- Served documentation bytes diffed before/after via `audit/docs_bodies.py`,
  proven to detect a single added space, and additionally compared between the
  source tree and a wheel installed into a fresh venv.
- `wc -l` over every tracked `.py` file: no file above 500.
