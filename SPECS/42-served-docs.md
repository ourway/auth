# #42 Served docs: canonical host and corrected examples

issuedb #42. Release 3.6.0.

EARS SPEC:
- The served /llms.txt, /docs, / and /claude shall give https://auth.rodmena.com as the base URL in every example.
- The served docs shall not recommend a permission name that the API rejects. Scoped permissions shall be shown as doc-123-edit.
- The served docs shall state that 400 and 401 from bad headers or names are HTML pages, and that the strict 409 and the per-user API-key errors (400 at the 25-key limit, 404 for an unknown key) are JSON.
- The tenant-settings section shall state that strict_users has been the default for new namespaces since 3.0.0.
- A test shall fail if any served doc names a host other than auth.rodmena.com as the base URL, or contains doc:123:edit.

EVIDENCE (live, 2026-10-27):
- auth.rodmena.com live: TLS CN auth.rodmena.com to 2027-01-25, readyz/health GET+HEAD 200 (infra thread 01M5XTREHNY38X7A6NNF3M6YPP).
- POST /api/permission/docs/doc:123:edit -> 400 text/html "Invalid permission name"; doc-123-edit -> {"result": true}.
- 26th POST /api/apikeys/user/carol -> 400 application/json; 401/400 for bad header/key -> text/html.
- Stale lines: api_reference.md:104, :282, :400; claude_guide.md:72, :83; base URL in api_reference.md:4,43,340, landing.md:4,18, claude_guide.md:20.

TECHNICAL PROBLEMS: 1. Served reference drifted from behaviour. 2. No test guards doc examples against the validators.
SOLUTION DOMAINS: documentation as served artifact; tests asserting doc examples against the name validators (codebase pattern: tests/ already render static_docs).
ALTERNATIVES: fix text only [REJECTED: drifts again] vs fix text plus a test over the served pages [CHOSEN].

## Measured

- tests/test_served_docs_host.py fetches /, /docs, /llms.txt and /claude through the app and asserts auth.rodmena.com is present (the known positive), the retired hosts are absent, doc:123:edit is absent, the shown scoped name passes validate_permission_name and doc:123:edit does not.
