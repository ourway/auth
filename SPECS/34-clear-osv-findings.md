# 34 — Clear every OSV finding (auth 3.3.0)

Ticket: issuedb #34. Requested by the director via infra-manager-c13110 on AgentBus threads 01M3FQ98TRMH8XNC12285088KW and 01M3FQT8396PQKC5RE5Y98572S.

EARS SPEC:
- The auth service shall resolve click >= 8.3.3 from inside /opt/auth/venv on vm-2, as read back by importlib.metadata and click.__file__ under the service interpreter.
- The auth service shall report 0 OSV advisories (any severity) over every distribution its deployed interpreter resolves, measured by audit/evaluations/probe_osv_resolved_set.py with the positive control passing.
- The auth repository shall pin no version carrying an OSV advisory in requirements.txt or uv.lock (0 findings over 100% of pins, per resolution fork), except where no fixed release exists for a supported Python, in which case the residual shall be listed with its reason in SPECS.
- If a lockfile pins a version with a known OSV advisory, then audit/evaluations/probe_osv_lockfiles.py shall exit 1 and name the package, version and advisory ids.
- The auth lockfiles shall not pin packages absent from pyproject's dependency closure (alembic, PyJWT removed).
- When auth 3.2.1 is released, the served /health version on auth.rodmena.app and auth.rodmena.co.uk shall equal 3.2.1 and the PyPI release shall be 3.2.1.
- Where a pinned upgrade crosses a major version, the full unit and postgres test suites shall pass unchanged (0 failures).

TECHNICAL PROBLEMS:
1. Runtime: host-inherited click shadowing (include-system-site-packages) on the deployed interpreter.
2. Supply chain: stale exact-pin lockfiles (Dockerfile consumes requirements.txt) carrying 16 + 9 advisories.
3. Regression detection: nothing fails when a lockfile drifts onto an advisory.
4. Release + deploy verification through served artifacts.

SOLUTION DOMAINS:
- Venv shadowing -> scripts/deploy.sh (already on master, 85d5e1f) installs click>=8.3.3 into the venv; infra agreed on AgentBus thread 01M3FQT8396PQKC5RE5Y98572S.
- Lock regeneration -> uv lock --upgrade (codebase uses uv.lock) and pip freeze of a fresh resolve (requirements.txt header convention).
- Advisory detection -> OSV querybatch (same source infra and probe_osv_resolved_set.py use).

ALTERNATIVES:
- click: venv install from deploy script [CHOSEN] vs pin click>=8.3.3 in pyproject [REJECTED: narrows every consumer's resolver for a transitive dep; infra concurred] vs locally built host pkg [REJECTED: unsigned package breaks CE 4.5 allow-listing answer].
- Lockfiles: regenerate [CHOSEN] vs delete requirements.txt [REJECTED: Dockerfile and docs consume it] vs hand-bump 25 pins [REJECTED: leaves alembic/PyJWT and does not re-resolve transitives].
- Lockfile guard: network OSV check as audit probe [CHOSEN; offline unit suite must not go red on network loss] vs unit test calling OSV [REJECTED: CI flakiness, offline runs red].

SYNTHESIS CHANGE (during implementation):
- After uv lock --upgrade, every residual uv.lock finding was confined to the python<=3.9 forks; no fixed release supports 3.9 (EOL 2025-10) and CI never tested it.
- CHOSEN: requires-python >=3.10, release 3.3.0 (minor, compatibility change).
- REJECTED: keep >=3.9 with 9 documented permanent residuals (lockfile red forever; 3.9 consumers unfixable regardless of auth).
- The lockfile guard is audit/evaluations/probe_osv_lockfiles.py (network; not in run_all.sh safe set, same reason as probe_osv_resolved_set.py).
