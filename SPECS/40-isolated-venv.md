# 40 — isolated vm-2 venv, fixed dependency versions, lazy client import (3.5.2)

issuedb #40. Related: #23, #39. Infra thread 01M5R230A5WJFK8EEGD41D3V51.

EARS SPEC:
- The auth deployment on vm-2 shall run from a virtualenv with include-system-site-packages = false.
- When deploy.sh rebuilds the venv, it shall install every distribution from a hash-pinned lock exported from uv.lock, and shall refuse to swap venvs if any installed distribution resolves outside the new venv.
- When deploy.sh rebuilds the venv, it shall refuse to swap unless psycopg reports pq.__impl__ == 'c' linked against the system libpq.
- When the swap completes and the health checks fail, the operator shall be able to restore the previous venv with one command (venv.prev kept).
- The deploy lock shall pin werkzeug >= 3.1.9, certifi >= 2026.10.19, urllib3 >= 2.8.0 and setuptools >= 84.1.0, and shall contain no pillow, pyjwt, filelock or brotli.
- When the server process imports auth and auth.main, it shall not import requests, urllib3 or brotli.
- When a consumer runs 'from auth import Client' (or AuthRefused, AuthTransportError, EnhancedAuthClient, or from auth.core), it shall receive the same objects as auth.client exports.
- auth shall accept python-json-logger >= 3.1.0, < 5.
- After the cut-over, the live apikeys probe shall pass every check against auth.rodmena.app, and /health and /readyz shall answer 200 on GET and HEAD on both hostnames.
- Quantified: one production restart; old venv retained; zero distributions outside /opt/auth/venv in the deployed process (procstat on every gunicorn process).

TECHNICAL PROBLEMS:
1. Reproducible, host-independent dependency resolution for a FreeBSD deployment (no PyPI wheels for C/Rust extensions).
2. Atomic replacement of a runtime environment with rollback.
3. Import-graph hygiene: the server process loads the HTTP client stack only because the package root imports it eagerly.
4. Declared range for python-json-logger excludes the version production ran.

SOLUTION DOMAINS:
- Lock: uv.lock is already the CI lock (codebase pattern); uv export emits a hash-pinned requirements file pip verifies with --require-hashes (pip manual, secure installs).
- Native builds: psycopg[c] against system libpq per house rule (memory never-bundled-libpq); cryptography/pydantic-core via vm-2's rustc 1.99.1.
- Swap: blue/green directory swap with retained previous (standard release pattern); supervice restart is the only interruption.
- Lazy attribute import: PEP 562 module __getattr__.

ALTERNATIVES:
- Lock source: uv export from uv.lock [CHOSEN: same versions CI tests] vs pip freeze on vm-2 after a free resolve [REJECTED: resolves versions CI never tested, no hashes] vs requirements.txt (dev freeze) [REJECTED: includes dev tools, no hashes, py3.11 resolve].
- Build location: compile on vm-2 in place [CHOSEN: toolchain present, no dependency on infra #157 which does not exist yet] vs infra wheelhouse [REJECTED for now: not built; supply-chain trust change for the director].
- Lazy import: PEP 562 __getattr__ [CHOSEN: keeps 'from auth import Client' and __all__] vs removing the re-export [REJECTED: breaks every consumer using from auth import Client] vs server importing a separate entry package [REJECTED: auth.main is a submodule, so the package root always runs].
- Swap: directory rename with venv.prev [CHOSEN: rollback is one rename + restart] vs in-place pip upgrade into the live venv [REJECTED: no rollback, live process sees half-installed tree].

Related: #23 (isolation), #39 (probe), infra thread 01M5R230A5WJFK8EEGD41D3V51 (director's order relayed 2026-10-24 22:55Z, target 2026-10-25).

## Measured during build

- vm-2 trial build of deploy/requirements-vm2.txt into /tmp, 2026-10-25: pip --require-hashes exit 0 in 2 min 46 s; pip check clean; psycopg 3.3.6 impl c, libpq 180006; distributions outside the venv: none; cryptography 50.0.1 and pydantic-core 2.46.5 compiled with rustc 1.99.1.
- Mutants caught: eager client import (footprint test), pillow added to lock, werkzeug 3.1.8, certifi without hashes (lock tests).
