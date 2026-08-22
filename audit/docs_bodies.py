"""Hash every documentation page the service serves, in both content types.

The docs pages are large static blobs; moving them between a Python literal and
a package data file is exactly the kind of change that silently mangles a
trailing newline or a brace escape. This fetches each page through the real
Flask stack — as a browser (HTML) and as an agent (Markdown) — and prints a
digest plus the byte length, so a before/after diff catches any drift.
"""

import hashlib
import os
import sys

os.environ.setdefault("AUTH_DATABASE_TYPE", "sqlite")
os.environ.setdefault("AUTH_SQLITE_PATH", ":memory:")
os.environ.setdefault("AUTH_JWT_SECRET_KEY", "docs-bodies-secret-key")
os.environ.setdefault("AUTH_ENABLE_ENCRYPTION", "false")

PAGES = ["/", "/docs", "/llms.txt", "/claude", "/opencode", "/codex"]
ACCEPTS = [
    ("agent", "*/*"),
    ("browser", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
]


def main() -> int:
    from auth.main import app

    out = []
    with app.test_client() as c:
        for path in PAGES:
            for label, accept in ACCEPTS:
                r = c.get(path, headers={"Accept": accept})
                body = r.get_data()
                digest = hashlib.sha256(body).hexdigest()[:32]
                out.append(
                    f"{path:12s} {label:8s} {r.status_code} "
                    f"{r.headers.get('Content-Type', '-'):32s} "
                    f"{len(body):7d}B  {digest}"
                )
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
