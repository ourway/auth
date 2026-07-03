#!/usr/bin/env bash
# Pre-publish smoke test: build the wheel, install it into a fresh venv,
# verify the wheel contents are clean, import the package, and run the
# README quick-start against SQLite.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d /tmp/auth-smoke-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

PYTHON="${PYTHON:-$REPO_DIR/.venv/bin/python}"

echo "==> Building wheel"
"$PYTHON" -m pip install --quiet --upgrade build >/dev/null
"$PYTHON" -m build --wheel --outdir "$WORK_DIR/dist" "$REPO_DIR" >/dev/null
WHEEL="$(ls "$WORK_DIR"/dist/*.whl)"
echo "    $WHEEL"

echo "==> Checking wheel contents are only auth/* + metadata"
BAD_FILES="$("$PYTHON" - "$WHEEL" <<'EOF'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
bad = [n for n in names if not (n.startswith("auth/") or n.startswith("auth-"))]
print("\n".join(bad))
EOF
)"
if [ -n "$BAD_FILES" ]; then
    echo "ERROR: wheel contains unexpected files:" >&2
    echo "$BAD_FILES" >&2
    exit 1
fi

echo "==> Installing into a fresh venv"
"$PYTHON" -m venv "$WORK_DIR/venv"
"$WORK_DIR/venv/bin/pip" install --quiet "$WHEEL"

echo "==> Import + README quick-start on SQLite"
env -i PATH="$PATH" HOME="$WORK_DIR" \
    AUTH_DATABASE_TYPE=sqlite \
    AUTH_SQLITE_PATH="$WORK_DIR/smoke.sqlite3" \
    AUTH_ENABLE_ENCRYPTION=false \
    "$WORK_DIR/venv/bin/python" - <<'EOF'
import uuid

import auth
print(f"    imported auth {auth.__version__}")

from auth import Authorization
from auth.database import create_tables

create_tables(raise_on_error=True)
client = Authorization(str(uuid.uuid4()))
assert client.add_role("admin", description="Administrator role") is True
assert client.add_permission("admin", "manage_users") is True
assert client.add_membership("alice@example.com", "admin") is True
assert client.user_has_permission("alice@example.com", "manage_users") is True
assert client.get_user_roles("alice@example.com") == [
    {"user": "alice@example.com", "role": "admin"}
]
print("    quick-start OK")

from auth.client import EnhancedAuthClient
c = EnhancedAuthClient(api_key=str(uuid.uuid4()), service_url="http://127.0.0.1:1")
c.close()
print("    EnhancedAuthClient constructs on installed urllib3")
EOF

echo "==> SMOKE TEST PASSED"
