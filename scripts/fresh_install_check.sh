#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d /tmp/auth-fresh-XXXXXX)"
PYTHON="${PYTHON:-python3}"
PG_IMAGE="${PG_IMAGE:-postgres:18}"
PG_PORT="${PG_PORT:-55498}"
APP_PORT="${APP_PORT:-4098}"
CONTAINER="auth-fresh-check-$$"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() { echo "FAILED: $*" >&2; exit 1; }

echo "==> PostgreSQL ($PG_IMAGE) with a non-superuser owner role"
docker run -d --name "$CONTAINER" -e POSTGRES_USER=ci -e POSTGRES_PASSWORD=ci \
    -e POSTGRES_DB=postgres -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
    docker exec "$CONTAINER" psql -U ci -d postgres -Atc 'select 1' >/dev/null 2>&1 && break
    sleep 1
done
sleep 2
docker exec "$CONTAINER" psql -U ci -d postgres -v ON_ERROR_STOP=1 -q \
    -c "CREATE ROLE auth LOGIN PASSWORD 'auth' NOSUPERUSER NOBYPASSRLS" \
    -c "CREATE DATABASE auth_ci OWNER auth" \
    -c "CREATE DATABASE auth_noschema OWNER auth"

echo "==> Wheel, installed with the c and migrations extras"
"$PYTHON" -m pip install --quiet --upgrade build >/dev/null
"$PYTHON" -m build --wheel --outdir "$WORK_DIR/dist" "$REPO_DIR" >/dev/null
WHEEL="$(ls "$WORK_DIR"/dist/*.whl)"
"$PYTHON" -m venv "$WORK_DIR/venv"
"$WORK_DIR/venv/bin/pip" install --quiet "${WHEEL}[c,migrations]" gunicorn
cd "$WORK_DIR"

URL="postgresql://auth:auth@127.0.0.1:$PG_PORT/auth_ci"
echo "==> auth-migrate apply, then verify"
env -i PATH="$PATH" HOME="$WORK_DIR" MG_DATABASE_URL="$URL" "$WORK_DIR/venv/bin/auth-migrate" apply --yes
env -i PATH="$PATH" HOME="$WORK_DIR" MG_DATABASE_URL="$URL" "$WORK_DIR/venv/bin/auth-migrate" verify

serve() {
    env -i PATH="$PATH" HOME="$WORK_DIR" \
        AUTH_DATABASE_URL="$1" AUTH_DATABASE_SCHEMA="$2" \
        AUTH_JWT_SECRET_KEY="fresh-check-$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" \
        AUTH_AUDIT_PEPPER="fresh-check-$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" \
        "$WORK_DIR/venv/bin/gunicorn" --bind "127.0.0.1:$APP_PORT" --workers 1 auth.main:app \
        >"$WORK_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 60); do
        curl -s -o /dev/null "http://127.0.0.1:$APP_PORT/health" && return 0
        sleep 0.5
    done
    cat "$WORK_DIR/server.log" >&2
    fail "server did not start"
}

stop() { kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }

echo "==> Without AUTH_DATABASE_SCHEMA the service refuses and names the setting"
serve "postgresql://auth:auth@127.0.0.1:$PG_PORT/auth_noschema" ""
CODE=$(curl -s -o "$WORK_DIR/refusal" -w '%{http_code}' "http://127.0.0.1:$APP_PORT/readyz")
stop
echo "    readyz $CODE"
[ "$CODE" = "503" ] || fail "expected 503 without the schema, got $CODE"
grep -q "AUTH_DATABASE_SCHEMA is 'public'" "$WORK_DIR/refusal" \
    || grep -q "AUTH_DATABASE_SCHEMA is 'public'" "$WORK_DIR/server.log" \
    || fail "the refusal does not name AUTH_DATABASE_SCHEMA"

echo "==> With AUTH_DATABASE_SCHEMA=auth_rbac the service serves"
serve "$URL" auth_rbac
B="http://127.0.0.1:$APP_PORT"
GET=$(curl -s -o /dev/null -w '%{http_code}' "$B/readyz")
HEAD=$(curl -s -o /dev/null -I -w '%{http_code}' "$B/readyz")
echo "    readyz GET $GET HEAD $HEAD"
[ "$GET" = "200" ] && [ "$HEAD" = "200" ] || fail "readyz GET $GET HEAD $HEAD"
KEY=$("$WORK_DIR/venv/bin/python" -c 'import uuid; print(uuid.uuid4())')
OTHER=$("$WORK_DIR/venv/bin/python" -c 'import uuid; print(uuid.uuid4())')
H="Authorization: Bearer $KEY"
curl -sf -X POST -H "$H" "$B/api/role/viewer" | grep -q '"result":true' || fail "create role"
curl -sf -X POST -H "$H" "$B/api/permission/viewer/monitors-view" | grep -q '"result":true' || fail "add permission"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$H" "$B/api/membership/u1/viewer")
[ "$CODE" = "409" ] || fail "strict grant without a key answered $CODE"
curl -sf -X POST -H "$H" "$B/api/apikeys/user/u1" | grep -q '"api_key":"rak_' || fail "create key"
curl -sf -X POST -H "$H" "$B/api/membership/u1/viewer" | grep -q '"result":true' || fail "grant"
curl -sf -H "$H" "$B/api/has_permission/u1/monitors-view" | grep -q '"has_permission":true' || fail "allowed"
curl -sf -H "$H" "$B/api/has_permission/u1/monitors-edit" | grep -q '"has_permission":false' || fail "denied"
curl -sf -H "Authorization: Bearer $OTHER" "$B/api/has_permission/u1/monitors-view" \
    | grep -q '"has_permission":false' || fail "another namespace sees the grant"
stop
echo "    strict 409, key, grant, allow, deny and namespace isolation all as expected"
echo "FRESH INSTALL CHECK PASSED"
