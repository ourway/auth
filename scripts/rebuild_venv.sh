#!/bin/sh
#   sh scripts/rebuild_venv.sh              # DRY RUN: print the plan, change nothing
#   sh scripts/rebuild_venv.sh --build      # build and verify a new venv; the live service is untouched
#   sh scripts/rebuild_venv.sh --swap       # point /opt/auth/venv at the newest verified build, restart, verify
#   sh scripts/rebuild_venv.sh --rollback   # point /opt/auth/venv back at the previous venv, restart, verify
set -eu

APP=${AUTH_APP_DIR:-/opt/auth/app}
LINK=${AUTH_VENV:-/opt/auth/venv}
VENVS=${AUTH_VENVS_DIR:-/opt/auth/venvs}
PYTHON=${AUTH_PYTHON:-/usr/local/bin/python3.12}
LOCK=${AUTH_DEPLOY_LOCK:-$APP/deploy/requirements-vm2.txt}
SERVICE=${AUTH_SERVICE:-authsvc}
ENV_FILE=${AUTH_ENV_FILE:-/opt/auth/etc/auth.env}
RUN_AS=${AUTH_RUN_AS:-authsvc}
TRIAL_PORT=${AUTH_TRIAL_PORT:-4001}
EXCLUDED="pillow pyjwt filelock brotli psycopg-binary"

fail() { echo "FAILED: $*" >&2; exit 1; }

check_venv() {
    V=$1
    echo "== checking $V"
    grep -qx 'include-system-site-packages = false' "$V/pyvenv.cfg" \
        || fail "$V/pyvenv.cfg does not say include-system-site-packages = false"
    "$V/bin/python" -m pip check || fail "pip check failed in $V"
    (cd "$APP" && "$V/bin/python" - "$V" "$EXCLUDED") <<'PY' || fail "venv content check failed for $V"
import importlib.metadata as m
import os
import sys

root = os.path.realpath(sys.argv[1])
excluded = set(sys.argv[2].split())
outside, present = [], []
for dist in m.distributions():
    name = dist.metadata["Name"].lower()
    where = os.path.realpath(str(dist.locate_file("")))
    if not where.startswith(root + os.sep):
        outside.append(f"{name} {dist.version} at {where}")
    if name in excluded:
        present.append(name)
for path in sys.path[1:]:
    real = os.path.realpath(path)
    if path and os.path.isdir(real) and "site-packages" in real and not real.startswith(root + os.sep):
        outside.append(f"sys.path entry {real}")

from psycopg import pq
import psycopg_c

impl = pq.__impl__
c_root = os.path.realpath(os.path.dirname(psycopg_c.__file__))
print(f"   distributions {len(list(m.distributions()))}, outside {len(outside)}, excluded present {present}")
print(f"   psycopg {m.version('psycopg')} impl {impl} libpq {pq.version()} psycopg_c at {c_root}")
for line in outside:
    print(f"   OUTSIDE: {line}")
ok = not outside and not present and impl == "c" and c_root.startswith(root + os.sep)
sys.exit(0 if ok else 1)
PY
}

trial_serve() {
    V=$1
    echo "== trial: serving from $V on 127.0.0.1:$TRIAL_PORT"
    LOG=$(mktemp /tmp/auth-trial.XXXXXX)
    chown "$RUN_AS" "$LOG"
    su -m "$RUN_AS" -c "cd '$APP' && exec '$V/bin/python' - '$ENV_FILE' '$V' '$TRIAL_PORT'" >"$LOG" 2>&1 <<'PY' &
import os
import sys

from supervice.config import _parse_env_file

env_file, venv, port = sys.argv[1:4]
os.environ.update(_parse_env_file(env_file))
os.execv(
    f"{venv}/bin/python",
    [
        f"{venv}/bin/python", "-m", "gunicorn",
        "--config", "gunicorn_config.py",
        "--bind", f"127.0.0.1:{port}",
        "--workers", "1",
        "--pid", f"/tmp/auth-trial-{port}.pid",
        "--error-logfile", "-",
        "--access-logfile", "-",
        "auth.main:app",
    ],
)
PY
    TRIAL_PID=$!
    CODE=000
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        sleep 1
        CODE=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$TRIAL_PORT/readyz" || echo 000)
        [ "$CODE" = "200" ] && break
    done
    HEAD_CODE=$(curl -s -o /dev/null -m 5 -I -w '%{http_code}' "http://127.0.0.1:$TRIAL_PORT/health" || echo 000)
    DOCS=$(curl -s -m 5 "http://127.0.0.1:$TRIAL_PORT/llms.txt" | grep -c "$(grep -m1 '^version' "$APP/pyproject.toml" | sed 's/.*"\(.*\)".*/\1/')" || true)
    MASTER=$(cat "/tmp/auth-trial-$TRIAL_PORT.pid" 2>/dev/null || echo "")
    if [ -n "$MASTER" ]; then
        kill "$MASTER" 2>/dev/null || true
    fi
    wait "$TRIAL_PID" 2>/dev/null || true
    echo "   readyz GET $CODE, health HEAD $HEAD_CODE, llms.txt version lines $DOCS"
    if [ "$CODE" != "200" ] || [ "$HEAD_CODE" != "200" ] || [ "$DOCS" = "0" ]; then
        sed 's/^/   | /' "$LOG" | tail -40
        rm -f "$LOG"
        fail "trial server from $V did not serve"
    fi
    rm -f "$LOG"
}

restart_and_verify() {
    service "$SERVICE" restart
    sleep 5
    [ "$(stat -f %Sp /dev/null)" = "crw-rw-rw-" ] || fail "/dev/null is $(stat -f %Sp /dev/null) after restart (#36)"
    sh "$APP/scripts/deploy.sh" --verify-only
}

[ -d "$APP/.git" ] || fail "no git checkout at $APP"
[ -f "$LOCK" ] || fail "no deploy lock at $LOCK"

case "${1:-}" in
    "")
        echo "== DRY RUN"
        echo "   would build $VENVS/<utc-stamp>-$(git -C "$APP" rev-parse --short HEAD) with $PYTHON"
        echo "   from $LOCK ($(grep -c '^[A-Za-z0-9]' "$LOCK") pinned distributions)"
        echo "   current $LINK -> $(readlink "$LINK" || echo "a plain directory")"
        ;;
    --build)
        [ -x "$PYTHON" ] || fail "no interpreter at $PYTHON"
        command -v pg_config >/dev/null || fail "pg_config not on PATH; psycopg-c cannot build against the system libpq"
        mkdir -p "$VENVS"
        NEW="$VENVS/$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$APP" rev-parse --short HEAD)"
        echo "== building $NEW"
        "$PYTHON" -m venv "$NEW"
        "$NEW/bin/python" -m pip install -q --require-hashes --no-deps -r "$LOCK"
        "$NEW/bin/python" -m pip install -q --no-deps --no-build-isolation -e "$APP"
        for STALE in "$APP"/*.egg-info; do
            [ -e "$STALE" ] || continue
            git -C "$APP" check-ignore -q "$STALE" || fail "$STALE is not an ignored build artifact"
            echo "   removing stale build metadata $STALE ($(grep -m1 '^Version' "$STALE/PKG-INFO" 2>/dev/null))"
            rm -rf "$STALE"
        done
        check_venv "$NEW"
        trial_serve "$NEW"
        "$NEW/bin/python" -m pip freeze --all > "$NEW/FREEZE.txt"
        git -C "$APP" rev-parse HEAD > "$NEW/VERIFIED"
        echo "BUILT AND VERIFIED: $NEW"
        ;;
    --swap)
        NEW=$(ls -1d "$VENVS"/[0-9]*/ 2>/dev/null | sed 's:/$::' | sort | tail -1)
        [ -n "$NEW" ] && [ -f "$NEW/VERIFIED" ] || fail "no verified build in $VENVS; run --build first"
        [ "$(cat "$NEW/VERIFIED")" = "$(git -C "$APP" rev-parse HEAD)" ] || fail "$NEW was verified at another commit"
        if [ -L "$LINK" ]; then
            PREV=$(readlink "$LINK")
        else
            [ -d "$LINK" ] || fail "$LINK is neither a symlink nor a directory"
            PREV="$VENVS/legacy-system-site-$(date -u +%Y%m%dT%H%M%SZ)"
            mv "$LINK" "$PREV"
            ln -s "$PREV" "$LINK"
        fi
        [ "$PREV" != "$NEW" ] || fail "$LINK already points at $NEW"
        echo "$PREV" > "$VENVS/PREVIOUS"
        ln -s "$NEW" "$LINK.next"
        mv -h "$LINK.next" "$LINK"
        echo "== $LINK -> $(readlink "$LINK") (previous $PREV)"
        restart_and_verify
        check_venv "$LINK"
        echo "SWAP OK"
        ;;
    --rollback)
        [ -f "$VENVS/PREVIOUS" ] || fail "no $VENVS/PREVIOUS recorded"
        PREV=$(cat "$VENVS/PREVIOUS")
        [ -x "$PREV/bin/python" ] || fail "previous venv $PREV is missing"
        CUR=$(readlink "$LINK")
        ln -s "$PREV" "$LINK.next"
        mv -h "$LINK.next" "$LINK"
        echo "$CUR" > "$VENVS/PREVIOUS"
        echo "== $LINK -> $PREV (rolled back from $CUR)"
        service "$SERVICE" restart
        sleep 5
        for H in ${AUTH_VERIFY_HOSTS:-"auth.rodmena.app auth.rodmena.co.uk"}; do
            curl -fsS -o /dev/null -m 10 "https://$H/readyz" || fail "https://$H/readyz not 200 after rollback"
        done
        echo "ROLLBACK OK"
        ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac
