#!/bin/sh
# Deploy auth on its host, and PROVE the deploy took effect.
#
# Written because the procedure was prose split across MIGRATIONS.md, the
# database runbook and an operator's memory, executed by hand. issuedb #7 was a
# skipped step from exactly that: the editable reinstall that refreshes installed
# metadata was missed, so /docs served 3.0.1 while the code was 3.2.0 for weeks.
# Nothing failed, nothing alerted, and the served artifact disagreed with the
# source. A script cannot forget a step, and this one refuses to claim success
# without checking the result.
#
# DRY RUN BY DEFAULT. Pass --apply to make changes.
#
#   sh scripts/deploy.sh              # show what would happen
#   sh scripts/deploy.sh --apply      # do it, then verify
#
# Exits non-zero if any step fails OR if verification cannot confirm the new
# state. A deploy that cannot be verified is reported as a failure, not a pass.
set -eu

APP=${AUTH_APP_DIR:-/opt/auth/app}
VENV=${AUTH_VENV:-/opt/auth/venv}
SERVICE=${AUTH_SERVICE:-authsvc}
HOSTS=${AUTH_VERIFY_HOSTS:-"auth.rodmena.app auth.rodmena.co.uk"}
CLICK_FLOOR=${AUTH_CLICK_FLOOR:-8.3.3}

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1
run() { if [ "$APPLY" = 1 ]; then echo "+ $*"; "$@"; else echo "  would run: $*"; fi; }

fail() { echo "DEPLOY FAILED: $*" >&2; exit 1; }

[ -x "$VENV/bin/python" ] || fail "no interpreter at $VENV/bin/python -- wrong host?"
[ -d "$APP/.git" ] || fail "no git checkout at $APP"

echo "== auth deploy  ($([ "$APPLY" = 1 ] && echo APPLY || echo 'DRY RUN'))"
echo "   app $APP   venv $VENV   service $SERVICE"

# --- refuse a working-tree deploy -------------------------------------------
# Deploying whatever happens to be checked out is how a host ends up running
# code that exists in no commit. The target is origin/master or nothing.
cd "$APP"
git fetch -q origin
LOCAL=$(git rev-parse HEAD)
TARGET=$(git rev-parse origin/master)
echo "   HEAD      $LOCAL"
echo "   origin/master $TARGET"

DIRTY=$(git status --porcelain | grep -v '^?? ' || true)
if [ -n "$DIRTY" ]; then
    echo "   local modifications present (the host keeps two .gitignore lines):"
    echo "$DIRTY" | sed 's/^/     /'
    run git stash push -q -m "deploy.sh $(date -u +%Y%m%dT%H%M%SZ)"
fi

if [ "$LOCAL" = "$TARGET" ]; then
    echo "   already at origin/master; continuing so the reinstall and checks still run"
else
    run git merge --ff-only origin/master
fi

# --- the step whose omission caused #7 --------------------------------------
# --no-deps deliberately: dependency changes are a separate, reviewed action.
# It is also why click below needs its own explicit install.
run "$VENV/bin/pip" install -q --no-deps -e "$APP"

# --- dependencies the venv must OWN rather than inherit ---------------------
# vm-2's venv has include-system-site-packages=true, so anything not installed
# here resolves from the host's py312-* packages. click reaches us through
# Flask; the host package has been stuck at 8.3.1 since April with
# PYSEC-2026-2132 open, and FreeBSD ports has not moved. Installing it here lets
# the venv shadow the host copy WITHOUT declaring it in pyproject, which would
# narrow every consumer's resolver for a dependency auth does not use directly.
run "$VENV/bin/pip" install -q "click>=$CLICK_FLOOR"

run service "$SERVICE" restart

if [ "$APPLY" = 0 ]; then
    echo
    echo "DRY RUN complete. Nothing changed. Re-run with --apply."
    exit 0
fi

# --- verification: a deploy is not done because the commands exited 0 -------
echo
echo "== verifying"
sleep 5

EXPECTED=$(git rev-parse --short HEAD)
INSTALLED=$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("auth"))')
SOURCE=$(grep -m1 '^version' "$APP/pyproject.toml" | sed 's/.*"\(.*\)".*/\1/')
echo "   commit $EXPECTED   installed metadata $INSTALLED   pyproject $SOURCE"
[ "$INSTALLED" = "$SOURCE" ] || fail "installed metadata $INSTALLED != pyproject $SOURCE (#7: the editable reinstall did not take)"

CLICK=$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("click"))')
CLICK_PATH=$("$VENV/bin/python" -c 'import click, os; print(os.path.dirname(click.__file__))')
echo "   click $CLICK from $CLICK_PATH"
case "$CLICK_PATH" in
    "$VENV"/*) ;;
    *) fail "click resolves from $CLICK_PATH, outside the venv -- the install did not shadow the host copy" ;;
esac

for H in $HOSTS; do
    for EP in health readyz; do
        CODE=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "https://$H/$EP" || echo 000)
        echo "   https://$H/$EP -> $CODE"
        [ "$CODE" = "200" ] || fail "https://$H/$EP returned $CODE"
    done
done

echo
echo "DEPLOY OK: commit $EXPECTED, metadata $INSTALLED, click $CLICK, all endpoints 200"
