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
#   sh scripts/deploy.sh               # DRY RUN: print the plan, change nothing
#   sh scripts/deploy.sh --verify-only # check the CURRENT deployment only
#   sh scripts/deploy.sh --apply       # deploy, then verify
#
# --verify-only exists so that rehearsing the checks never requires --apply.
# It was added after --apply was used against production to exercise a failure
# mode, which advanced the checkout before aborting. A gate that cannot be
# rehearsed safely invites precisely that.
#
# Exits non-zero if any step fails OR if verification cannot confirm the new
# state. A deploy that cannot be verified is a failure, not a pass.
set -eu

APP=${AUTH_APP_DIR:-/opt/auth/app}
VENV=${AUTH_VENV:-/opt/auth/venv}
SERVICE=${AUTH_SERVICE:-authsvc}
HOSTS=${AUTH_VERIFY_HOSTS:-"auth.rodmena.app auth.rodmena.co.uk"}

# Packages the venv must OWN rather than inherit from the host's py312-* set,
# with the floor each must meet. Space separated, "name>=version".
#
#   click       reaches us through Flask. The host package sat at 8.3.1 with
#               PYSEC-2026-2132 open while FreeBSD ports did not move for five
#               months. requirements.txt now pins 8.5.0; this floor is the
#               backstop if a venv is rebuilt without it.
#   setuptools  the host's is 63.1.0 (CVE-2024-6345, CVE-2025-47273, both HIGH).
#               84.0.0 was hand-installed into this venv by infra on 2026-09-16
#               and declared NOWHERE: not pyproject, not requirements.txt, not
#               uv.lock. ledger lost exactly this to a venv rebuild and silently
#               fell back to 63.1.0. Declared here so a clean deploy cannot.
VENV_OWNED=${AUTH_VENV_OWNED:-"click>=8.3.3 setuptools>=84.0.0"}

APPLY=0
VERIFY_ONLY=0
case "${1:-}" in
    --apply)       APPLY=1 ;;
    --verify-only) VERIFY_ONLY=1 ;;
    "")            ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

run() { if [ "$APPLY" = 1 ]; then echo "+ $*"; "$@"; else echo "  would run: $*"; fi; }
fail() { echo "FAILED: $*" >&2; exit 1; }

verify() {
    echo "== verifying the deployment as it stands"
    cd "$APP"

    INSTALLED=$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("auth"))')
    SOURCE=$(grep -m1 '^version' "$APP/pyproject.toml" | sed 's/.*"\(.*\)".*/\1/')
    echo "   checkout $(git rev-parse --short HEAD)   installed metadata $INSTALLED   pyproject $SOURCE"
    [ "$INSTALLED" = "$SOURCE" ] || fail "installed metadata $INSTALLED != pyproject $SOURCE (#7: the editable reinstall did not take)"

    # Both halves for each package, because either alone passes while a finding
    # stands: the venv can own a copy that is still vulnerable, and a fixed
    # version can be the host's.
    for SPEC in $VENV_OWNED; do
        NAME=$(echo "$SPEC" | sed 's/>=.*//')
        FLOOR=$(echo "$SPEC" | sed 's/.*>=//')
        GOT=$("$VENV/bin/python" -c "import importlib.metadata as m; print(m.version('$NAME'))") \
            || fail "$NAME is not installed"
        WHERE=$("$VENV/bin/python" -c "import $NAME, os; print(os.path.dirname($NAME.__file__))")
        echo "   $NAME $GOT from $WHERE"
        case "$WHERE" in
            "$VENV"/*) ;;
            *) fail "$NAME resolves from $WHERE, outside the venv -- it is inheriting the host copy" ;;
        esac
        "$VENV/bin/python" - "$GOT" "$FLOOR" <<'PY' || fail "$NAME $GOT is below the required floor $FLOOR"
import sys
from packaging.version import Version
sys.exit(0 if Version(sys.argv[1]) >= Version(sys.argv[2]) else 1)
PY
    done

    for H in $HOSTS; do
        for EP in health readyz; do
            CODE=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "https://$H/$EP" || echo 000)
            echo "   https://$H/$EP -> $CODE"
            [ "$CODE" = "200" ] || fail "https://$H/$EP returned $CODE"
        done
    done
    echo "VERIFIED: metadata $INSTALLED, venv owns [$VENV_OWNED], all endpoints 200"
}

[ -x "$VENV/bin/python" ] || fail "no interpreter at $VENV/bin/python -- wrong host?"
[ -d "$APP/.git" ] || fail "no git checkout at $APP"

if [ "$VERIFY_ONLY" = 1 ]; then
    verify
    exit 0
fi

MODE=DRY-RUN
[ "$APPLY" = 1 ] && MODE=APPLY
echo "== auth deploy ($MODE)"
echo "   app $APP   venv $VENV   service $SERVICE"

# --- refuse a working-tree deploy -------------------------------------------
# Deploying whatever happens to be checked out is how a host ends up running
# code that exists in no commit. The target is origin/master or nothing.
cd "$APP"
git fetch -q origin
echo "   HEAD          $(git rev-parse HEAD)"
echo "   origin/master $(git rev-parse origin/master)"

DIRTY=$(git status --porcelain | grep -v '^?? ' || true)
if [ -n "$DIRTY" ]; then
    echo "   local modifications present:"
    echo "$DIRTY" | sed 's/^/     /'
    run git stash push -q -m "deploy.sh $(date -u +%Y%m%dT%H%M%SZ)"
fi
run git merge --ff-only origin/master

# The step whose omission caused #7. --no-deps deliberately: dependency changes
# are a separate, reviewed action, which is also why VENV_OWNED is explicit.
run "$VENV/bin/pip" install -q --no-deps -e "$APP"

# vm-2's venv has include-system-site-packages=true, so anything NOT installed
# here resolves from the host's py312-* packages. Installing them here shadows
# the host copies WITHOUT declaring them in pyproject, which would narrow every
# consumer's resolver for packages auth does not use directly.
for SPEC in $VENV_OWNED; do
    run "$VENV/bin/pip" install -q "$SPEC"
done

run service "$SERVICE" restart

if [ "$APPLY" = 0 ]; then
    echo
    echo "DRY RUN complete. Nothing changed. Re-run with --apply."
    exit 0
fi

sleep 5
echo
verify
echo "DEPLOY OK"
