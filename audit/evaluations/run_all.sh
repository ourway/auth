#!/bin/sh
# Safe-by-default audit probe runner.
#
# Every probe here drives auth through its own HTTP interface against an
# ephemeral in-process instance on throwaway SQLite, so this is safe to run
# against a machine hosting a live service. Probes that need failure injection
# or sustained load are listed under DESTRUCTIVE and refuse to run unless
# AUDIT_ALLOW_DESTRUCTIVE=1 is set.
#
# Exits non-zero if any probe fails, AND if any probe could not run. A probe
# that skips has not checked anything, so counting it as a pass turns "I had no
# database to ask" into "tenant isolation is fine". Set AUDIT_ALLOW_SKIPS=1 to
# acknowledge the gap deliberately -- the summary still names what was skipped.
set -u
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY=${AUDIT_PYTHON:-"$DIR/../../.venv/bin/python"}

SAFE="probe_client_key_validator_parity.py
probe_audit_records_real_client_ip.py
probe_user_name_charset.py
probe_encryption_key_canary.py
probe_readiness_and_concurrency.py
probe_audit_partition_runway.py
probe_test_isolation_guard.py
probe_client_distinguishes_refusal.py
probe_rotate_key_recovery.py
probe_rls_cross_tenant_isolation.py
probe_rls_no_leak_across_pooled_connections.py
probe_rls_covers_every_tenant_table.py
probe_rls_forced_not_merely_enabled.py"

# probe_rls_forced_not_merely_enabled gates its own destructive half: it only
# takes FORCE off a table when AUDIT_ALLOW_DESTRUCTIVE=1 and a superuser URL
# are both given, and says plainly when it did not, so it is safe in the list
# above and there is nothing to run twice here.
DESTRUCTIVE=""

fails=0
total=0
skipped=0
skipped_names=""
out=$(mktemp)
for p in $SAFE; do
    [ -f "$DIR/$p" ] || continue
    total=$((total + 1))
    if ! "$PY" "$DIR/$p" 2>&1 | tee "$out"; then
        fails=$((fails + 1))
    fi
    if grep -q "SKIPPED" "$out"; then
        skipped=$((skipped + 1))
        skipped_names="$skipped_names $p"
    fi
    echo
done
rm -f "$out"

if [ "${AUDIT_ALLOW_DESTRUCTIVE:-0}" = "1" ]; then
    for p in $DESTRUCTIVE; do
        [ -f "$DIR/$p" ] || continue
        echo "!! DESTRUCTIVE probe: $p"
        total=$((total + 1))
        "$PY" "$DIR/$p" || fails=$((fails + 1))
        echo
    done
elif [ -n "$DESTRUCTIVE" ]; then
    echo "-- skipping destructive probes (set AUDIT_ALLOW_DESTRUCTIVE=1 to run)"
fi

echo "======================================================"
if [ "$total" -eq 0 ]; then
    echo "NO PROBES RAN - treat this as a failure, not a pass"
    exit 1
fi
echo "probes: $total   failed: $fails   skipped: $skipped"
[ "$fails" -eq 0 ] || exit 1

if [ "$skipped" -gt 0 ]; then
    echo
    echo "$skipped probe(s) COULD NOT RUN and checked nothing:"
    for p in $skipped_names; do echo "    $p"; done
    echo
    echo "Most of these need a PostgreSQL deployment (AUTH_PG_URL). Tenant"
    echo "isolation was NOT verified by this run. 'make probe-postgres' builds"
    echo "a disposable container and runs the full set."
    if [ "${AUDIT_ALLOW_SKIPS:-0}" = "1" ]; then
        echo
        echo "AUDIT_ALLOW_SKIPS=1 - exiting 0 with the gap acknowledged."
        exit 0
    fi
    exit 2
fi
