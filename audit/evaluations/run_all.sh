#!/bin/sh
# Safe-by-default audit probe runner.
#
# Every probe here drives auth through its own HTTP interface against an
# ephemeral in-process instance on throwaway SQLite, so this is safe to run
# against a machine hosting a live service. Probes that need failure injection
# or sustained load are listed under DESTRUCTIVE and refuse to run unless
# AUDIT_ALLOW_DESTRUCTIVE=1 is set.
#
# Exits non-zero if any probe fails.
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
for p in $SAFE; do
    [ -f "$DIR/$p" ] || continue
    total=$((total + 1))
    if ! "$PY" "$DIR/$p"; then
        fails=$((fails + 1))
    fi
    echo
done

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
echo "probes: $total   failed: $fails"
[ "$fails" -eq 0 ] || exit 1
