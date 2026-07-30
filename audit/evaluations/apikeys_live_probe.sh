#!/usr/bin/env bash
# Live probe: per-user API-key lifecycle (SPEC 0004) against a running auth.
#
#   AUTH_BASE=https://auth.rodmena.app bash audit/evaluations/apikeys_live_probe.sh
#
# Uses freshly minted throwaway tenant keys only — it never touches an
# existing namespace. Probe order is deliberate: every check that must go RED
# is preceded by the same check going GREEN on a known positive, so a vacuous
# red can't pass. Exits non-zero on the first failed assertion.

set -euo pipefail
BASE="${AUTH_BASE:-https://auth.rodmena.app}"
PASS=0

uuid() { python3 -c "import uuid; print(uuid.uuid4())"; }

req() { # method path tenant [json-body]
    local method="$1" path="$2" tenant="$3" body="${4:-}"
    if [ -n "$body" ]; then
        curl -fsS -X "$method" -H "Authorization: Bearer $tenant" \
            -H "Content-Type: application/json" -d "$body" "$BASE$path"
    else
        curl -fsS -X "$method" -H "Authorization: Bearer $tenant" "$BASE$path"
    fi
}

check() { # description actual expected
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1)); echo "PASS: $1"
    else
        echo "FAIL: $1 — expected [$3] got [$2]"; exit 1
    fi
}

TENANT_A="$(uuid)"; TENANT_B="$(uuid)"
echo "== throwaway tenants minted =="

# --- create → validate GREEN (the known positive everything else leans on)
CREATED=$(req POST "/api/apikeys/user/probe.user@example.com" "$TENANT_A" '{"label": "live probe"}')
SECRET=$(echo "$CREATED" | jq -r .data.api_key)
KEY_ID=$(echo "$CREATED" | jq -r .data.key_id)
check "create returns rak_ secret" "$(echo "$SECRET" | grep -cE '^rak_[0-9A-Za-z]{43}$')" "1"
check "validate green on live key" \
    "$(req POST /api/apikeys/validate "$TENANT_A" "{\"api_key\": \"$SECRET\"}" | jq -r '.data.valid')" "true"
check "validate returns the user" \
    "$(req POST /api/apikeys/validate "$TENANT_A" "{\"api_key\": \"$SECRET\"}" | jq -r '.data.user')" "probe.user@example.com"

# --- tampered secret RED
TAMPERED="${SECRET%?}X"; [ "$TAMPERED" = "$SECRET" ] && TAMPERED="${SECRET%?}Y"
check "tampered secret -> unknown_key" \
    "$(req POST /api/apikeys/validate "$TENANT_A" "{\"api_key\": \"$TAMPERED\"}" | jq -r '.data.reason')" "unknown_key"

# --- cross-tenant RED while owner still GREEN
check "foreign tenant -> unknown_key" \
    "$(req POST /api/apikeys/validate "$TENANT_B" "{\"api_key\": \"$SECRET\"}" | jq -r '.data.reason')" "unknown_key"
check "owner still green after foreign probe" \
    "$(req POST /api/apikeys/validate "$TENANT_A" "{\"api_key\": \"$SECRET\"}" | jq -r '.data.valid')" "true"
check "foreign tenant sees empty list" \
    "$(req GET "/api/apikeys/user/probe.user@example.com" "$TENANT_B" | jq -r '.data.count')" "0"

# --- list shows the live key
check "owner list count" \
    "$(req GET "/api/apikeys/user/probe.user@example.com" "$TENANT_A" | jq -r '.data.count')" "1"
check "list never carries the secret" \
    "$(req GET "/api/apikeys/user/probe.user@example.com" "$TENANT_A" | grep -c "$SECRET" || true)" "0"

# --- revoke → RED, idempotent, list reflects it
check "revoke" \
    "$(req DELETE "/api/apikeys/user/probe.user@example.com/$KEY_ID" "$TENANT_A" | jq -r '.data.revoked')" "true"
check "validate red after revoke" \
    "$(req POST /api/apikeys/validate "$TENANT_A" "{\"api_key\": \"$SECRET\"}" | jq -r '.data.reason')" "revoked"
check "double revoke idempotent" \
    "$(req DELETE "/api/apikeys/user/probe.user@example.com/$KEY_ID" "$TENANT_A" | jq -r '.data.already_revoked')" "true"
check "list shows is_active=false" \
    "$(req GET "/api/apikeys/user/probe.user@example.com" "$TENANT_A" | jq -r '.data.keys[0].is_active')" "false"

# --- rotation preserves user keys (fresh key on tenant B, then rotate B)
CREATED_B=$(req POST "/api/apikeys/user/rotation.probe" "$TENANT_B")
SECRET_B=$(echo "$CREATED_B" | jq -r .data.api_key)
check "pre-rotation green (tenant B)" \
    "$(req POST /api/apikeys/validate "$TENANT_B" "{\"api_key\": \"$SECRET_B\"}" | jq -r '.data.valid')" "true"
ROTATED=$(req POST /api/keys/rotate "$TENANT_B")
TENANT_B2=$(echo "$ROTATED" | jq -r .data.new_key)
check "rotate migrated api_keys count" "$(echo "$ROTATED" | jq -r '.data.migrated.api_keys')" "1"
check "secret validates under NEW tenant key" \
    "$(req POST /api/apikeys/validate "$TENANT_B2" "{\"api_key\": \"$SECRET_B\"}" | jq -r '.data.valid')" "true"
check "old tenant key -> unknown_key" \
    "$(req POST /api/apikeys/validate "$TENANT_B" "{\"api_key\": \"$SECRET_B\"}" | jq -r '.data.reason')" "unknown_key"

# --- backward compat: the classic RBAC flow, byte-shape as documented
TENANT_C="$(uuid)"
check "create_role bare shape" "$(req POST /api/role/probers "$TENANT_C" | jq -c .)" '{"result":true}'
check "add_permission bare shape" "$(req POST /api/permission/probers/probe_things "$TENANT_C" | jq -c .)" '{"result":true}'
check "add_membership bare shape" "$(req POST /api/membership/probe.user/probers "$TENANT_C" | jq -c .)" '{"result":true}'
check "has_permission wrapped shape" \
    "$(req GET /api/has_permission/probe.user/probe_things "$TENANT_C" | jq -r '.data.has_permission')" "true"
check "write-to-missing-role stays 200/false" \
    "$(req POST /api/membership/probe.user/ghosts "$TENANT_C" | jq -c .)" '{"result":false}'

# --- served docs advertise the new endpoints (the artifact, not the source)
DOCS=$(curl -fsS "$BASE/llms.txt?cachebust=$(uuid)")
check "docs list /api/apikeys/user" "$(echo "$DOCS" | grep -c '/api/apikeys/user' | head -1 | awk '{print ($1>0)?1:0}')" "1"
check "docs list /api/apikeys/validate" "$(echo "$DOCS" | grep -c '/api/apikeys/validate' | head -1 | awk '{print ($1>0)?1:0}')" "1"
check "docs report 2.4.0" "$(echo "$DOCS" | grep -c '2\.4\.0' | head -1 | awk '{print ($1>0)?1:0}')" "1"

echo "== ALL $PASS PROBES PASSED against $BASE =="
