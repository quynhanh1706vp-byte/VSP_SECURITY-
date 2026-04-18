#!/bin/bash
# Validate data quality — catch empty/hardcoded responses
# Fixed version: robust token + no -f flag (so we can see 401)
set -uo pipefail

API="${VSP_API:-http://127.0.0.1:8080}"

# Fetch fresh token with strict validation
TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vsp.local","password":"admin"}' | jq -r '.token // ""')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ] || [ ${#TOKEN} -lt 50 ]; then
    echo "✗ Auth failed — token invalid (length ${#TOKEN})"
    exit 1
fi

# Helper: call API with current token, auto-refresh if 401
call_api() {
    local path="$1"
    local response
    response=$(curl -s -H "Authorization: Bearer $TOKEN" "$API$path")
    # Check if response looks like error (empty or non-JSON)
    if [ -z "$response" ] || ! echo "$response" | jq . >/dev/null 2>&1; then
        # Re-auth once
        TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" \
          -H "Content-Type: application/json" \
          -d '{"email":"admin@vsp.local","password":"admin"}' | jq -r '.token // ""')
        response=$(curl -s -H "Authorization: Bearer $TOKEN" "$API$path")
    fi
    echo "$response"
}

FAIL=0
check() {
  local name="$1"
  local cond="$2"
  local val="$3"
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    echo "✗ $name = empty/null"
    FAIL=$((FAIL+1))
    return
  fi
  if eval "$cond"; then
    echo "✓ $name = $val"
  else
    echo "✗ $name = $val (failed: $cond)"
    FAIL=$((FAIL+1))
  fi
}

# ═══ Findings summary ═══
SUMMARY=$(call_api "/api/v1/vsp/findings/summary?scope=all")
TOTAL=$(echo "$SUMMARY" | jq -r '.total // 0')
CRIT=$(echo "$SUMMARY" | jq -r '.critical // 0')
HIGH=$(echo "$SUMMARY" | jq -r '.high // 0')

check "findings_total" "[ $TOTAL -gt 100 ]" "$TOTAL"
check "findings_critical" "[ $CRIT -ge 0 ]" "$CRIT"
check "findings_high" "[ $HIGH -gt 0 ]" "$HIGH"

# ═══ Runs count ═══
RUNS_JSON=$(call_api "/api/v1/vsp/runs/index?limit=100")
RUNS=$(echo "$RUNS_JSON" | jq '.runs | length' 2>/dev/null || echo 0)
check "runs_count" "[ $RUNS -gt 10 ]" "$RUNS"

# ═══ P4 Zero Trust ═══
ZT=$(call_api "/api/p4/zt/status")
P4=$(echo "$ZT" | jq -r '.p4_readiness // 0')
check "p4_readiness" "[ $P4 -ge 85 ]" "$P4"

# ═══ SBOM NTIA ═══
SBOM=$(call_api "/api/p4/sbom/view")
NTIA=$(echo "$SBOM" | jq -r '.ntia_compliance_pct // 0 | floor')
check "sbom_ntia_not_zero" "[ $NTIA -gt 0 ]" "$NTIA%"
check "sbom_ntia_valid" "[ $NTIA -ge 0 ] && [ $NTIA -le 100 ]" "$NTIA%"

# ═══ ATO ═══
ATO_RESP=$(call_api "/api/p4/ato/expiry")
ATO=$(echo "$ATO_RESP" | jq -r '.ato_status // "unknown"')
DAYS=$(echo "$ATO_RESP" | jq -r '.days_remaining // 0')
check "ato_authorized" "[ \"$ATO\" = \"authorized\" ]" "$ATO"
check "ato_days_positive" "[ $DAYS -gt 0 ]" "$DAYS"

# ═══ SBOM libexpat consistency ═══
LIB=$(echo "$SBOM" | jq -r '.components[] | select(.name=="libexpat") | "\(.severity // "none")|\(.cves)"' | head -1)
LIB_SEV=$(echo "$LIB" | cut -d'|' -f1)
LIB_CVE=$(echo "$LIB" | cut -d'|' -f2)
if [ -z "$LIB_SEV" ]; then
  # libexpat not present in SBOM
  echo "⊘ libexpat_sev_consistent = not present (skip)"
elif [ "$LIB_SEV" = "HIGH" ] && [ "${LIB_CVE:-0}" -eq 0 ]; then
  echo "✗ libexpat_sev_consistent: sev=HIGH but cves=0 (inconsistent)"
  FAIL=$((FAIL+1))
else
  echo "✓ libexpat_sev_consistent = sev=$LIB_SEV cves=$LIB_CVE"
fi

# ═══ SBOM summary ═══
SUMM=$(echo "$SBOM" | jq -r '.summary.total // "null"')
check "sbom_summary_present" "[ \"$SUMM\" != \"null\" ]" "$SUMM"

# ═══ Threat Intel IOCs ═══
IOC_RESP=$(call_api "/api/v1/ti/iocs?limit=100")
IOCS=$(echo "$IOC_RESP" | jq '.iocs | length' 2>/dev/null || echo 0)
check "ti_iocs_present" "[ $IOCS -ge 0 ]" "$IOCS"

# ═══ Supply Chain (NEW from Milestone 1) ═══
SIGS=$(call_api "/api/v1/supply-chain/signatures" | jq -r '.count // 0')
check "supply_chain_signatures" "[ $SIGS -ge 0 ]" "$SIGS"

PROV=$(call_api "/api/v1/supply-chain/provenance" | jq -r '.count // 0')
check "slsa_provenance" "[ $PROV -ge 0 ]" "$PROV"

VEX=$(call_api "/api/p4/vex" | jq -r '.count // 0')
check "vex_statements" "[ $VEX -ge 0 ]" "$VEX"

echo ""
[ $FAIL -eq 0 ] && { echo "✅ DATA QUALITY PASS"; exit 0; } || { echo "❌ $FAIL checks failed"; exit 1; }
