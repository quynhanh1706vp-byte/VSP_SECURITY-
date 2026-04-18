#!/bin/bash
# OSCAL + SSDF + CISA Attestation test suite
# References:
#   NIST OSCAL 1.1.2
#   NIST SP 800-218 SSDF v1.1
#   CISA Secure Software Self-Attestation Common Form (2024)
set -uo pipefail

API="${VSP_API:-http://127.0.0.1:8080}"

TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vsp.local","password":"admin"}' | jq -r '.token // ""')

if [ -z "$TOKEN" ] || [ ${#TOKEN} -lt 50 ]; then
    echo "✗ Auth failed"; exit 1
fi

PASS=0; FAIL=0
TMP=$(mktemp)

ok() { PASS=$((PASS+1)); echo "✓ $1"; }
ko() { FAIL=$((FAIL+1)); echo "✗ $1 → $(head -c 150 "$TMP")"; }

api_get() {
    curl -s -o "$TMP" -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" "$API$1"
}

api_post() {
    curl -s -o "$TMP" -w "%{http_code}" \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$2" "$API$1"
}

echo "═══ OSCAL + SSDF + Attestation Test Suite ═══"
echo ""

# ─── OSCAL Models ───
echo "── OSCAL Models ──"

code=$(api_get "/api/p4/oscal/catalog")
[ "$code" = "200" ] && ok "catalog_endpoint" || ko "catalog_endpoint [$code]"
CAT_FAMILIES=$(jq -r '.catalog.groups | length' "$TMP")
[ "${CAT_FAMILIES:-0}" -ge 5 ] && ok "catalog_has_families ($CAT_FAMILIES)" || ko "catalog_no_families"
OSCAL_VER=$(jq -r '.catalog.metadata."oscal-version"' "$TMP")
[ "$OSCAL_VER" = "1.1.2" ] && ok "oscal_version_1.1.2" || ko "oscal_version_wrong ($OSCAL_VER)"

code=$(api_get "/api/p4/oscal/profile")
[ "$code" = "200" ] && ok "profile_endpoint" || ko "profile_endpoint [$code]"
PROFILE_IMPORTS=$(jq -r '.profile.imports | length' "$TMP")
[ "${PROFILE_IMPORTS:-0}" -ge 1 ] && ok "profile_imports_catalog" || ko "profile_no_imports"

code=$(api_get "/api/p4/oscal/ssp/extended")
[ "$code" = "200" ] && ok "ssp_extended_endpoint" || ko "ssp_extended [$code]"
SSP_SYSTEM=$(jq -r '."system-security-plan"."system-characteristics"."system-name"' "$TMP")
[ "$SSP_SYSTEM" = "VSP Security Platform" ] && ok "ssp_system_name_correct" || ko "ssp_system_wrong ($SSP_SYSTEM)"
SSP_CONTROLS=$(jq -r '."system-security-plan"."control-implementation"."implemented-requirements" | length' "$TMP")
[ "${SSP_CONTROLS:-0}" -ge 4 ] && ok "ssp_has_controls ($SSP_CONTROLS)" || ko "ssp_no_controls"

code=$(api_get "/api/p4/oscal/assessment-plan")
[ "$code" = "200" ] && ok "assessment_plan_endpoint" || ko "assessment_plan [$code]"
AP_TASKS=$(jq -r '."assessment-plan".tasks | length' "$TMP")
[ "${AP_TASKS:-0}" -ge 5 ] && ok "assessment_plan_has_tasks ($AP_TASKS)" || ko "assessment_plan_no_tasks"

code=$(api_get "/api/p4/oscal/assessment-results")
[ "$code" = "200" ] && ok "assessment_results_endpoint" || ko "assessment_results [$code]"

code=$(api_get "/api/p4/oscal/poam-extended")
[ "$code" = "200" ] && ok "poam_extended_endpoint" || ko "poam_extended [$code]"
POAM_COUNT=$(jq -r '."plan-of-action-and-milestones"."poam-items" | length' "$TMP")
[ "${POAM_COUNT:-0}" -ge 0 ] && ok "poam_items_list_valid ($POAM_COUNT)" || ko "poam_items_invalid"

# ─── SSDF ───
echo ""
echo "── SSDF Practices ──"

code=$(api_get "/api/p4/ssdf/practices")
[ "$code" = "200" ] && ok "ssdf_list_endpoint" || ko "ssdf_list [$code]"
SSDF_TOTAL=$(jq -r '.total // 0' "$TMP")
[ "$SSDF_TOTAL" -eq 20 ] && ok "ssdf_has_20_practices" || ko "ssdf_wrong_count ($SSDF_TOTAL)"
SSDF_PCT=$(jq -r '.implementation_pct // 0' "$TMP")
[ "$SSDF_PCT" -ge 70 ] && ok "ssdf_impl_pct_good ($SSDF_PCT%)" || ko "ssdf_impl_low ($SSDF_PCT%)"

# Update test
UP_BODY='{"practice_id":"PO.1.1","status":"implemented","notes":"Auto-test update"}'
code=$(api_post "/api/p4/ssdf/practice/update" "$UP_BODY")
[ "$code" = "200" ] && ok "ssdf_update_endpoint" || ko "ssdf_update [$code]"

# ─── Attestation ───
echo ""
echo "── CISA Attestation ──"

code=$(api_get "/api/p4/attestation/generate")
[ "$code" = "200" ] && ok "attest_generate_endpoint" || ko "attest_generate [$code]"
FORM_UUID=$(jq -r '.form_uuid // ""' "$TMP")
[ -n "$FORM_UUID" ] && ok "attest_form_uuid_generated" || ko "attest_no_uuid"
ATTEST_PCT=$(jq -r '.attestation_stats.attestation_pct // 0' "$TMP")
[ "$ATTEST_PCT" -ge 70 ] && ok "attest_pct_good ($ATTEST_PCT%)" || ko "attest_pct_low ($ATTEST_PCT%)"
ATTEST_TOTAL=$(jq -r '.attestation_stats.total_practices // 0' "$TMP")
[ "$ATTEST_TOTAL" -eq 20 ] && ok "attest_all_20_practices" || ko "attest_wrong_total ($ATTEST_TOTAL)"

# Sign test
SIGN_BODY=$(jq -nc --arg uuid "$FORM_UUID" '{
  form_uuid: $uuid,
  signed_by_name: "Automated Test",
  signed_by_title: "Chief Executive Officer",
  signed_by_email: "auto-test@vsp.local",
  signature_method: "electronic"
}')
code=$(api_post "/api/p4/attestation/sign" "$SIGN_BODY")
[ "$code" = "200" ] && ok "attest_sign_endpoint" || ko "attest_sign [$code]"

code=$(api_get "/api/p4/attestation/list")
[ "$code" = "200" ] && ok "attest_list_endpoint" || ko "attest_list [$code]"
FORMS_COUNT=$(jq -r '.count // 0' "$TMP")
[ "$FORMS_COUNT" -ge 1 ] && ok "attest_forms_persisted ($FORMS_COUNT)" || ko "attest_forms_empty"
SIGNED_COUNT=$(jq -r '.by_status.signed // 0' "$TMP")
[ "$SIGNED_COUNT" -ge 1 ] && ok "attest_has_signed_forms ($SIGNED_COUNT)" || ko "attest_no_signed"

rm -f "$TMP"
echo ""
echo "─────────────────────────"
echo "OSCAL + SSDF + Attestation: $PASS pass / $FAIL fail"
if [ $FAIL -eq 0 ]; then
    echo "✅ M2 TEST SUITE PASS"
    exit 0
else
    echo "❌ M2 TEST SUITE FAIL"
    exit 1
fi
