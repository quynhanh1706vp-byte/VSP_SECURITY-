#!/bin/bash
# ════════════════════════════════════════════════════════════════
# Supply Chain test suite — validates Sigstore/SLSA/VEX endpoints
# References: NIST SP 800-218 PS, SLSA Framework, CycloneDX VEX 1.4
# ════════════════════════════════════════════════════════════════
set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
TOKEN=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@vsp.local","password":"admin"}' | jq -r .token)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "✗ Auth failed — cannot get token"
    exit 1
fi

PASS=0; FAIL=0
TMP=$(mktemp)

ok() { PASS=$((PASS+1)); echo "✓ $1"; }
ko() { FAIL=$((FAIL+1)); echo "✗ $1 → $(head -c 200 "$TMP")"; }

api() {
    local method="$1" path="$2" body="${3:-}"
    if [ -z "$body" ]; then
        curl -s -o "$TMP" -w "%{http_code}" \
            -X "$method" -H "Authorization: Bearer $TOKEN" \
            "$BASE_URL$path"
    else
        curl -s -o "$TMP" -w "%{http_code}" \
            -X "$method" -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body" "$BASE_URL$path"
    fi
}

echo "═══ Supply Chain Test Suite ═══"

# 1. Public key export (no auth needed)
code=$(curl -s -o "$TMP" -w "%{http_code}" "$BASE_URL/api/v1/supply-chain/public-key")
[ "$code" = "200" ] && ok "public_key_export" || ko "public_key_export [$code]"
KEY_ID=$(jq -r '.key_id // "null"' "$TMP")
[ "$KEY_ID" != "null" ] && [ -n "$KEY_ID" ] && ok "key_id_present ($KEY_ID)" || ko "key_id_missing"

# 2. Sign artifact
SIGN_BODY='{"artifact_name":"vsp-test:v1","artifact_digest":"sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2","payload":{"test":"suite"},"signed_by":"test@vsp.local"}'
code=$(api POST "/api/v1/supply-chain/sign" "$SIGN_BODY")
[ "$code" = "200" ] && ok "sign_artifact" || ko "sign_artifact [$code]"
BUNDLE=$(jq -c '.bundle // empty' "$TMP")
[ -n "$BUNDLE" ] && ok "bundle_generated" || ko "bundle_missing"

# 3. Verify signature (roundtrip)
if [ -n "$BUNDLE" ]; then
    VER_BODY="{\"bundle\": $BUNDLE}"
    code=$(api POST "/api/v1/supply-chain/verify" "$VER_BODY")
    [ "$code" = "200" ] && ok "verify_roundtrip" || ko "verify_roundtrip [$code]"
    VALID=$(jq -r '.valid // false' "$TMP")
    [ "$VALID" = "true" ] && ok "signature_cryptographically_valid" || ko "signature_invalid"
fi

# 4. List signatures
code=$(api GET "/api/v1/supply-chain/signatures")
[ "$code" = "200" ] && ok "list_signatures" || ko "list_signatures [$code]"
SIG_COUNT=$(jq -r '.count // 0' "$TMP")
[ "$SIG_COUNT" -gt 0 ] && ok "signatures_persisted ($SIG_COUNT)" || ko "signatures_not_persisted"

# 5. SLSA Provenance generation
PROV_BODY='{"artifact_name":"vsp-test:v1","artifact_digest":"sha256:abc123","source_uri":"git+https://github.com/vsp/platform","source_commit":"06f22db","slsa_level":2}'
code=$(api POST "/api/v1/supply-chain/provenance" "$PROV_BODY")
[ "$code" = "200" ] && ok "slsa_provenance_gen" || ko "slsa_provenance_gen [$code]"
SLSA_LEVEL=$(jq -r '.slsa_level // 0' "$TMP")
[ "$SLSA_LEVEL" -eq 2 ] && ok "slsa_level_correct (L$SLSA_LEVEL)" || ko "slsa_level_wrong ($SLSA_LEVEL)"

# Check statement format (in-toto v1)
STATEMENT_TYPE=$(jq -r '.statement._type // "null"' "$TMP")
[ "$STATEMENT_TYPE" = "https://in-toto.io/Statement/v1" ] && ok "intoto_statement_v1" || ko "intoto_format_wrong ($STATEMENT_TYPE)"

# 6. List provenance
code=$(api GET "/api/v1/supply-chain/provenance")
[ "$code" = "200" ] && ok "list_provenance" || ko "list_provenance [$code]"
PROV_COUNT=$(jq -r '.count // 0' "$TMP")
[ "$PROV_COUNT" -gt 0 ] && ok "provenance_persisted ($PROV_COUNT)" || ko "provenance_not_persisted"

# 7. VEX create
VEX_BODY='{"product_name":"vsp-gateway","product_version":"1.0","component_name":"test-comp","cve_id":"CVE-TEST-0001","status":"not_affected","justification":"code_not_reachable","detail":"test run","author":"test@vsp.local"}'
code=$(api POST "/api/p4/vex" "$VEX_BODY")
[ "$code" = "200" ] && ok "vex_create" || ko "vex_create [$code]"
BOM_FORMAT=$(jq -r '.statement.bomFormat // "null"' "$TMP")
[ "$BOM_FORMAT" = "CycloneDX" ] && ok "vex_cyclonedx_format" || ko "vex_format_wrong ($BOM_FORMAT)"
SPEC_VER=$(jq -r '.statement.specVersion // "null"' "$TMP")
[ "$SPEC_VER" = "1.4" ] && ok "vex_spec_1.4" || ko "vex_spec_wrong ($SPEC_VER)"

# 8. VEX list
code=$(api GET "/api/p4/vex")
[ "$code" = "200" ] && ok "list_vex" || ko "list_vex [$code]"
VEX_COUNT=$(jq -r '.count // 0' "$TMP")
[ "$VEX_COUNT" -gt 0 ] && ok "vex_persisted ($VEX_COUNT)" || ko "vex_not_persisted"

# 9. VEX statistics present
STATS_PRESENT=$(jq -r '.statistics | has("affected") and has("not_affected")' "$TMP")
[ "$STATS_PRESENT" = "true" ] && ok "vex_statistics_aggregated" || ko "vex_stats_missing"

# 10. Filter VEX by status
code=$(api GET "/api/p4/vex?status=not_affected")
[ "$code" = "200" ] && ok "vex_filter_status" || ko "vex_filter_status [$code]"

rm -f "$TMP"
echo ""
echo "─────────────────────────"
echo "Supply Chain: $PASS pass / $FAIL fail"
if [ $FAIL -eq 0 ]; then
    echo "✅ SUPPLY CHAIN PASS"
    exit 0
else
    echo "❌ SUPPLY CHAIN FAIL"
    exit 1
fi
