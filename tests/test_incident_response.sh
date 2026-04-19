#!/bin/bash
# M3 test suite — IR + CIRCIA + Forensics + Extended handlers
set -uo pipefail
API="${VSP_API:-http://127.0.0.1:8080}"
TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" -H "Content-Type: application/json" \
  -d '{"email":"admin@vsp.local","password":"admin"}' | jq -r '.token // ""')
[ -z "$TOKEN" ] && { echo "✗ auth failed"; exit 1; }

PASS=0; FAIL=0; TMP=$(mktemp)
ok(){ PASS=$((PASS+1)); echo "✓ $1"; }
ko(){ FAIL=$((FAIL+1)); echo "✗ $1 → $(head -c 150 "$TMP")"; }
api(){ local m="$1" p="$2" b="${3:-}"; if [ -z "$b" ]; then
  curl -s -o "$TMP" -w "%{http_code}" -X "$m" -H "Authorization: Bearer $TOKEN" "$API$p"
else
  curl -s -o "$TMP" -w "%{http_code}" -X "$m" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" -d "$b" "$API$p"; fi; }

echo "═══ M3 IR + CIRCIA + Forensics ═══"

# IR endpoints
c=$(api GET /api/p4/ir/incidents); [ "$c" = "200" ] && ok "ir_list" || ko "ir_list [$c]"
TOTAL=$(jq -r .count "$TMP"); [ "$TOTAL" -ge 2 ] && ok "ir_has_incidents ($TOTAL)" || ko "ir_no_incidents"

c=$(api POST /api/p4/ir/incident '{"title":"Test suite incident","severity":"medium","impact_integrity":true}')
[ "$c" = "200" ] && ok "ir_create" || ko "ir_create [$c]"
INC=$(jq -r .incident_id "$TMP"); IS_SUB=$(jq -r .is_substantial "$TMP")
[ -n "$INC" ] && ok "ir_id_generated ($INC)" || ko "ir_no_id"
[ "$IS_SUB" = "true" ] && ok "ir_auto_substantial" || ko "ir_not_substantial"

c=$(api POST /api/p4/ir/incident/transition "$(jq -nc --arg i "$INC" '{incident_id:$i,phase:"containment"}')")
[ "$c" = "200" ] && ok "ir_transition" || ko "ir_transition"

# Extended handlers
c=$(api GET "/api/p4/ir/incident/detail?id=INC-2026-0002")
[ "$c" = "200" ] && ok "ir_detail" || ko "ir_detail [$c]"
jq -e '.timeline and .impact and .circia_reports' "$TMP" > /dev/null && ok "ir_detail_complete" || ko "ir_detail_fields"

c=$(api POST /api/p4/ir/incident/update "$(jq -nc --arg i "$INC" '{incident_id:$i,field:"description",value:"Test updated"}')")
[ "$c" = "200" ] && ok "ir_update" || ko "ir_update [$c]"

c=$(api POST /api/p4/ir/incident/ransom-payment "$(jq -nc --arg i "$INC" '{incident_id:$i,amount_usd:25000,payment_method:"bitcoin"}')")
[ "$c" = "200" ] && ok "ir_ransom_payment" || ko "ir_ransom [$c]"

c=$(api POST /api/p4/ir/incident/lessons "$(jq -nc --arg i "$INC" '{incident_id:$i,root_cause:"Test RCA",lessons_learned:"Test lessons",corrective_actions:["act1","act2"]}')")
[ "$c" = "200" ] && ok "ir_lessons" || ko "ir_lessons [$c]"

# CIRCIA
c=$(api POST /api/p4/circia/generate "$(jq -nc --arg i "$INC" '{incident_id:$i,report_type:"substantial_incident",ci_sector:"information_technology"}')")
[ "$c" = "200" ] && ok "circia_generate" || ko "circia_generate [$c]"
RUUID=$(jq -r .report_uuid "$TMP"); [ -n "$RUUID" ] && ok "circia_has_uuid" || ko "circia_no_uuid"

c=$(api GET "/api/p4/circia/report/detail?uuid=$RUUID")
[ "$c" = "200" ] && ok "circia_detail" || ko "circia_detail [$c]"

c=$(api POST /api/p4/circia/submit "$(jq -nc --arg u "$RUUID" '{report_uuid:$u,submitted_by_name:"Test",submitted_by_title:"CISO",submitted_by_email:"x@vsp.local"}')")
[ "$c" = "200" ] && ok "circia_submit" || ko "circia_submit"

c=$(api GET /api/p4/circia/reports); [ "$c" = "200" ] && ok "circia_list" || ko "circia_list"

# Forensics
c=$(api POST /api/p4/forensics/evidence "$(jq -nc --arg i "$INC" '{incident_id:$i,evidence_type:"log_file",description:"Test log",file_size_bytes:1024,collected_by:"auto-test"}')")
[ "$c" = "200" ] && ok "forensics_create" || ko "forensics_create [$c]"
EVD=$(jq -r .evidence_id "$TMP")

c=$(api POST /api/p4/forensics/custody "$(jq -nc --arg e "$EVD" '{evidence_id:$e,actor:"test",action:"analyzed"}')")
[ "$c" = "200" ] && ok "forensics_custody" || ko "forensics_custody"

c=$(api GET /api/p4/forensics/evidence); [ "$c" = "200" ] && ok "forensics_list" || ko "forensics_list"

# Playbooks
c=$(api GET /api/p4/ir/playbooks); [ "$c" = "200" ] && ok "playbooks" || ko "playbooks"
PB_COUNT=$(jq -r .count "$TMP"); [ "$PB_COUNT" -ge 5 ] && ok "playbooks_5plus ($PB_COUNT)" || ko "playbooks_few"

rm -f "$TMP"
echo ""
echo "─────────────────────────"
echo "M3: $PASS pass / $FAIL fail"
[ $FAIL -eq 0 ] && { echo "✅ M3 TEST SUITE PASS"; exit 0; } || { echo "❌ FAIL"; exit 1; }
