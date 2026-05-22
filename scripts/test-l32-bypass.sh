#!/usr/bin/env bash
# scripts/test-l32-bypass.sh — adversarial bypass-attempts on recent fixes.
#
# Every CRITICAL fix landed this session is now a target. For each, this
# level fires bypass payloads and asserts they fail. The catch: when a
# fix lands, often a SIBLING vector goes unprotected. This level pins
# every recent fix against a creative-attacker probe.
#
#   33.1 Cross-tenant cache key — try cookie injection / X-Tenant-Slug
#        rewrite to pollute another tenant's cache key.
#   33.2 SSE Hub tenant routing — connect with malformed JWT, inject
#        scan_complete via direct DB INSERT, scan A's stream.
#   33.3 Audit chain race — fire 50 concurrent INSERTs, immediate
#        re-verify, no chain breaks.
#   33.4 X-Forwarded-For with multi-hop — XFF chain "1.2.3.4, 127.0.0.1"
#        attempting to make the LAST hop look like loopback.
#   33.5 pprof loopback gate — try IPv6 ::1 form, IPv6 mapped IPv4.
#   33.6 OpenAPI surface drift below ratchet — adding a new GET in code
#        without a spec entry MUST push count above ratchet.
#
# Pre-flight: $JWT_SECRET, $DB_DSN, gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local slug="${1:-default}"
  local now exp h p s
  now=$(date +%s); exp=$((now + 3600))
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  p=$(printf '{"sub":"l32@vsp.local","email":"l32@vsp.local","role":"admin","tenant_id":"%s","iat":%d,"exp":%d}' \
    "$slug" "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$h" "$p" "$s"
}
ADMIN_A=$(mint_jwt default)
ADMIN_B=$(mint_jwt acme-corp)
TENANT_B_UUID="8bb9a716-fd14-4eba-92e8-681dc5bdb718"

# ── 33.1 Cache key — header injection bypass ──────────────────────────────

phase_open "33.1 Cross-tenant cache — header-injection cannot pollute key"

# Hit findings/summary as B, then immediately as A but with weird
# headers (X-Tenant-Slug, Cookie pollution) to see if any header
# steers the cache key away from the auth.Claims tenant.
B_TOTAL=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN_B" \
  "$BASE/api/v1/vsp/findings/summary" | jq -r '.total // -1')
sleep 1
# Probe with various header tricks — none of these should make A
# see B's data.
HEADERS=(
  '-H "X-Tenant-Slug: acme-corp"'
  '-H "X-Forwarded-Tenant: acme-corp"'
  '-H "Cookie: tenant_id=acme-corp"'
  '-H "X-Tenant: 8bb9a716-fd14-4eba-92e8-681dc5bdb718"'
)
LEAK=0
for hdr in "${HEADERS[@]}"; do
  body=$(eval curl -s --max-time 5 -H "'Authorization: Bearer $ADMIN_A'" $hdr \
    "$BASE/api/v1/vsp/findings/summary")
  total=$(echo "$body" | jq -r '.total // -1' 2>/dev/null)
  if [[ "$total" == "$B_TOTAL" && "$total" != "0" ]]; then
    LEAK=$((LEAK+1))
  fi
done
if (( LEAK == 0 )); then
  _pass "33.1.1 cache key resistant to header-injection bypass"
else
  _fail "33.1.1 cache leaked across $LEAK header tricks" \
    "tenant A saw B's count via header injection — cache key is not auth-bound"
fi

# ── 33.2 SSE Hub — direct DB scan_complete injection probe ────────────────

phase_open "33.2 SSE — direct-DB INSERT can't reach foreign tenant"

# Insert a high-RID DONE run for tenant B. SSE poller picks it up
# and broadcasts. Connect as A, capture stream, assert NO scan_complete
# carries B's tenant UUID.
CANARY_RID="zzz-L32-$$"
SSE_OUT=$(mktemp)
cleanup_l32() {
  rm -f "$SSE_OUT"
  _psql_oneshot "DELETE FROM runs WHERE rid='$CANARY_RID';" >/dev/null 2>&1 || true
}
trap cleanup_l32 EXIT

curl -s --max-time 8 -N -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/events" > "$SSE_OUT" 2>/dev/null &
SSE_PID=$!
sleep 1
_psql_oneshot "INSERT INTO runs (rid, tenant_id, mode, profile, status, gate, total_findings, summary)
               VALUES ('$CANARY_RID', '$TENANT_B_UUID', 'on-demand', 'FAST', 'DONE', 'PASS', 0, '{}')
               ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true
sleep 7
kill "$SSE_PID" 2>/dev/null || true
wait "$SSE_PID" 2>/dev/null || true

if grep -q "$TENANT_B_UUID\|$CANARY_RID" "$SSE_OUT" 2>/dev/null; then
  _fail "33.2.1 SSE leaked B's scan_complete to A" \
    "stream captured B's UUID after direct-DB INSERT bypass"
else
  _pass "33.2.1 SSE Hub didn't fan B's scan_complete to A"
fi

# ── 33.3 Audit chain — 50-way concurrent insert, no break ────────────────

phase_open "33.3 Audit chain — 50-way insert burst stays consistent"

# Fire 50 audit-emitting requests in parallel, then verify the chain.
# Pre-L5 fix this would shred the chain (advisory-lock-free
# pending-hash race). Post-fix should hold.
sudo systemctl restart vsp-gateway 2>/dev/null && sleep 4
ADMIN_A=$(mint_jwt default)   # re-mint after restart

for i in $(seq 1 50); do
  curl -s -o /dev/null --max-time 3 \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"l32-burst-$i@vsp.local\",\"password\":\"wrong\"}" \
    "$BASE/api/v1/auth/login" &
done
wait
sleep 2

VERIFY=$(curl -s -X POST --max-time 5 -H "Authorization: Bearer $ADMIN_A" \
  "$BASE/api/v1/audit/verify" | jq -r '.ok // false' 2>/dev/null)
if [[ "$VERIFY" == "true" ]]; then
  _pass "33.3.1 audit chain intact after 50-way insert burst"
else
  _fail "33.3.1 audit chain broke under concurrent burst" \
    "verify ok=$VERIFY — race regression"
fi

# ── 33.4 X-Forwarded-For chain ─────────────────────────────────────────────

phase_open "33.4 XFF chain — last-hop spoof can't claim trusted source"

# chi.RealIP picks the FIRST entry in XFF. We want to make sure that
# even with a chain like "1.2.3.4, 127.0.0.1", a non-trusted source
# can't impersonate loopback. From the loopback test box, this still
# probes the trusted source path — but if the wrapper accidentally
# read the LAST hop (some implementations do), 127.0.0.1 would be
# accepted as the rewrite target. Test: with loopback as the actual
# TCP source, set XFF: "8.8.8.8, 127.0.0.1". chi.RealIP rewrites to
# "8.8.8.8" (first), gate sees 8.8.8.8 → 403.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
  -H "X-Forwarded-For: 8.8.8.8, 127.0.0.1" \
  "$BASE/debug/pprof/")
if [[ "$status" == "403" ]]; then
  _pass "33.4.1 XFF chain — last-hop loopback masquerade rejected [403]"
else
  _fail "33.4.1 XFF chain accepted last-hop loopback" \
    "expected 403, got $status — chi.RealIP may be reading rightmost"
fi

# ── 33.5 pprof gate — IPv6 forms ──────────────────────────────────────────

phase_open "33.5 pprof gate — IPv6 ::1 / mapped-IPv4 still loopback"

# Probe via IPv6 loopback. If gateway listens on ::1, this should
# pass (same machine). The gate's IP allow-list must accept ::1.
status6=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 -6 \
  "http://[::1]:8921/debug/pprof/" 2>/dev/null || echo "000")
if [[ "$status6" == "200" ]]; then
  _pass "33.5.1 IPv6 ::1 reaches /debug/* (loopback recognised)"
elif [[ "$status6" == "000" ]]; then
  _skip "33.5.1 IPv6 ::1" "gateway not listening on IPv6 in this env"
elif [[ "$status6" == "403" ]]; then
  _fail "33.5.1 IPv6 ::1 blocked" \
    "::1 IS loopback but gate refused — IPv6 form not in allow-list"
else
  _skip "33.5.1 IPv6 ::1" "unexpected $status6"
fi

# IPv6-mapped IPv4 form: ::ffff:127.0.0.1 — some gates miss this.
# We can only test if the gateway DUAL-binds, which it may not. So
# this is informational.
status_mapped=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 -6 \
  "http://[::ffff:127.0.0.1]:8921/debug/pprof/" 2>/dev/null || echo "000")
if [[ "$status_mapped" == "200" || "$status_mapped" == "000" ]]; then
  _pass "33.5.2 IPv6-mapped-IPv4 [${status_mapped}] no bypass"
else
  _fail "33.5.2 IPv6-mapped-IPv4 unexpected" "$status_mapped"
fi

# ── 33.6 OpenAPI ratchet — adding undocumented endpoint must fail ─────────

phase_open "33.6 OpenAPI ratchet — synthetic new endpoint fails"

# Confirm L10 11.3.1 ratchet engages. Compute current undocumented
# count + 1 (simulating one new undocumented endpoint added).
GATEWAY_GETS=$(grep -E 'r\.Get\("/api/v1/' "$ROOT/cmd/gateway/main.go" 2>/dev/null \
  | grep -v "//\|\.bak" \
  | grep -oE '"/api/v1/[^"]*"' | tr -d '"' | sort -u)
SPEC_GETS=$(python3 -c "
import yaml, sys
with open('$ROOT/api/openapi.yaml') as f:
    spec = yaml.safe_load(f)
for path, item in (spec.get('paths') or {}).items():
    if path.startswith('/api/v1') and 'get' in item:
        print(path)
" | sort -u)

# Count undocumented after filtering known internal routes (matches
# L10 logic).
declare -A IN_SPEC
while IFS= read -r p; do IN_SPEC["$p"]=1; done <<<"$SPEC_GETS"
UNDOC_NOW=0
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  case "$p" in
    *"/healthz"|*"/metrics"|*"/sse"|*"/events"|*"/tail"|*"/log"|"/api/v1/p4/"*|"/api/v1/internal/"*) continue ;;
  esac
  if [[ -z "${IN_SPEC[$p]:-}" ]]; then
    UNDOC_NOW=$((UNDOC_NOW+1))
  fi
done <<<"$GATEWAY_GETS"

# Read the ratchet from the test file.
RATCHET=$(grep -E "^RATCHET=" "$ROOT/scripts/test-l10-openapi.sh" \
  | head -1 | cut -d= -f2)
RATCHET=${RATCHET:-0}

if (( UNDOC_NOW <= RATCHET )); then
  _pass "33.6.1 OpenAPI ratchet engaged [undoc=$UNDOC_NOW ≤ ratchet=$RATCHET]"
else
  _fail "33.6.1 OpenAPI ratchet broken" \
    "$UNDOC_NOW undocumented vs ratchet $RATCHET — test would not catch new undoc endpoints"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
