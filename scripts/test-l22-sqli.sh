#!/usr/bin/env bash
# scripts/test-l22-sqli.sh — SQL-injection active probe.
#
# Go's pgx driver uses parameterised queries by default, so simple
# in-band SQLi is structurally hard. Real risk areas:
#
#   - Dynamic ORDER BY (column name can't be parameterised)
#   - Dynamic table/schema names (fmt.Sprintf into query string)
#   - LIKE patterns with user-supplied substrings
#   - JSON Path / jsonb_path_query expressions
#   - Custom string-concat queries that escaped review
#
# This level fires classic SQLi payloads at every GET endpoint that
# accepts a query parameter, then asserts:
#   - 5xx response body never contains SQL state markers
#   - Boolean-condition payloads never produce different result sets
#     (boolean-blind SQLi indicator)
#   - Time-based payloads don't hang the request beyond max-time
#
# Pre-flight: $JWT_SECRET, $DB_DSN, gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local now exp h p s
  now=$(date +%s); exp=$((now + 3600))
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  p=$(printf '{"sub":"l22@vsp.local","email":"l22@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
    "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$h" "$p" "$s"
}
ADMIN=$(mint_jwt)

# ── 23.1 In-band SQLi — error-based ───────────────────────────────────────

phase_open "23.1 In-band — error-based SQLi probe"

# Payloads aimed at producing a SQL-state error in the response body.
# We hit known query-param endpoints with each payload and grep the
# response for state markers.
declare -a PAYLOADS=(
  "'"
  "''"
  "1' OR '1'='1"
  "1\" OR \"1\"=\"1"
  "1; DROP TABLE users--"
  "' UNION SELECT NULL--"
  "%27%20OR%201%3D1--"
  "abc' AND SLEEP(0)--"
)
declare -a TARGETS=(
  "/api/v1/vsp/findings?severity="
  "/api/v1/vsp/findings?tool="
  "/api/v1/vsp/findings?q="
  "/api/v1/audit/log?action="
  "/api/v1/vsp/runs?limit="
)

LEAKS=()
PROBES=0
for url in "${TARGETS[@]}"; do
  for payload in "${PAYLOADS[@]}"; do
    PROBES=$((PROBES+1))
    full="$url$(printf '%s' "$payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g')"
    body=$(mktemp)
    status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
      -H "Authorization: Bearer $ADMIN" "$BASE$full")
    # Look for SQL-state markers in the response body. RED FLAGS:
    #   - SQLSTATE codes
    #   - "syntax error at or near"
    #   - column / relation names from internal schema
    if grep -qiE "SQLSTATE|syntax error|invalid input syntax|column \"[a-z_]+\" does not exist|relation \"[a-z_]+\" does not exist|pg_catalog|pgx\.[A-Z]" "$body" 2>/dev/null; then
      hit=$(grep -iE "SQLSTATE|syntax error|invalid input|relation \"|column \"|pgx\." "$body" | head -1 | head -c 120)
      LEAKS+=("$url payload='$payload' status=$status: $hit")
    fi
    rm -f "$body"
  done
done

if (( ${#LEAKS[@]} == 0 )); then
  _pass "23.1.1 no SQL-state leakage across $PROBES probes"
else
  printf -v LIST '%s | ' "${LEAKS[@]:0:3}"
  _fail "23.1.1 SQL state in response" "${LIST%| }"
fi

# ── 23.2 Boolean-blind — same-result invariant ─────────────────────────────

phase_open "23.2 Boolean-blind — payload doesn't change row count"

# Pull the baseline count for /vsp/findings, then probe with a TRUE
# tautology and a FALSE tautology. If parameterisation is correct,
# both should return the same count (the payload doesn't reach SQL).
BASELINE=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/vsp/findings?limit=10" | jq -r '.findings | length' 2>/dev/null)

TRUE_HITS=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/vsp/findings?limit=10&severity=CRITICAL%27%20OR%20%271%27%3D%271" \
  | jq -r '.findings | length' 2>/dev/null)

FALSE_HITS=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/vsp/findings?limit=10&severity=CRITICAL%27%20AND%20%271%27%3D%272" \
  | jq -r '.findings | length' 2>/dev/null)

if [[ "$TRUE_HITS" == "$FALSE_HITS" ]]; then
  _pass "23.2.1 boolean-tautology payloads don't change result set [both=$TRUE_HITS]"
else
  _fail "23.2.1 boolean-blind SQLi" \
    "true-payload returned $TRUE_HITS rows, false returned $FALSE_HITS — payload is reaching SQL"
fi

# ── 23.3 Time-based — no DB sleep on payload ──────────────────────────────

phase_open "23.3 Time-based — pg_sleep payload doesn't actually sleep"

START=$(date +%s%N)
curl -s -o /dev/null --max-time 5 -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/vsp/findings?severity=%27%3B%20SELECT%20pg_sleep%283%29--"
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))

if (( ELAPSED_MS < 2500 )); then
  _pass "23.3.1 pg_sleep(3) payload didn't sleep [${ELAPSED_MS}ms]"
else
  _fail "23.3.1 pg_sleep payload effective" \
    "request took ${ELAPSED_MS}ms — payload is reaching DB and slept"
fi

# ── 23.4 ORDER BY injection — column-name can't be parameterised ──────────

phase_open "23.4 ORDER BY — column-name allow-listed, not user-controlled"

# Endpoints that accept ?sort= or ?order= are highest-risk because
# column names literally can't be parameterised. Probe with an
# obviously invalid column name; expected: 400 (allow-list rejects)
# or 200 with default sort. Anything else = column passed to SQL.
for url in \
  "/api/v1/vsp/findings?sort=NONEXISTENT_COLUMN_X" \
  "/api/v1/vsp/findings?order=NONEXISTENT_COLUMN_X" \
  "/api/v1/vsp/runs?sort=NONEXISTENT_COLUMN_X"; do
  status=$(curl -s -o /tmp/l22_o.json -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE$url")
  body=$(head -c 200 /tmp/l22_o.json 2>/dev/null)
  if [[ "$status" == "200" ]]; then
    # 200 either means: (a) param was ignored (handler doesn't read it),
    # or (b) handler defaulted to a known column. Both are safe.
    _pass "23.4 $url ignored unknown column [200]"
  elif [[ "$status" == "400" ]]; then
    _pass "23.4 $url rejected unknown column [400]"
  elif [[ "$status" =~ ^5 ]]; then
    if echo "$body" | grep -qiE "column.*does not exist|relation"; then
      _fail "23.4 $url SQL leaked through ORDER BY" "$body"
    else
      _fail "23.4 $url unexpected 5xx" "$status"
    fi
  fi
done
rm -f /tmp/l22_o.json

# ── final ──────────────────────────────────────────────────────────────────

final_summary
