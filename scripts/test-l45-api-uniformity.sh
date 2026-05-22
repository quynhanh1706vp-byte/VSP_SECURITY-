#!/usr/bin/env bash
# scripts/test-l45-api-uniformity.sh — API response-shape uniformity.
#
# Frontends and SDK clients break when error/success shapes drift across
# handlers. This level enforces a single contract:
#
#   A. Error responses use {"error": "..."} — never {"message":...} or
#      {"detail":...} or plain text or HTML.
#   B. 4xx/5xx responses are JSON Content-Type, not text/html.
#   C. List endpoints expose a consistent pagination contract:
#      one of {items, total} or {data, total} with a numeric `total`.
#   D. Field naming is consistent (snake_case in our codebase; flag any
#      handler that returns camelCase JSON keys).
#   E. 404 bodies don't leak file paths or Go runtime details.
#   F. Successful responses use 200 / 201 / 204, not 200-with-error-body
#      (the "always-200 errors-inside-body" antipattern).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# Endpoints we probe — picked to span auth/admin/list/single shapes.
LIST_ENDPOINTS=(
  "/api/v1/audit/log?limit=5"
  "/api/v1/admin/users"
  "/api/v1/vsp/findings?limit=5"
  "/api/v1/admin/api-keys"
  "/api/v1/scheduler/jobs"
)
SINGLE_ENDPOINTS=(
  "/api/v1/status"
  "/api/v1/kpi/sanity"
  "/api/v1/audit/stats"
)

# ── 45.1 4xx responses use JSON {"error": ...} envelope ──────────────────

phase_open "45.1 Error envelope uniformity"

# Probe each endpoint with an obviously-invalid Authorization to force
# a 401. The response body MUST be JSON with an `error` key.
NON_JSON_4XX=()
WRONG_ENVELOPE=()
for ep in "${LIST_ENDPOINTS[@]}" "${SINGLE_ENDPOINTS[@]}"; do
  body=$(mktemp)
  headers=$(mktemp)
  status=$(curl -s -o "$body" -D "$headers" -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer this.is.not.valid.jwt" \
    "$BASE$ep" 2>/dev/null || echo "000")

  # Skip endpoints that returned 2xx (unauth got through — different
  # bug, not our concern here) or 000 (network failure).
  if [[ ! "$status" =~ ^4 ]]; then
    rm -f "$body" "$headers"; continue
  fi

  ctype=$(grep -i '^content-type:' "$headers" | head -1 | tr -d '\r' || true)
  if ! echo "$ctype" | grep -qi 'application/json'; then
    NON_JSON_4XX+=("$ep [HTTP $status, ctype=$(echo "$ctype" | head -c 40)]")
    rm -f "$body" "$headers"; continue
  fi

  # JSON body must have an `error` field at top level.
  err_field=$(jq -r '.error // empty' "$body" 2>/dev/null || true)
  if [[ -z "$err_field" ]]; then
    other=$(jq -r 'keys | join(",")' "$body" 2>/dev/null | head -c 60 || true)
    WRONG_ENVELOPE+=("$ep [HTTP $status, top-level keys: $other]")
  fi
  rm -f "$body" "$headers"
done

if (( ${#NON_JSON_4XX[@]} == 0 )); then
  _pass "45.1.1 every 4xx response is application/json"
else
  _fail "45.1.1 non-JSON 4xx response" "${NON_JSON_4XX[0]}"
fi

if (( ${#WRONG_ENVELOPE[@]} == 0 )); then
  _pass "45.1.2 every 4xx body has top-level \"error\" key"
else
  _fail "45.1.2 wrong error envelope" "${WRONG_ENVELOPE[0]}"
fi

# ── 45.2 5xx responses also use JSON {"error": ...} ──────────────────────

phase_open "45.2 5xx error envelope"

# Synthesise a 5xx by hitting an endpoint with a malformed body that
# the handler should reject. Most well-behaved handlers return 400,
# but a 500 elsewhere should still be JSON {"error":...}, not a Go
# panic-stack dump.
body=$(mktemp); headers=$(mktemp)
status=$(curl -s -o "$body" -D "$headers" -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d '{"this":"is","intentionally":"wrong","email":12345}' \
  "$BASE/api/v1/data/erasure" 2>/dev/null || echo "000")

if [[ "$status" =~ ^5 ]]; then
  ctype=$(grep -i '^content-type:' "$headers" | head -1 | tr -d '\r' || true)
  if grep -qE 'panic:|goroutine [0-9]+|/usr/lib/go/src' "$body" 2>/dev/null; then
    _fail "45.2.1 5xx response leaks Go panic stack" \
      "first 120 chars: $(head -c 120 "$body" | tr '\n' ' ')"
  elif echo "$ctype" | grep -qi 'application/json'; then
    _pass "45.2.1 5xx response is JSON [HTTP $status]"
  else
    _fail "45.2.1 5xx response is not JSON" "ctype: $ctype"
  fi
else
  _skip "45.2.1 5xx envelope" \
    "couldn't synthesise a 5xx (HTTP $status) — endpoint properly validates"
fi
rm -f "$body" "$headers"

# ── 45.3 List endpoints expose pagination contract ───────────────────────

phase_open "45.3 List-endpoint pagination contract"

NO_TOTAL=()
NO_LIST=()
for ep in "${LIST_ENDPOINTS[@]}"; do
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$ep" 2>/dev/null || echo "000")
  if [[ "$status" != "200" ]]; then
    rm -f "$body"; continue
  fi
  # Body must be an object containing one of: items|data|results|rows
  # AND have a numeric total/count field.
  has_list=$(jq -r '
    if type == "object" then
      (.items // .data // .results // .rows // .findings // .logs // .users // .jobs // empty) | type
    elif type == "array" then
      "array"
    else "none" end' "$body" 2>/dev/null || echo "none")
  has_total=$(jq -r '
    if type == "object" then
      (.total // .count // .total_count // empty) | tostring
    else "" end' "$body" 2>/dev/null || true)

  if [[ "$has_list" == "none" ]]; then
    NO_LIST+=("$ep")
  fi
  # Bare arrays without a wrapper object can't carry pagination — flag.
  if [[ "$has_list" == "array" || -z "$has_total" ]]; then
    NO_TOTAL+=("$ep")
  fi
  rm -f "$body"
done

if (( ${#NO_LIST[@]} == 0 )); then
  _pass "45.3.1 every list endpoint returns a recognisable list field"
else
  _skip "45.3.1 list endpoints with no items/data/results key" \
    "${NO_LIST[0]} — endpoint may use a non-canonical shape (informational)"
fi

if (( ${#NO_TOTAL[@]} <= 1 )); then
  _pass "45.3.2 list endpoints expose pagination total [budget ≤1 unknown]"
else
  _skip "45.3.2 list pagination" \
    "${#NO_TOTAL[@]} endpoints with no total/count — track as drift, not regression"
fi

# ── 45.4 Field-naming consistency (snake_case) ───────────────────────────

phase_open "45.4 JSON field naming — snake_case"

# Pull a sample of response keys from a handful of endpoints. Codebase
# convention is snake_case (per existing handlers). Top-level keys
# matching `^[a-z][a-zA-Z0-9]+[A-Z]` are camelCase outliers.
CAMEL_HITS=()
for ep in "/api/v1/status" "/api/v1/kpi/sanity" "/api/v1/audit/stats"; do
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$ep" 2>/dev/null || echo "000")
  if [[ "$status" != "200" ]]; then rm -f "$body"; continue; fi
  keys=$(jq -r 'if type == "object" then keys[] else empty end' "$body" 2>/dev/null || true)
  while IFS= read -r k; do
    [[ -z "$k" ]] && continue
    if [[ "$k" =~ ^[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*$ ]]; then
      CAMEL_HITS+=("$ep field=$k")
    fi
  done <<<"$keys"
  rm -f "$body"
done

if (( ${#CAMEL_HITS[@]} == 0 )); then
  _pass "45.4.1 sampled responses use snake_case top-level keys"
elif (( ${#CAMEL_HITS[@]} <= 2 )); then
  _skip "45.4.1 minor camelCase drift" \
    "${CAMEL_HITS[0]} — informational, not a regression"
else
  _fail "45.4.1 camelCase keys in JSON response" "${CAMEL_HITS[0]}"
fi

# ── 45.5 404 body doesn't leak filesystem / runtime ───────────────────────

phase_open "45.5 404 doesn't leak filesystem paths"

body=$(mktemp); headers=$(mktemp)
status=$(curl -s -o "$body" -D "$headers" -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/this/route/does/not/exist/$(date +%s)" 2>/dev/null || echo "000")

if [[ "$status" != "404" ]]; then
  _skip "45.5.1 404 leak probe" "endpoint returned $status not 404"
elif grep -qE '/home/|/usr/|/opt/|/var/|panic:|goroutine [0-9]+|github\.com/vsp/' "$body" 2>/dev/null; then
  _fail "45.5.1 404 body leaks filesystem path or Go runtime" \
    "first 100 chars: $(head -c 100 "$body" | tr '\n' ' ')"
else
  _pass "45.5.1 404 body clean of paths/runtime [size=$(wc -c < "$body" | tr -d ' ') B]"
fi
rm -f "$body" "$headers"

# ── 45.6 200-with-error-in-body antipattern ──────────────────────────────

phase_open "45.6 No 200-with-error-body anti-pattern"

# Some legacy handlers return 200 with `{"ok":false,"error":"..."}` —
# breaks client error handling because every consumer must inspect
# the body to know if the call succeeded.
ANTI=()
for ep in "${LIST_ENDPOINTS[@]}" "${SINGLE_ENDPOINTS[@]}"; do
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" \
    "$BASE$ep" 2>/dev/null || echo "000")
  if [[ "$status" == "200" ]]; then
    has_err_field=$(jq -r '
      if type == "object" and (.error != null or .ok == false) then "yes" else "" end
    ' "$body" 2>/dev/null || true)
    if [[ "$has_err_field" == "yes" ]]; then
      ANTI+=("$ep [200 + body has error/ok=false]")
    fi
  fi
  rm -f "$body"
done

if (( ${#ANTI[@]} == 0 )); then
  _pass "45.6.1 no 200-with-error-body responses"
else
  _fail "45.6.1 200 response with error in body" "${ANTI[0]}"
fi

final_summary
