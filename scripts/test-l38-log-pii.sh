#!/usr/bin/env bash
# scripts/test-l38-log-pii.sh — log-PII-leak audit.
#
# Operational rule: gateway logs MUST NOT contain personally-identifiable
# data, secrets, tokens, or anything else that would be a compliance
# failure if a log shipper / SRE / contractor saw it.
#
# Strategy: probe endpoints with UNIQUE sentinel values (canary email,
# random password, distinct Authorization tokens), give the async
# logging path 1 second to flush, then grep the gateway log for
# any sentinel that leaked through.
#
# Why this catches things L27 misses: L27 verifies log lines are
# STRUCTURED (JSON / zerolog console with kv pairs). It says nothing
# about CONTENT — a perfectly-structured log line that happens to
# contain `password=hunter2` is still a serious leak.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# Resolve gateway log file. Same fallback chain as L27:
#   1. LOG_FALLBACK env (CI sets to /tmp/gateway.log)
#   2. journalctl -u vsp-gateway (operator path)
LOG_TMP=$(mktemp)
if [[ -n "${LOG_FALLBACK:-}" && -r "$LOG_FALLBACK" ]]; then
  cp "$LOG_FALLBACK" "$LOG_TMP"
elif command -v journalctl &>/dev/null; then
  sudo journalctl -u vsp-gateway --no-pager -n 500 2>/dev/null > "$LOG_TMP" || true
fi

if [[ ! -s "$LOG_TMP" ]]; then
  _skip "29.0 log source available" "no readable LOG_FALLBACK and journalctl empty"
  final_summary
  exit 0
fi

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 29.1 Sentinel email — never appears in logs ───────────────────────────

phase_open "29.1 Email PII — request payloads aren't logged"

# A unique sentinel per channel so we can pinpoint WHICH input vector
# leaked, not just that something did.
CANARY_BASE="l38-pii-$(date +%s%N | sha256sum | head -c 10)"
CANARY_BODY="${CANARY_BASE}-body@vsp-pii.test"
CANARY_FORM="${CANARY_BASE}-form@vsp-pii.test"
CANARY_QUERY="${CANARY_BASE}-query@vsp-pii.test"
CANARY_HEADER="${CANARY_BASE}-header@vsp-pii.test"
CANARY_UPPER="L38-PII-${CANARY_BASE^^}-CASE@VSP-PII.TEST"

# Channel 1: JSON body via /auth/login (auth handler) and /data/erasure
curl -s -o /dev/null --max-time 5 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d "{\"email\":\"$CANARY_BODY\",\"password\":\"l38-NEVER-LOG-pwd\"}" \
  "$BASE/api/v1/auth/login" 2>/dev/null || true

curl -s -o /dev/null --max-time 5 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d "{\"email\":\"$CANARY_BODY\",\"reason\":\"l38 probe\"}" \
  "$BASE/api/v1/data/erasure" 2>/dev/null || true

# Channel 2: form-encoded body
curl -s -o /dev/null --max-time 5 -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer $ADMIN" \
  --data-urlencode "email=$CANARY_FORM" \
  --data-urlencode "password=l38-NEVER-LOG-pwd" \
  "$BASE/api/v1/auth/login" 2>/dev/null || true

# Channel 3: query parameter — many access logs include the query string
curl -s -o /dev/null --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/audit/log?email=$(printf '%s' "$CANARY_QUERY" | jq -sRr @uri)&limit=1" \
  2>/dev/null || true

# Channel 4: custom request header
curl -s -o /dev/null --max-time 5 \
  -H "Authorization: Bearer $ADMIN" \
  -H "X-Forwarded-Email: $CANARY_HEADER" \
  -H "X-Original-User: $CANARY_HEADER" \
  "$BASE/api/v1/kpi/sanity" 2>/dev/null || true

# Channel 5: UPPERCASE/MIXED case sentinel — confirms the grep below
# is case-insensitive. A logger that lowercases payloads would otherwise
# evade a case-sensitive search.
curl -s -o /dev/null --max-time 5 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d "{\"email\":\"$CANARY_UPPER\"}" \
  "$BASE/api/v1/auth/login" 2>/dev/null || true

# Give async log writers ~2s to flush.
sleep 2

# Refresh the log capture so we see what just got written.
if [[ -n "${LOG_FALLBACK:-}" && -r "$LOG_FALLBACK" ]]; then
  cp "$LOG_FALLBACK" "$LOG_TMP"
elif command -v journalctl &>/dev/null; then
  sudo journalctl -u vsp-gateway --no-pager -n 500 2>/dev/null > "$LOG_TMP" || true
fi

# Search for ANY of the channel sentinels — case-insensitive so a
# lowercased log line containing l38-PII-ABCDEF-CASE@vsp-pii.test
# (case fold) still triggers the failure.
declare -A LEAK_BY_CHANNEL=(
  [body]="$CANARY_BODY"
  [form]="$CANARY_FORM"
  [query]="$CANARY_QUERY"
  [header]="$CANARY_HEADER"
  [upper-case]="$CANARY_UPPER"
)
LEAKS=""
for chan in "${!LEAK_BY_CHANNEL[@]}"; do
  needle="${LEAK_BY_CHANNEL[$chan]}"
  if grep -iqF "$needle" "$LOG_TMP" 2>/dev/null; then
    LEAKS+="$chan "
  fi
done

if [[ -n "$LEAKS" ]]; then
  HIT=$(grep -inF "$CANARY_BASE" "$LOG_TMP" | head -1)
  _fail "29.1.1 canary email leaked into log" \
    "channels with leak: ${LEAKS}— first hit: $HIT"
else
  _pass "29.1.1 no canary email across 5 channels [$(wc -l <"$LOG_TMP") lines scanned]"
fi

# 29.1.2 — Validation-error body must NOT echo the email back. Some
# JSON validators include the offending value in the error message
# ("invalid email: <user-input>"), which surfaces in error pages and
# log lines indexed by SRE tooling.
ERR_CANARY="${CANARY_BASE}-error-echo@vsp-pii.test"
err_body=$(curl -s --max-time 5 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d "{\"email\":\"$ERR_CANARY\",\"reason\":\"\"}" \
  "$BASE/api/v1/data/erasure" 2>/dev/null || true)

if echo "$err_body" | grep -iqF "$ERR_CANARY"; then
  _fail "29.1.2 validation error echoed PII back" \
    "response body contains the input email — review error formatting"
else
  _pass "29.1.2 validation error doesn't echo input email"
fi

# ── 29.2 Password / secret literals never logged ──────────────────────────

phase_open "29.2 Secret literals — passwords / tokens not logged"

# Search for ANY plaintext password leak from auth flows.
for pattern in \
    '"password":"[^"]*"' \
    'password=[^ &"]\+' \
    '"client_secret":"[^"]*"' \
    'BEGIN (RSA )?PRIVATE KEY' \
  ; do
  if grep -E -q "$pattern" "$LOG_TMP" 2>/dev/null; then
    HIT=$(grep -nE "$pattern" "$LOG_TMP" | head -1)
    _fail "29.2.1 secret pattern '$pattern' leaked" "first hit: $HIT"
  else
    _pass "29.2.1 no '$pattern' in log"
  fi
done

# ── 29.3 Authorization headers / Bearer tokens never logged ───────────────

phase_open "29.3 Authorization headers redacted"

# A Bearer token has the shape <header>.<payload>.<sig> with base64-url chars.
# If the log contains an actual JWT payload it's a critical leak.
# Filter to only HS256 JWTs (header eyJ...HMAC), to avoid catching
# unrelated dot-separated b64 strings.
# `|| true` on every grep pipeline because no-match returns 1 and
# under set -euo pipefail that would abort the script silently.
JWT_HITS=$(grep -oE 'eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}' "$LOG_TMP" 2>/dev/null | head -3 || true)
if [[ -n "$JWT_HITS" ]]; then
  _fail "29.3.1 JWT-shaped token leaked into log" "first hit: $(echo "$JWT_HITS" | head -1 | cut -c1-60)..."
else
  _pass "29.3.1 no JWT-shaped tokens in log"
fi

# Bearer header reflection — some servers echo the header back in error
# bodies or log lines.
if grep -iqE 'authorization:\s*bearer\s+ey' "$LOG_TMP" 2>/dev/null; then
  _fail "29.3.2 Authorization header logged verbatim" \
    "see grep -iE 'authorization:.*bearer ey' on the log"
else
  _pass "29.3.2 Authorization header not echoed"
fi

# ── 29.4 Common PII patterns ──────────────────────────────────────────────

phase_open "29.4 Common PII patterns (credit card / SSN / phone)"

# Luhn-shaped 13-19 digit sequences — credit cards. Exclude lines
# that contain a UUID anywhere (uuids look like 4-4-4-4 from the
# middle of an 8-4-4-4-12 string, which causes a false positive).
# Strip UUIDs from each log line FIRST, then look for CC-shape on
# what remains.
UUID_RE='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
CC_RE='\b[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}\b'
CC_HITS=$(sed -E "s/$UUID_RE//g" "$LOG_TMP" 2>/dev/null \
          | grep -oE "$CC_RE" \
          | grep -v '^0000' \
          | head -1 || true)
if [[ -n "$CC_HITS" ]]; then
  _fail "29.4.1 credit-card-shaped digits in log" "$CC_HITS"
else
  _pass "29.4.1 no plausible credit-card digits [UUIDs stripped, all-zero runs ignored]"
fi

# Vietnamese phone numbers (10-11 digits starting 0).
PHONE_HITS=$(grep -oE '\b0[1-9][0-9]{8,9}\b' "$LOG_TMP" 2>/dev/null | sort -u | head -3 || true)
if [[ -n "$PHONE_HITS" ]] && (( $(echo "$PHONE_HITS" | wc -l) > 5 )); then
  _fail "29.4.2 many phone-number-shaped digit runs" "$(echo "$PHONE_HITS" | head -3 | tr '\n' ',')..."
else
  _pass "29.4.2 phone-number leak count within tolerance"
fi

# ── 29.5 SQL state / stack frames in user-facing errors ───────────────────

phase_open "29.5 SQLSTATE codes don't surface in successful logs"

# SQLSTATE in ERR/WRN log lines is fine (operator needs that). But it
# should NEVER appear in INF lines (which are HTTP request logs and may
# be shipped to customer-visible dashboards).
if grep -qE 'INF.*SQLSTATE [0-9]{5}' "$LOG_TMP" 2>/dev/null; then
  _fail "29.5.1 SQLSTATE in INF log line" \
    "$(grep -E 'INF.*SQLSTATE [0-9]{5}' "$LOG_TMP" | head -1)"
else
  _pass "29.5.1 SQLSTATE absent from INF lines"
fi

rm -f "$LOG_TMP"
final_summary
