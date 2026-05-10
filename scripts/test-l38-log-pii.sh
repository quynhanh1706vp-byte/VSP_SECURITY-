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

CANARY_EMAIL="l38-pii-canary-$(date +%s%N | sha256sum | head -c 12)@vsp-pii-probe.test"

# Probe several handlers that might log request body.
curl -s -o /dev/null --max-time 5 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d "{\"email\":\"$CANARY_EMAIL\",\"password\":\"l38-NEVER-LOG-pwd\"}" \
  "$BASE/api/v1/auth/login" 2>/dev/null || true

curl -s -o /dev/null --max-time 5 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN" \
  -d "{\"email\":\"$CANARY_EMAIL\",\"reason\":\"l38 probe\"}" \
  "$BASE/api/v1/data/erasure" 2>/dev/null || true

# Give async log writers ~1.5s to flush.
sleep 2

# Refresh the log capture so we see what just got written.
if [[ -n "${LOG_FALLBACK:-}" && -r "$LOG_FALLBACK" ]]; then
  cp "$LOG_FALLBACK" "$LOG_TMP"
elif command -v journalctl &>/dev/null; then
  sudo journalctl -u vsp-gateway --no-pager -n 500 2>/dev/null > "$LOG_TMP" || true
fi

if grep -qF "$CANARY_EMAIL" "$LOG_TMP"; then
  HIT=$(grep -nF "$CANARY_EMAIL" "$LOG_TMP" | head -1)
  _fail "29.1.1 canary email leaked into log" "first hit: $HIT"
else
  _pass "29.1.1 canary email not in log [$(wc -l <"$LOG_TMP") lines scanned]"
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

# Luhn-shaped 13-19 digit sequences — credit cards.
CC_HITS=$(grep -oE '\b[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}\b' "$LOG_TMP" 2>/dev/null | head -1 || true)
if [[ -n "$CC_HITS" ]]; then
  _fail "29.4.1 credit-card-shaped digits in log" "$CC_HITS"
else
  _pass "29.4.1 no credit-card-shaped digits"
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
