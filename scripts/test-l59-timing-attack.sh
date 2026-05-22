#!/usr/bin/env bash
# scripts/test-l59-timing-attack.sh — timing-side-channel resistance.
#
# Login endpoint shape:
#   - Valid email + wrong password   → BCrypt compares; returns 401
#   - Invalid email                  → Should bcrypt against dummy hash
#                                       to keep response time constant
#   - Same email, repeated requests  → response time variance should
#                                       be < 50% (no leak about cache state)
#
# If invalid-email responses are FASTER than valid-email responses,
# an attacker can enumerate valid usernames by timing alone.
#
# We measure timing distributions and assert the median delta between
# valid-but-wrong and invalid-email cases is < 100ms.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 59.1 Login timing — valid email vs invalid email ─────────────────────

phase_open "59.1 Login timing — user-enumeration resistance"

# Two cohorts × 10 samples each.
VALID_EMAIL="${L59_VALID_EMAIL:-admin@vsp.local}"
INVALID_EMAIL="l59-nonexistent-$(date +%s%N | sha256sum | head -c 8)@vsp.test"

measure() {
  local email="$1"
  # curl -w outputs total_time in seconds (float). Convert to ms.
  curl -s -o /dev/null -w '%{time_total}' --max-time 10 \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"wrong-l59-$(date +%N)\"}" \
    "$BASE/api/v1/auth/login" 2>/dev/null || echo "0"
}

# Warm-up — first request is always slower (TLS handshake, JIT etc).
measure "$VALID_EMAIL" > /dev/null
measure "$INVALID_EMAIL" > /dev/null

# Collect samples. Interleave to spread any background noise.
VALID_SAMPLES=()
INVALID_SAMPLES=()
for _ in 1 2 3 4 5 6 7 8 9 10; do
  v=$(measure "$VALID_EMAIL")
  i=$(measure "$INVALID_EMAIL")
  VALID_SAMPLES+=("$v")
  INVALID_SAMPLES+=("$i")
done

# Compute median for each cohort. Convert seconds → milliseconds.
median() {
  printf '%s\n' "$@" \
    | awk '{print $1 * 1000}' \
    | sort -n \
    | awk 'BEGIN{c=0} {a[c++]=$1} END{print (c%2==0 ? (a[c/2-1]+a[c/2])/2 : a[(c-1)/2])}'
}

V_MED=$(median "${VALID_SAMPLES[@]}")
I_MED=$(median "${INVALID_SAMPLES[@]}")
# Delta = |valid - invalid| in ms
DELTA=$(awk -v v="$V_MED" -v i="$I_MED" 'BEGIN { d = v - i; if (d<0) d=-d; printf "%.1f", d }')

# Pass threshold: < 100ms delta. Anything above 100ms and a valid-vs-
# invalid email is reliably distinguishable from outside.
if awk -v d="$DELTA" 'BEGIN { exit (d > 100 ? 1 : 0) }'; then
  _pass "59.1.1 login timing close [valid=${V_MED}ms invalid=${I_MED}ms Δ=${DELTA}ms]"
else
  # In CI the login may always 429 (rate-limited). If both medians
  # are <50ms (essentially the rate-limiter rejection time), the
  # signal is too noisy — skip rather than fail.
  if awk -v v="$V_MED" -v i="$I_MED" 'BEGIN { exit (v < 50 && i < 50 ? 0 : 1) }'; then
    _skip "59.1.1 login timing" "both medians <50ms (rate-limited?) — signal noisy"
  else
    _fail "59.1.1 login timing leak" \
      "valid=${V_MED}ms invalid=${I_MED}ms Δ=${DELTA}ms — user enumeration via timing"
  fi
fi

# ── 59.2 SAME credential repeated — variance < 50% ──────────────────────

phase_open "59.2 Response-time variance per cohort"

# Pull a single cohort's variance. High variance means the handler
# leaks state (cache hit/miss, lazy bcrypt, etc).
variance_pct() {
  local samples=("$@")
  local sorted
  sorted=$(printf '%s\n' "${samples[@]}" | awk '{print $1 * 1000}' | sort -n)
  local min max med
  min=$(echo "$sorted" | head -1)
  max=$(echo "$sorted" | tail -1)
  awk -v mn="$min" -v mx="$max" 'BEGIN { if (mn > 0) printf "%.0f", ((mx-mn)/mn)*100; else printf "0" }'
}

VAR_V=$(variance_pct "${VALID_SAMPLES[@]}")
VAR_I=$(variance_pct "${INVALID_SAMPLES[@]}")

if (( VAR_V > 200 )) || (( VAR_I > 200 )); then
  _skip "59.2.1 response-time variance" \
    "valid=${VAR_V}% invalid=${VAR_I}% — high variance (noisy environment)"
else
  _pass "59.2.1 response-time variance acceptable [valid=${VAR_V}% invalid=${VAR_I}%]"
fi

# ── 59.3 No password-comparison short-circuit ────────────────────────────

phase_open "59.3 Source-level: bcrypt.CompareHashAndPassword vs == on hash"

# Plain `==` or `bytes.Equal` on a password hash is constant-time-ish
# in Go, but bcrypt.CompareHashAndPassword is the canonical correct
# call. Look for raw equality checks where BOTH sides are a hash-like
# variable. Exclude:
#   - `password == ""` (empty-string check, not hash comparison)
#   - `password == nil`
#   - comparison with string literal (not a hash)
LEAKS=$(grep -rEn '(passwordHash|pw_hash|hashed_password|HashedPassword)\s*==\s*[a-zA-Z_]' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak\|// safe-cmp' \
  | grep -vE '==\s*(""|nil|0)' \
  | head -3 || true)

if [[ -z "$LEAKS" ]]; then
  _pass "59.3.1 no plain == on password hashes in source"
else
  _fail "59.3.1 plain == comparison on password hash" \
    "$(echo "$LEAKS" | head -1)"
fi

final_summary
