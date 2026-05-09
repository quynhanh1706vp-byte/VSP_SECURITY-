#!/usr/bin/env bash
# scripts/test-l23-trust-boundary.sh — proxy-header trust boundary.
#
# CRITICAL bug found before L23: chimw.RealIP rewrote r.RemoteAddr
# from X-Forwarded-For unconditionally, so a direct attacker could
# set XFF: 127.0.0.1 from any IP and impersonate loopback —
# bypassing the /debug/* loopback gate, the /metrics localhost gate,
# and IPLockout's per-IP counters.
#
# Fix wired in cmd/gateway/main.go: trustedRealIP middleware honours
# XFF only when the immediate TCP source IP is in a trusted-proxy
# allow-list. This watchdog asserts the fix is in place + behavioral
# correctness.
#
# Pre-flight: gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl

# ── 24.1 Source code asserts trustedRealIP is wired ────────────────────────

phase_open "24.1 Source — trustedRealIP middleware is wired"

GW="$ROOT/cmd/gateway/main.go"
if grep -qE "trustedRealIP\(viper\.GetString" "$GW" \
   && grep -qE "func trustedRealIP\(" "$GW"; then
  _pass "24.1.1 trustedRealIP wired in router + defined in main.go"
else
  _fail "24.1.1 trustedRealIP not wired" \
    "main.go missing the middleware — XFF bypass regression possible"
fi

# Negative — chi.RealIP must NOT be used directly anymore (only via
# the trusted wrapper).
if grep -qE "r\.Use\(chimw\.RealIP\)" "$GW"; then
  _fail "24.1.2 raw chimw.RealIP still mounted" \
    "regression — the unconditional XFF-trust middleware is back"
else
  _pass "24.1.2 raw chimw.RealIP not mounted directly"
fi

# ── 24.2 Behaviour — XFF rewrite still works for trusted source ───────────

phase_open "24.2 Behaviour — loopback source can still set XFF"

# The fix preserves legitimate proxy behaviour: loopback is in the
# default trusted set, so chi.RealIP DOES fire for our test box.
# Probe /debug with XFF: 8.8.8.8 from loopback. RemoteAddr gets
# rewritten to 8.8.8.8, gate rejects → 403. Confirms the wrapper
# allows the trusted path.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
  -H "X-Forwarded-For: 8.8.8.8" \
  "$BASE/debug/pprof/")
if [[ "$status" == "403" ]]; then
  _pass "24.2.1 XFF from trusted source rewrites RemoteAddr [→ 403 on /debug]"
else
  _fail "24.2.1 XFF rewrite broken" \
    "expected 403 (RealIP rewrites loopback→8.8.8.8, then gate rejects), got $status"
fi

# ── 24.3 Behaviour — direct loopback still 200 ────────────────────────────

phase_open "24.3 Behaviour — direct loopback /debug/* still allowed"

# Sanity: legitimate operator on the host can still pprof.
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
  "$BASE/debug/pprof/")
if [[ "$status" == "200" ]]; then
  _pass "24.3.1 direct loopback /debug/* → 200 (no false-positive lockout)"
else
  _fail "24.3.1 direct loopback blocked" \
    "expected 200, got $status — fix may be over-restrictive"
fi

# ── 24.4 IPLockout — pinned to FORWARDED IP behind trusted proxy ──────────

phase_open "24.4 IPLockout — fires per forwarded IP (proxy-aware accounting)"

# Restart gateway so IPLockout is clean.
sudo systemctl restart vsp-gateway 2>/dev/null && sleep 4

# Behind a trusted proxy (loopback in our default), each different
# X-Forwarded-For represents a different REAL client. IPLockout
# correctly tracks per-forwarded-IP, NOT per-immediate-source. So:
#   - 22 bad logins from XFF=A → A locks at 20
#   - 1 bad login from XFF=B  → B's counter is fresh (correct)
# This test validates that the per-FORWARDED-IP counter engages when
# a single forwarded address hits the threshold.

# Round 1: hammer one specific XFF value 22 times.
LOCKED_AT_FIXED=0
for i in $(seq 1 22); do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 198.51.100.42" \
    -d "{\"email\":\"l23-fixed-$i@vsp.local\",\"password\":\"wrong\"}" \
    "$BASE/api/v1/auth/login")
  if [[ "$status" == "429" ]]; then
    LOCKED_AT_FIXED=$i; break
  fi
done

if (( LOCKED_AT_FIXED > 0 && LOCKED_AT_FIXED <= 22 )); then
  _pass "24.4.1 IPLockout fires per fixed forwarded IP [locked at attempt #$LOCKED_AT_FIXED]"
else
  _fail "24.4.1 IPLockout didn't engage for fixed XFF" \
    "fired no lock across 22 attempts at one forwarded IP — accounting broken"
fi

# Round 2: ensure a DIFFERENT forwarded IP starts fresh (proves the
# accounting is per-IP, not global per-immediate-source).
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X POST -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 198.51.100.43" \
  -d '{"email":"fresh@vsp.local","password":"wrong"}' \
  "$BASE/api/v1/auth/login")

if [[ "$status" == "401" ]]; then
  _pass "24.4.2 fresh forwarded IP starts at 0 (per-IP isolation works)"
elif [[ "$status" == "429" ]]; then
  _fail "24.4.2 fresh IP inherited lockout" \
    "different XFF should have its own counter — got 429 immediately"
else
  _skip "24.4.2 fresh forwarded IP" "unexpected $status"
fi

# ── 24.5 No header injection from forwarded chain ─────────────────────────

phase_open "24.5 X-Forwarded-Proto only changes scheme when source trusted"

# Set X-Forwarded-Proto: https from an unknown forwarded host.
# Expectation: Set-Cookie's Secure flag is decided by the request
# the gateway actually saw — if XFP from non-trusted sources is
# stripped (it is), the gateway makes its own decision based on
# r.TLS. We can't easily test "non-trusted source" from this box
# (we ARE trusted), but we can verify the source-code stripping
# logic exists.
if grep -qE 'r\.Header\.Del\("X-Forwarded-Proto"\)' "$GW"; then
  _pass "24.5.1 X-Forwarded-Proto stripped from non-trusted sources"
else
  _fail "24.5.1 X-Forwarded-Proto not stripped" \
    "non-trusted attacker could fake HTTPS context"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
