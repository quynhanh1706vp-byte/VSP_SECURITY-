#!/usr/bin/env bash
# scripts/test-l70-http-smuggling.sh — HTTP request smuggling.
#
# Why this matters: a smuggled request bypasses every middleware in
# front of the second-request handler — auth, RLS, CSRF, audit. Go's
# net/http closes most CL/TE doors at parse time, but the gateway's
# middleware stack and reverse-proxy quirks can still surface drift:
#
#   • Conflicting Content-Length + Transfer-Encoding headers
#   • Multiple Content-Length headers
#   • TE: chunked with malformed chunk sizes
#   • Oversized headers / continuation lines (RFC 7230 §3.2.4 obs-fold)
#   • Missing Host header on HTTP/1.1 (RFC 7230 §5.4)
#
# The probe sends raw HTTP via /dev/tcp because curl normalises away
# many of these patterns. We assert the gateway returns 400 (proper
# reject) rather than 200 (smuggled through) or 500 (panic).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# Extract host:port from $BASE
HOST=$(echo "$BASE" | sed -E 's|https?://||; s|/.*||')
HOSTNAME="${HOST%:*}"
PORT="${HOST##*:}"

# raw_probe NAME RAW_REQUEST EXPECT_PATTERN
# Sends the literal bytes (with \r\n line endings) and checks the
# status line against EXPECT_PATTERN (regex). Use this for control
# sequences curl would normalise away.
raw_probe() {
  local name="$1" raw="$2" want="$3"
  local resp status
  if ! resp=$( (printf "%b" "$raw"; sleep 0.3) | timeout 5 bash -c "exec 3<>/dev/tcp/$HOSTNAME/$PORT; cat >&3; cat <&3" 2>/dev/null ); then
    _skip "$name" "raw socket probe failed (gateway unreachable?)"
    return
  fi
  status=$(echo "$resp" | head -n1 | tr -d '\r')
  if [[ "$status" =~ $want ]]; then
    _pass "$name [$status]"
  else
    _fail "$name" "expected $want, got: $status"
  fi
}

# ── 70.1 Conflicting Content-Length + Transfer-Encoding ─────────────────

phase_open "70.1 CL.TE smuggling rejected"

# Two Content-Length values → must reject. Go's net/http rejects this
# at parse time with 400.
RAW_DUAL_CL="GET /api/v1/status HTTP/1.1\r\nHost: $HOST\r\nContent-Length: 5\r\nContent-Length: 10\r\nConnection: close\r\n\r\nABCDE"
raw_probe "70.1.1 dual Content-Length rejected" "$RAW_DUAL_CL" "^HTTP/1\\.[01] 400"

# CL + TE: chunked → the proxy may pick one, the gateway the other.
# Per RFC 7230 §3.3.3, when both present TE wins and CL must be ignored,
# but a sane stack rejects the request outright.
RAW_CL_TE="POST /api/v1/auth/login HTTP/1.1\r\nHost: $HOST\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n"
raw_probe "70.1.2 CL+TE conflict rejected" "$RAW_CL_TE" "^HTTP/1\\.[01] (400|405|411)"

# TE: chunked with body that has bogus chunk size → reject.
RAW_BAD_CHUNK="POST /api/v1/auth/login HTTP/1.1\r\nHost: $HOST\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZZ\r\nbody\r\n0\r\n\r\n"
raw_probe "70.1.3 malformed chunked size rejected" "$RAW_BAD_CHUNK" "^HTTP/1\\.[01] 400"

# ── 70.2 Missing Host header ───────────────────────────────────────────

phase_open "70.2 RFC 7230 §5.4 — missing Host on HTTP/1.1"

RAW_NO_HOST="GET /api/v1/status HTTP/1.1\r\nConnection: close\r\n\r\n"
raw_probe "70.2.1 missing Host header rejected" "$RAW_NO_HOST" "^HTTP/1\\.[01] 400"

# ── 70.3 Oversized header rejected ─────────────────────────────────────

phase_open "70.3 oversized header → rejected before handler runs"

# Net/http default MaxHeaderBytes = 1MiB. Sending a 2 MiB header should
# elicit 431 (Request Header Fields Too Large) or 400. NOT 200 — that
# would mean the slow-header DoS surface is open.
LONG=$(printf 'A%.0s' {1..2000000})
RAW_BIG="GET /api/v1/status HTTP/1.1\r\nHost: $HOST\r\nX-Filler: $LONG\r\nConnection: close\r\n\r\n"
raw_probe "70.3.1 2MiB header rejected" "$RAW_BIG" "^HTTP/1\\.[01] (400|413|431|431)"

# ── 70.4 Obsolete line-folding (RFC 7230 §3.2.4) ───────────────────────

phase_open "70.4 obsolete header line-folding rejected"

# obs-fold was deprecated in HTTP/1.1; some proxies still emit it.
# Smuggling vector: hide a second header inside a folded continuation.
RAW_OBSFOLD="GET /api/v1/status HTTP/1.1\r\nHost: $HOST\r\nX-Smuggle: real\r\n value\r\nConnection: close\r\n\r\n"
raw_probe "70.4.1 obs-fold continuation handled safely" "$RAW_OBSFOLD" "^HTTP/1\\.[01] (200|400)"

# ── 70.5 Static detector: gateway uses Go net/http with timeouts ───────

phase_open "70.5 gateway has ReadHeaderTimeout + bounded MaxHeaderBytes"

if grep -q "ReadHeaderTimeout" "$ROOT/cmd/gateway/main.go"; then
  _pass "70.5.1 ReadHeaderTimeout configured"
else
  _fail "70.5.1 ReadHeaderTimeout missing" \
    "slowloris-style header DoS possible"
fi

# Even default MaxHeaderBytes (1MiB) is fine; we just want a value.
# Net/http applies a default if not set, so absence is OK — but log it.
if grep -qE "MaxHeaderBytes\s*:" "$ROOT/cmd/gateway/main.go"; then
  _pass "70.5.2 MaxHeaderBytes explicitly set"
else
  _skip "70.5.2 MaxHeaderBytes explicit" \
    "default 1MiB is acceptable; explicit setting is best-practice"
fi

# ── 70.6 Proxy config audit: no obvious smuggling-prone directives ─────

phase_open "70.6 nginx/proxy configs free of smuggling-prone directives"

# If any nginx/envoy/haproxy config ships in the repo, sniff for
# directives known to enable smuggling:
#   • proxy_http_version 1.0 (without TE awareness)
#   • underscores_in_headers off (some proxies smuggle via X_FOO)
PROXY_CONFIGS=$(find "$ROOT" -name "*.conf" -o -name "nginx.conf*" 2>/dev/null \
  | grep -v node_modules | grep -v ".git" | head -20)

if [[ -z "$PROXY_CONFIGS" ]]; then
  _skip "70.6.1 proxy config scan" "no nginx/envoy configs in repo"
else
  BAD=$(echo "$PROXY_CONFIGS" | xargs grep -lE "proxy_http_version[[:space:]]+1\.0" 2>/dev/null || true)
  if [[ -z "$BAD" ]]; then
    _pass "70.6.1 no proxy_http_version 1.0 (TE-unaware) configs"
  else
    _fail "70.6.1 found proxy_http_version 1.0" "$BAD — TE-aware 1.1 required"
  fi
fi

final_summary
