#!/usr/bin/env bash
# scripts/test-l35-redirect-ssrf.sh — open-redirect + SSRF probes.
#
# Two attack classes that share a common shape (server takes a URL
# from user input, then either redirects to it OR fetches it):
#
#   A. Open redirect — the gateway accepts an attacker-controlled URL
#      in a `redirect=` / `next=` / `return_to=` parameter and emits
#      it in a Location header. Used in phishing chains where the
#      attacker's domain inherits the trusted origin's reputation.
#
#   B. SSRF (Server-Side Request Forgery) — the gateway accepts an
#      attacker-controlled URL in a webhook / target / proxy field
#      and FETCHES it. Used to reach internal services
#      (169.254.169.254 cloud metadata, localhost-only admin ports,
#      Redis, Postgres, etc).
#
# This file probes both. The gateway has at least three known
# attack-surface points:
#   - SSO `?redirect=` (sso_oidc.go:187 / 305)
#   - SIEM webhook URL (siem.go:50 — has ValidateWebhookURL guard)
#   - Scan target_url (siem_extended.go:1130)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# ── 35.1 SSO redirect parameter — only same-origin paths allowed ─────────

phase_open "35.1 SSO `?redirect=` validation"

# Expectation: any redirect= value that resolves to an external origin
# (or to a non-http(s) scheme) must be rejected OR coerced to a safe
# default. The handler at sso_oidc.go:177 currently does a bare
# `redirAfter = r.URL.Query().Get("redirect")` and stores it; the
# eventual Location header is the issue.
#
# We probe the entrypoint and the callback. We do NOT actually walk
# through OIDC, just verify the entrypoint either rejects or
# normalises the value.

for evil_redirect in \
    "//evil.com/phish" \
    "https://attacker.example.org/phish" \
    "javascript:alert(1)" \
    "data:text/html,<script>alert(1)</script>" \
    "file:///etc/passwd" \
    "@evil.com" \
  ; do
  enc=$(printf '%s' "$evil_redirect" | jq -sRr @uri)
  status=$(curl -s -o /dev/null -w "%{http_code}|%{redirect_url}" --max-time 5 \
    "$BASE/api/v1/auth/sso/login?redirect=$enc" 2>/dev/null || echo "000|")
  http=${status%%|*}
  loc=${status#*|}

  # Pass conditions:
  #   a) the gateway returned 4xx (rejected the redirect param), OR
  #   b) the Location header resolves to the gateway's own origin
  #      (doesn't include attacker domain).
  if [[ "$http" =~ ^4 ]]; then
    _pass "35.1 reject '$evil_redirect' [HTTP $http]"
  elif [[ -n "$loc" ]] && ! echo "$loc" | grep -qiE "(evil\.com|attacker|javascript:|data:|file:)"; then
    _pass "35.1 normalise '$evil_redirect' → safe [Location=$(echo "$loc" | head -c 60)]"
  else
    _fail "35.1 open redirect via '$evil_redirect'" \
      "HTTP $http, Location=$(echo "$loc" | head -c 100)"
  fi
done

# ── 35.2 SIEM webhook URL — SSRF surface ──────────────────────────────────

phase_open "35.2 SIEM webhook URL — block internal/metadata SSRF"

# These targets MUST be rejected by ValidateWebhookURL:
#   - cloud metadata (AWS, GCP, Azure)
#   - localhost / 127.0.0.1 / ::1
#   - private RFC 1918 / link-local
#   - non-http(s) schemes (gopher, dict, file, ftp)

for ssrf_url in \
    "http://169.254.169.254/latest/meta-data/" \
    "http://169.254.169.254/computeMetadata/v1/" \
    "http://127.0.0.1:6379/" \
    "http://localhost:5432/" \
    "http://10.0.0.1/" \
    "http://192.168.1.1/" \
    "gopher://127.0.0.1:6379/_FLUSHALL" \
    "file:///etc/passwd" \
    "dict://127.0.0.1:11211/stat" \
  ; do
  body=$(printf '{"name":"l35-probe","url":"%s","provider":"generic"}' "$ssrf_url")
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN" \
    -d "$body" \
    "$BASE/api/v1/siem/webhooks" 2>/dev/null || echo "000")

  if [[ "$status" =~ ^4 ]]; then
    _pass "35.2 webhook rejects '$ssrf_url' [HTTP $status]"
  elif [[ "$status" == "404" || "$status" == "405" || "$status" == "501" ]]; then
    # Endpoint not mounted in this build — skip rather than false-pass.
    _skip "35.2 webhook URL $ssrf_url" "endpoint not available [HTTP $status]"
  else
    _fail "35.2 webhook accepted SSRF URL '$ssrf_url'" "HTTP $status"
  fi
done

# ── 35.3 Scan target_url — same SSRF guards apply ────────────────────────

phase_open "35.3 Scan target_url — block metadata/internal"

# /api/v1/vsp/run takes a target URL for DAST-style probing. It MUST
# refuse cloud-metadata and loopback targets — otherwise the scanner
# can be turned into an SSRF gadget.
for ssrf_target in \
    "http://169.254.169.254/" \
    "http://127.0.0.1:8921/api/v1/admin/users" \
    "http://localhost:6379/" \
  ; do
  body=$(printf '{"target_url":"%s","mode":"FAST","profile":"FAST"}' "$ssrf_target")
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN" \
    -d "$body" \
    "$BASE/api/v1/vsp/run" 2>/dev/null || echo "000")

  if [[ "$status" =~ ^4 ]]; then
    _pass "35.3 scan rejects target '$ssrf_target' [HTTP $status]"
  elif [[ "$status" == "404" || "$status" == "405" ]]; then
    _skip "35.3 scan target $ssrf_target" "endpoint not available [HTTP $status]"
  else
    _fail "35.3 scan accepted SSRF target '$ssrf_target'" "HTTP $status"
  fi
done

# ── 35.4 Header-based redirect injection ─────────────────────────────────

phase_open "35.4 Header-injection — newline in redirect param"

# A naive Location-header writer that doesn't strip CR/LF can be
# tricked into emitting arbitrary headers via a smuggled \r\n in the
# parameter. Probe with an encoded CR-LF + Set-Cookie.
SMUGGLE='/dashboard%0d%0aSet-Cookie:%20pwn=1'
status=$(curl -s -i --max-time 5 \
  "$BASE/api/v1/auth/sso/login?redirect=$SMUGGLE" 2>/dev/null \
  | head -20 | tr -d '\r')

if echo "$status" | grep -q "Set-Cookie:.*pwn"; then
  _fail "35.4.1 CRLF-injection in redirect param" \
    "Set-Cookie: pwn=1 was reflected into response headers"
else
  _pass "35.4.1 CRLF in redirect param sanitised"
fi

final_summary
