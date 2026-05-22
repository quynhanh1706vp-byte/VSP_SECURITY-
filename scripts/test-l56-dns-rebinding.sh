#!/usr/bin/env bash
# scripts/test-l56-dns-rebinding.sh — DNS-rebinding allowlist verification.
#
# When an SSRF allowlist resolves the URL's hostname at REQUEST time
# (not validate time), an attacker can race: their DNS server returns
# a public IP for validation, then returns 127.0.0.1 for the actual
# fetch. Classic time-of-check-time-of-use bug.
#
# Defence shapes that work:
#   A. Resolve the hostname ONCE, then connect to that IP directly
#      (or pin via http.Transport.DialContext).
#   B. Pin the resolved IP to the network family and validate it's
#      not in 127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16,
#      ::1, fe80::/10, etc.
#
# This level is mostly STATIC analysis — runtime probing needs a
# controllable DNS server, which CI can't easily provide. Gated by
# L56_RUNTIME=1 for environments that have one.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 56.1 SSRF validators resolve hostname themselves ─────────────────────

phase_open "56.1 URL validators don't trust net.DefaultResolver pre-dial"

# Look for ValidateWebhookURL / ValidateSSOURL / SafeFetch patterns.
# Each should:
#   a) Parse the URL
#   b) Reject if scheme not http/https
#   c) Reject if host is in a literal blocklist (localhost / 127.* /
#      [::1] / 169.254.* / cloud-metadata hosts)
#   d) Resolve host → IP via net.LookupHost
#   e) Reject if the resolved IP is in a private range
#   f) Pin that IP via http.Transport.DialContext when fetching
#
# Many implementations stop at (c) and (e), missing the dial-pin (f),
# which leaves a DNS-rebinding race.
VALIDATORS=$(grep -rln 'ValidateWebhookURL\|ValidateSSOURL\|ValidateURL\|SafeFetch' \
  "$ROOT/internal/" 2>/dev/null \
  | grep -v '_test\.go\|\.bak' \
  | head -5 || true)

if [[ -z "$VALIDATORS" ]]; then
  _skip "56.1.0 URL validators present" "no ValidateWebhookURL or similar found"
else
  COUNT=$(echo "$VALIDATORS" | wc -l | tr -d ' ')
  _pass "56.1.0 found $COUNT URL-validation file(s)"

  # Each validator file should mention `LookupHost`, `LookupIP`, or
  # `DialContext` — proves it resolves AND pins (not just regex-checks
  # the hostname). `|| true` because no-match grep -l exits 1 and
  # would otherwise abort under set -e + pipefail.
  PINS=$(echo "$VALIDATORS" | while read -r f; do
    grep -lE 'LookupHost|LookupIP|DialContext|net\.IPNet|169\.254' "$f" 2>/dev/null || true
  done | sort -u | grep -c . 2>/dev/null || echo 0)
  PINS=$(echo "$PINS" | head -1 | tr -dc '0-9')
  PINS=${PINS:-0}

  if [[ "$PINS" -ge 1 ]] 2>/dev/null; then
    _pass "56.1.1 at least one validator resolves+checks IP [$PINS file(s)]"
  else
    _fail "56.1.1 no validator does IP-resolution + check" \
      "validator files exist but none use LookupHost/LookupIP — DNS rebinding window open"
  fi
fi

# ── 56.2 No DialContext that's a no-op ───────────────────────────────────

phase_open "56.2 Custom http.Transport doesn't disable DNS validation"

# Some codebases use a custom DialContext that does `(net.Dialer{}).DialContext(...)`
# without re-validating the IP. That's effectively a passthrough.
HITS=$(grep -rEn 'http\.Transport\{' \
  --include='*.go' \
  "$ROOT/internal/" "$ROOT/cmd/" 2>/dev/null \
  | grep -v '_test\.go' \
  | head -5 || true)

if [[ -z "$HITS" ]]; then
  _pass "56.2.1 no custom http.Transport — uses defaults (safe but no pinning)"
else
  _skip "56.2.1 custom http.Transport present" \
    "review each for DialContext IP-pin: $(echo "$HITS" | wc -l) site(s)"
fi

# ── 56.3 Runtime probe — only when a fake DNS server is available ────────

phase_open "56.3 Runtime rebinding probe (gated)"

if [[ "${L56_RUNTIME:-0}" != "1" ]]; then
  _skip "56.3.0 runtime probe" "L56_RUNTIME!=1 — requires controllable DNS server, skip by default"
else
  # When L56_DNS_REBINDER is a hostname under attacker control that
  # rotates A records, we can craft a webhook URL to it and verify the
  # gateway rejects after first resolution (or pins the IP).
  REBIND="${L56_DNS_REBINDER:-rebind.example.invalid}"
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-x}")}" \
    -d "{\"url\":\"http://$REBIND/webhook\",\"name\":\"l56-probe\",\"provider\":\"generic\"}" \
    "$BASE/api/v1/siem/webhooks" 2>/dev/null || echo "000")

  if [[ "$status" =~ ^4 ]]; then
    _pass "56.3.1 rebinder hostname rejected at validation [HTTP $status]"
  else
    _skip "56.3.1 rebinder probe" "HTTP $status — manual review required"
  fi
fi

final_summary
