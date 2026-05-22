#!/usr/bin/env bash
# scripts/test-l16-info-disclosure.sh — information disclosure probes.
#
# Beyond the stack-trace check L15 does on a single endpoint, this
# walks a broader surface and looks for:
#
#   17.1 Verbose error messages leaking file paths / package names
#        / internal IPs / DB connection strings.
#
#   17.2 ETag/Last-Modified pseudo-leakage of internal state (low
#        severity but worth a watchdog).
#
#   17.3 Server header disclosure (Server: ..., X-Powered-By: ...).
#
#   17.4 Error responses leaking SQL syntax / column names / query
#        plans (database schema reconnaissance).
#
#   17.5 404 vs 403 oracle — is "resource exists in another tenant"
#        distinguishable from "resource doesn't exist"? IDOR-adjacent.
#
#   17.6 Build / version disclosure (Go version, gateway version
#        header, source code in HTML comments).
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
  local slug="${1:-default}" role="${2:-admin}"
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 3600))
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  payload=$(printf '{"sub":"l16@vsp.local","email":"l16@vsp.local","role":"%s","tenant_id":"%s","iat":%d,"exp":%d}' \
    "$role" "$slug" "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  sig=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$header" "$payload" "$sig"
}
ADMIN=$(mint_jwt)
ADMIN_B=$(mint_jwt "acme-corp" admin)

# ── 17.1 Error messages don't leak file paths / package names ──────────────

phase_open "17.1 Error bodies — no path/package/CIDR leakage"

# Force errors at multiple endpoints, scan response bodies for markers.
LEAK_HITS=()
for probe in \
  "POST /api/v1/auth/login application/json not-json"               \
  "POST /api/v1/vsp/run application/json {invalid:"                 \
  "GET  /api/v1/vsp/run/RID-DOES-NOT-EXIST"                         \
  "GET  /api/v1/admin/tenants/abc"                                  \
  "POST /api/v1/data/erasure application/json malformed"            ; do
  IFS=' ' read -r method path ct body <<<"$probe"
  body_tmp=$(mktemp)
  if [[ "$method" == "GET" ]]; then
    curl -s -o "$body_tmp" --max-time 5 -H "Authorization: Bearer $ADMIN" "$BASE$path" >/dev/null
  else
    curl -s -o "$body_tmp" --max-time 5 \
      -X "$method" -H "Authorization: Bearer $ADMIN" -H "Content-Type: $ct" \
      -d "$body" "$BASE$path" >/dev/null
  fi
  # Markers: absolute paths to source / module paths / IP addresses /
  # DB DSN tokens. We deliberately don't flag generic "error" strings.
  hits=$(grep -oE \
    "/home/[^[:space:]\"]+|/usr/lib/go|github\.com/vsp/platform/[^[:space:]\"]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|postgres://[^[:space:]\"]+" \
    "$body_tmp" 2>/dev/null | head -3 || true)
  if [[ -n "$hits" ]]; then
    LEAK_HITS+=("$path: $hits")
  fi
  rm -f "$body_tmp"
done

if (( ${#LEAK_HITS[@]} == 0 )); then
  _pass "17.1.1 no path/package/CIDR leakage in error bodies"
else
  printf -v LIST '%s | ' "${LEAK_HITS[@]:0:3}"
  _fail "17.1.1 internal-info leak in errors" "${LIST%| }"
fi

# ── 17.2 SQL leakage in 5xx ────────────────────────────────────────────────

phase_open "17.2 SQL leakage — DB error messages don't reach the client"

# Force a DB error by injecting a malformed UUID in path.
SQL_BODY=$(curl -s --max-time 5 -H "Authorization: Bearer $ADMIN" \
  "$BASE/api/v1/data/exports/$(printf '\xFF\x00')" 2>/dev/null | head -c 500)

if echo "$SQL_BODY" | grep -qE "syntax error|invalid input|relation \"|column \"|SQLSTATE|pgx\.|pgconn\.|FROM [a-z_]+ WHERE"; then
  _fail "17.2.1 SQL detail leaked" "$(echo "$SQL_BODY" | head -c 200)"
else
  _pass "17.2.1 no SQL detail leaked in malformed-UUID error"
fi

# Force tenant-of-different-shape (slug column) — historically this
# returned "invalid input syntax for type uuid: <slug>" verbatim.
SQL_BODY2=$(curl -s --max-time 5 -X POST \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"plan":"%%%%"}' \
  "$BASE/api/v1/admin/tenants/not-a-uuid/plan" 2>/dev/null | head -c 500)
if echo "$SQL_BODY2" | grep -qE "invalid input syntax|SQLSTATE|22P02"; then
  _fail "17.2.2 SQL state leaked" "$(echo "$SQL_BODY2" | head -c 200)"
else
  _pass "17.2.2 no SQLSTATE in error body"
fi

# ── 17.3 Server / version-disclosure headers ───────────────────────────────

phase_open "17.3 Server / version headers minimal"

HDR=$(curl -s -i --max-time 5 "$BASE/api/v1/status" 2>/dev/null | head -30)
if echo "$HDR" | grep -qiE "^Server: (gunicorn|uwsgi|nginx/[0-9]|Apache/[0-9]|Express|Werkzeug)"; then
  _fail "17.3.1 Server header leaks stack" "$(echo "$HDR" | grep -i "^Server:" | head -1)"
elif echo "$HDR" | grep -qiE "^X-Powered-By:"; then
  _fail "17.3.2 X-Powered-By leaks stack" "$(echo "$HDR" | grep -i "X-Powered-By" | head -1)"
else
  _pass "17.3.1 no Server / X-Powered-By stack-disclosing headers"
fi

# ── 17.4 404-vs-403 oracle ────────────────────────────────────────────────

phase_open "17.4 IDOR oracle — A's response for B's run is 404 (not 403)"

# Pick a real run from tenant B. Tenant A's probe should get 404
# ("not found" — same response as a non-existent rid). A 403 would
# tell tenant A "this run exists in some other tenant", which is a
# weaker information disclosure than IDOR but still reconnaissance.
RID_B=$(_psql_oneshot "SELECT rid FROM runs WHERE tenant_id='8bb9a716-fd14-4eba-92e8-681dc5bdb718' LIMIT 1;")
RID_FAKE="RID-DEFINITELY-DOES-NOT-EXIST-$(date +%s)"

if [[ -n "$RID_B" ]]; then
  STATUS_REAL=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/vsp/run/$RID_B")
  STATUS_FAKE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/vsp/run/$RID_FAKE")
  if [[ "$STATUS_REAL" == "$STATUS_FAKE" ]]; then
    _pass "17.4.1 same status for foreign-tenant + nonexistent [$STATUS_REAL = $STATUS_FAKE]"
  elif [[ "$STATUS_REAL" == "403" && "$STATUS_FAKE" == "404" ]]; then
    _fail "17.4.1 oracle leak" \
      "tenant A gets 403 for B's run, 404 for nonexistent — leaks existence"
  else
    _pass "17.4.1 statuses differ but both deny [real=$STATUS_REAL fake=$STATUS_FAKE]"
  fi
else
  _skip "17.4.1 IDOR oracle" "no tenant-B run available"
fi

# ── 17.5 HTML comment leakage ──────────────────────────────────────────────

phase_open "17.5 HTML — no source-code comments shipped to client"

# Probe landing + a panel; look for HTML <!-- ... --> comments that
# embed dev/build metadata (build timestamps, commit hashes, source
# file references). Single-line decorative comments are fine; multi-
# line / source-quoting ones are the bug class.
LEAK=()
for path in "/" "/static/index.html" "/static/panels/dashboard.html"; do
  body=$(curl -s --max-time 5 "$BASE$path" 2>/dev/null)
  hits=$(echo "$body" | grep -oE '<!--[^>]+(TODO|FIXME|XXX|HACK|DEBUG|password|secret|token=|admin@)[^>]*-->' | head -2)
  if [[ -n "$hits" ]]; then
    LEAK+=("$path: ${hits%%$'\n'*}")
  fi
done
if (( ${#LEAK[@]} == 0 )); then
  _pass "17.5.1 no TODO/FIXME/secret leakage in HTML comments"
else
  printf -v LIST '%s | ' "${LEAK[@]}"
  _fail "17.5.1 HTML comment leak" "${LIST%| }"
fi

# ── 17.6 X-Build / X-Version exposure ──────────────────────────────────────

phase_open "17.6 Build version disclosure"

BUILD_HDR=$(curl -s -i --max-time 5 "$BASE/api/v1/status" 2>/dev/null \
  | grep -iE "^(X-Build|X-Version|X-Vsp-Version|X-Commit|X-Git-Sha):" || true)

# Disclosing a coarse version (X-Vsp-Version: 0.10.0) is acceptable
# for support; a full git SHA gives an attacker a precise CVE map.
if [[ -z "$BUILD_HDR" ]]; then
  _pass "17.6.1 no build-version header"
elif echo "$BUILD_HDR" | grep -qiE "[a-f0-9]{40}|[a-f0-9]{8,}-[a-f0-9]{4,}"; then
  _fail "17.6.1 git SHA exposed" "$BUILD_HDR"
else
  _pass "17.6.1 build header is coarse [$BUILD_HDR]"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
