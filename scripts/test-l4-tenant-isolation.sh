#!/usr/bin/env bash
# scripts/test-l4-tenant-isolation.sh — L4 multi-tenant isolation matrix.
#
# Two tenants (default + acme-corp) already exist in the dev DB. This
# runner mints two JWTs (one per tenant) and then probes the same
# endpoint set with EACH token, asserting that:
#
#   1. List responses never contain rows whose tenant_id ≠ the caller's
#      tenant. (Catches RLS bypass + handler-side tenant-filter bugs.)
#   2. Direct-by-ID fetch on the OTHER tenant's resource returns 404,
#      not 200 with leaked content. (Catches IDOR.)
#   3. Canary rows seeded into one tenant never appear in the other
#      tenant's responses. (Catches cache-key collision bugs.)
#
# Why this is L4 (above L3): L1-L3 used a single tenant. This file is
# the first time we prove the isolation contract holds against a real
# adversarial-tenant probe.
#
# Pre-flight: requires gateway running, Postgres available, JWT_SECRET
# in /etc/vsp/env.production (or $JWT_SECRET env override).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

# ── tenant fixtures ────────────────────────────────────────────────────────

TENANT_A_SLUG="default"
TENANT_A_UUID="1bdf7f20-dbb3-4116-815f-26b4dc747e76"
TENANT_B_SLUG="acme-corp"
TENANT_B_UUID="8bb9a716-fd14-4eba-92e8-681dc5bdb718"

# Confirm both tenants actually exist before doing anything destructive.
TENANT_CHECK=$(_psql_oneshot "SELECT count(*) FROM tenants WHERE id IN ('$TENANT_A_UUID','$TENANT_B_UUID');")
if [[ "$TENANT_CHECK" != "2" ]]; then
  printf "%s✗%s expected both tenants to exist (got %s)\n" "$C_RED" "$C_RESET" "$TENANT_CHECK" >&2
  exit 2
fi

# ── token mint ─────────────────────────────────────────────────────────────

# Read JWT_SECRET fresh from the canonical file every time. We deliberately
# do NOT fall back to the env value — that masked a real bug in iter 1
# (a stale exported $JWT_SECRET from an earlier shell session signed
# tokens with a rotated-out key, every probe got 401). Running env can
# override via $VSP_JWT_SECRET_FILE if that file path moves.
_secret_file="${VSP_JWT_SECRET_FILE:-/etc/vsp/env.production}"
JWT_SECRET=$(sudo grep '^JWT_SECRET=' "$_secret_file" 2>/dev/null | cut -d= -f2-)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET not available; set VSP_JWT_SECRET_FILE or put in /etc/vsp/env.production\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local slug="$1" role="$2"
  local now exp header payload sig
  now=$(date +%s); exp=$((now + 3600))
  header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  payload=$(printf '{"sub":"l4b@vsp.local","email":"l4b@vsp.local","role":"%s","tenant_id":"%s","iat":%d,"exp":%d}' \
    "$role" "$slug" "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  sig=$(printf '%s' "$header.$payload" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$header" "$payload" "$sig"
}

TOKEN_A=$(mint_jwt "$TENANT_A_SLUG" admin)
TOKEN_B=$(mint_jwt "$TENANT_B_SLUG" admin)

# Sanity: tokens parse and reach a real handler. If this fails the rest
# of the file is misleading — better to bail with a clear error.
SANITY_A=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOKEN_A" "$BASE/api/v1/vsp/findings?limit=1")
SANITY_B=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $TOKEN_B" "$BASE/api/v1/vsp/findings?limit=1")
if [[ "$SANITY_A" != "200" || "$SANITY_B" != "200" ]]; then
  printf "%s✗%s mint sanity failed (A=%s B=%s) — check JWT_SECRET / gateway is up\n" \
    "$C_RED" "$C_RESET" "$SANITY_A" "$SANITY_B" >&2
  exit 2
fi

# ── canary seeding ─────────────────────────────────────────────────────────
#
# Inserts one row into compliance_evidence per tenant with a unique
# marker. The body of every probe response is then grepped for the
# OPPOSITE tenant's marker; any hit is a leak. Cleanup runs at the
# end via the EXIT trap.

CANARY_A="L4B-CANARY-A-$$"
CANARY_B="L4B-CANARY-B-$$"

cleanup_canaries() {
  _psql_oneshot "DELETE FROM compliance_evidence WHERE filename IN ('$CANARY_A.txt','$CANARY_B.txt');" >/dev/null 2>&1 || true
}
trap cleanup_canaries EXIT

# Use _psql_oneshot for a side-effect insert (we don't care about the result).
seed_canary() {
  local tenant_uuid="$1" name="$2"
  if [[ -n "${DB_DSN:-}" ]]; then
    PAGER=cat psql -X --pset pager=off -d "$DB_DSN" -c \
      "INSERT INTO compliance_evidence (tenant_id, control_id, filename, content_type, size_bytes, sha256, blob, notes)
       VALUES ('$tenant_uuid','L4B','$name.txt','text/plain',16,
               'aa$(printf '0%.0s' {1..62})',
               '\x4c34422d43414e4152592d54455354','l4b isolation probe canary');" >/dev/null
  else
    PAGER=cat psql -X --pset pager=off -h "${PGHOST:-localhost}" -U "${PGUSER:-vsp}" -d "${PGDATABASE:-vsp_go}" -c \
      "INSERT INTO compliance_evidence (tenant_id, control_id, filename, content_type, size_bytes, sha256, blob, notes)
       VALUES ('$tenant_uuid','L4B','$name.txt','text/plain',16,
               'aa$(printf '0%.0s' {1..62})',
               '\x4c34422d43414e4152592d54455354','l4b isolation probe canary');" >/dev/null
  fi
}

seed_canary "$TENANT_A_UUID" "$CANARY_A"
seed_canary "$TENANT_B_UUID" "$CANARY_B"

# ── helper: assert response NEVER contains foreign tenant marker ────────────

# assert_no_leak NAME URL TOKEN FOREIGN_MARKER
# Fetches URL with the given Bearer token and asserts that FOREIGN_MARKER
# does not appear anywhere in the response body. Captures HTTP status
# for context.
assert_no_leak() {
  local name="$1" url="$2" token="$3" marker="$4"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local body status
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 \
    -H "Authorization: Bearer $token" "$BASE$url" 2>/dev/null) || status="000"
  if [[ "$status" != "200" ]]; then
    _fail "$name" "HTTP $status (expected 200)"
    rm -f "$body"; return
  fi
  if grep -q "$marker" "$body"; then
    _fail "$name" "FOREIGN tenant marker $marker present in $url response"
    rm -f "$body"; return
  fi
  _pass "$name [no $marker leak]"
  rm -f "$body"
}

# assert_only_my_tenant NAME URL TOKEN MY_TENANT_UUID FOREIGN_TENANT_UUID
# Fetches URL and asserts that for every row in the JSON response, any
# tenant_id field equals MY_TENANT_UUID. Catches the case where a list
# handler joins across tenants.
assert_only_my_tenant() {
  local name="$1" url="$2" token="$3" mine="$4" foreign="$5"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local body status
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 \
    -H "Authorization: Bearer $token" "$BASE$url" 2>/dev/null) || status="000"
  if [[ "$status" != "200" ]]; then
    local snippet
    snippet=$(head -c 120 "$body" 2>/dev/null | tr -d '\n')
    _fail "$name" "HTTP $status — $snippet"
    rm -f "$body"; return
  fi
  # Look for tenant_id values anywhere in the JSON tree.
  local foreign_count my_count
  foreign_count=$(jq -r '.. | objects | .tenant_id? // empty' "$body" 2>/dev/null \
    | grep -c "^$foreign$" || true)
  my_count=$(jq -r '.. | objects | .tenant_id? // empty' "$body" 2>/dev/null \
    | grep -c "^$mine$" || true)
  if (( foreign_count > 0 )); then
    _fail "$name" "$foreign_count row(s) leaked from foreign tenant $foreign in $url"
    rm -f "$body"; return
  fi
  _pass "$name [my=$my_count foreign=0]"
  rm -f "$body"
}

# assert_404_or_404ish NAME URL TOKEN
# Probe direct-by-id IDOR: caller is tenant A, URL points at tenant B's
# resource. Expect 404 (or 403). Anything in 2xx is a leak.
assert_idor_blocked() {
  local name="$1" url="$2" token="$3"
  _should_run "$name" || { _skip "$name" "filtered"; return; }
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -H "Authorization: Bearer $token" "$BASE$url" 2>/dev/null) || status="000"
  if [[ "$status" =~ ^(404|403)$ ]]; then
    _pass "$name [HTTP $status]"
    return
  fi
  if [[ "$status" =~ ^2 ]]; then
    _fail "$name" "IDOR — got HTTP $status fetching foreign resource"
    return
  fi
  _fail "$name" "unexpected HTTP $status (expected 404/403)"
}

# ── probes ─────────────────────────────────────────────────────────────────

phase_open "5.1 List endpoints — tenant_id never crosses"

assert_only_my_tenant "5.1.1 findings — A sees only A" \
  "/api/v1/vsp/findings?limit=200" "$TOKEN_A" "$TENANT_A_UUID" "$TENANT_B_UUID"
assert_only_my_tenant "5.1.2 findings — B sees only B" \
  "/api/v1/vsp/findings?limit=200" "$TOKEN_B" "$TENANT_B_UUID" "$TENANT_A_UUID"

assert_only_my_tenant "5.1.3 runs — A sees only A" \
  "/api/v1/vsp/runs?limit=200" "$TOKEN_A" "$TENANT_A_UUID" "$TENANT_B_UUID"
assert_only_my_tenant "5.1.4 runs — B sees only B" \
  "/api/v1/vsp/runs?limit=200" "$TOKEN_B" "$TENANT_B_UUID" "$TENANT_A_UUID"

assert_only_my_tenant "5.1.5 audit/log — A sees only A" \
  "/api/v1/audit/log?limit=200" "$TOKEN_A" "$TENANT_A_UUID" "$TENANT_B_UUID"
assert_only_my_tenant "5.1.6 audit/log — B sees only B" \
  "/api/v1/audit/log?limit=200" "$TOKEN_B" "$TENANT_B_UUID" "$TENANT_A_UUID"

phase_open "5.2 Canary marker — never leaks across tenants"

assert_no_leak "5.2.1 evidence — A search shouldn't find B's canary" \
  "/api/v1/compliance/evidence" "$TOKEN_A" "$CANARY_B"
assert_no_leak "5.2.2 evidence — B search shouldn't find A's canary" \
  "/api/v1/compliance/evidence" "$TOKEN_B" "$CANARY_A"

assert_no_leak "5.2.3 findings list — A shouldn't see B canary" \
  "/api/v1/vsp/findings?limit=200" "$TOKEN_A" "$CANARY_B"
assert_no_leak "5.2.4 findings list — B shouldn't see A canary" \
  "/api/v1/vsp/findings?limit=200" "$TOKEN_B" "$CANARY_A"

phase_open "5.3 IDOR — direct-by-ID fetch of foreign resource"

# Pull one real run id from each tenant.
RUN_A_ID=$(_psql_oneshot "SELECT id FROM runs WHERE tenant_id='$TENANT_A_UUID' LIMIT 1;")
RUN_B_ID=$(_psql_oneshot "SELECT id FROM runs WHERE tenant_id='$TENANT_B_UUID' LIMIT 1;")
FIND_A_ID=$(_psql_oneshot "SELECT id FROM findings WHERE tenant_id='$TENANT_A_UUID' LIMIT 1;")
FIND_B_ID=$(_psql_oneshot "SELECT id FROM findings WHERE tenant_id='$TENANT_B_UUID' LIMIT 1;")

if [[ -n "$RUN_B_ID" ]]; then
  assert_idor_blocked "5.3.1 A fetching B's run by ID" \
    "/api/v1/vsp/run/$RUN_B_ID" "$TOKEN_A"
fi
if [[ -n "$RUN_A_ID" ]]; then
  assert_idor_blocked "5.3.2 B fetching A's run by ID" \
    "/api/v1/vsp/run/$RUN_A_ID" "$TOKEN_B"
fi

# Fetch RIDs (text identifiers used in the find-by-rid handler) too —
# Sprint 6.x's lookup API supports both UUID and rid; both must be
# tenant-scoped or it's an IDOR vector.
RID_B=$(_psql_oneshot "SELECT rid FROM runs WHERE tenant_id='$TENANT_B_UUID' LIMIT 1;")
RID_A=$(_psql_oneshot "SELECT rid FROM runs WHERE tenant_id='$TENANT_A_UUID' LIMIT 1;")
if [[ -n "$RID_B" ]]; then
  assert_idor_blocked "5.3.3 A fetching B's run by RID" \
    "/api/v1/vsp/run/$RID_B" "$TOKEN_A"
fi
if [[ -n "$RID_A" ]]; then
  assert_idor_blocked "5.3.4 B fetching A's run by RID" \
    "/api/v1/vsp/run/$RID_A" "$TOKEN_B"
fi

phase_open "5.4 Tenant scope on aggregate endpoints"

# Aggregate endpoints don't return tenant_id in their bodies but their
# COUNTS must differ between the two tenants. If both report identical
# numbers, that's a strong signal someone is computing globally and
# slicing client-side.
PROBE_FINDINGS_A=$(curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_A" "$BASE/api/v1/vsp/findings/summary" 2>/dev/null | jq -r '.total // .total_findings // empty' 2>/dev/null || echo "")
PROBE_FINDINGS_B=$(curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_B" "$BASE/api/v1/vsp/findings/summary" 2>/dev/null | jq -r '.total // .total_findings // empty' 2>/dev/null || echo "")

if [[ -n "$PROBE_FINDINGS_A" && -n "$PROBE_FINDINGS_B" ]]; then
  if [[ "$PROBE_FINDINGS_A" == "$PROBE_FINDINGS_B" ]]; then
    _fail "5.4.1 findings/summary differs per tenant" \
      "both tenants reported total=$PROBE_FINDINGS_A — looks tenant-blind"
  else
    _pass "5.4.1 findings/summary tenant-scoped [A=$PROBE_FINDINGS_A B=$PROBE_FINDINGS_B]"
  fi
else
  _skip "5.4.1 findings/summary tenant-scoped" "endpoint did not return parseable totals"
fi

# Audit stats parity check.
STATS_A=$(curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_A" "$BASE/api/v1/audit/stats" 2>/dev/null | jq -r '.total_events // empty' 2>/dev/null || echo "")
STATS_B=$(curl -s --max-time 10 -H "Authorization: Bearer $TOKEN_B" "$BASE/api/v1/audit/stats" 2>/dev/null | jq -r '.total_events // empty' 2>/dev/null || echo "")

if [[ -n "$STATS_A" && -n "$STATS_B" ]]; then
  if [[ "$STATS_A" == "$STATS_B" ]]; then
    _fail "5.4.2 audit/stats differs per tenant" \
      "both tenants reported total_events=$STATS_A — looks tenant-blind"
  else
    _pass "5.4.2 audit/stats tenant-scoped [A=$STATS_A B=$STATS_B]"
  fi
else
  _skip "5.4.2 audit/stats tenant-scoped" "endpoint did not return parseable totals"
fi

phase_open "5.5 Cross-token cookie isolation"

# Set a vsp_token cookie for tenant A but Authorization header for B.
# Spec: header takes precedence (chi auth middleware). If a leak occurs
# it would manifest as A's audit user_id appearing in a B-token call.
A_USER=$(_psql_oneshot "SELECT id FROM users WHERE tenant_id='$TENANT_A_UUID' AND role='admin' LIMIT 1;")

if [[ -n "$A_USER" ]]; then
  # Probe with B's bearer + A's cookie. Should be tenant B response only.
  body=$(mktemp)
  status=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 \
    -H "Authorization: Bearer $TOKEN_B" \
    -H "Cookie: vsp_token=$TOKEN_A" \
    "$BASE/api/v1/vsp/findings?limit=50" 2>/dev/null) || status="000"
  if [[ "$status" == "200" ]]; then
    leak=$(jq -r '.. | objects | .tenant_id? // empty' "$body" 2>/dev/null \
      | grep -c "^$TENANT_A_UUID$" || true)
    if (( leak > 0 )); then
      _fail "5.5.1 header-vs-cookie precedence" \
        "B's header should win, but A's tenant rows appeared ($leak rows)"
    else
      _pass "5.5.1 header-vs-cookie precedence [bearer wins]"
    fi
  else
    _fail "5.5.1 header-vs-cookie precedence" "HTTP $status"
  fi
  rm -f "$body"
fi

# ── final summary ──────────────────────────────────────────────────────────

final_summary
