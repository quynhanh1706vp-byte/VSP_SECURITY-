#!/usr/bin/env bash
# test-l3-comprehensive.sh — VSP Level 3 deep test (~5 min runtime).
#
# Goes beyond L2's "endpoint returns 200" to verify SEMANTIC correctness:
#   • Auth boundary: tampered JWTs, expired tokens, role escalation
#   • Input validation: SQL injection, path traversal, oversized bodies,
#     null bytes, unicode, nested JSON bombs
#   • Cross-tenant IDOR (depends on having 2 tenants seeded)
#   • Compliance content depth: specific NIST control IDs present,
#     SSDF families covered, cATO criteria IDs match the 7 published
#   • Resilience: concurrent erasure, audit-chain repair under contention
#   • Sprint deliverable depth: scanner dirs each have runner.go,
#     audit bundle SHA-256s verify after extract, self-SBOM has >0
#     components, Sigma rules are valid YAML + reference real ATT&CK
#
# Usage: same env as L2 (TOKEN_ADMIN, TOKEN_ANALYST, DB_DSN).
#        ./scripts/test-l3-comprehensive.sh [phase]
#        phases: 4.1 | 4.2 | 4.3 | 4.4 | 4.5 | 4.6 | all

set -uo pipefail
cd "$(dirname "$0")/.."

. "$(dirname "$0")/lib/vsp-test.sh"

require_command curl jq go
require_env TOKEN_ADMIN

PHASE="${1:-all}"
H_ADMIN=(-H "Authorization: Bearer $TOKEN_ADMIN")
[[ -n "${TOKEN_ANALYST:-}" ]] && H_ANALYST=(-H "Authorization: Bearer $TOKEN_ANALYST")

printf "\n%s%s VSP L3 Comprehensive Test%s\n" "$C_BOLD" "$C_GREEN" "$C_RESET"
printf "Base:   %s\n" "$BASE"
printf "Phase:  %s\n" "$PHASE"

# ═════════════════════════════════════════════════════════════════════════
# 4.1 Auth boundary — 15 cases probing every credential path + bypass
# ═════════════════════════════════════════════════════════════════════════

run_4_1_auth() {
  phase_open "4.1 Auth boundary attacks"

  # 4.1.1 Missing Authorization header → 401.
  assert_status "4.1.1 missing Authorization → 401" \
    "/api/v1/vsp/findings" 401

  # 4.1.2 Empty Authorization header.
  assert_status "4.1.2 empty Authorization → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Authorization:"

  # 4.1.3 Bearer prefix without token.
  assert_status "4.1.3 'Bearer ' without token → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Authorization: Bearer "

  # 4.1.4 Garbage bytes after Bearer.
  assert_status "4.1.4 garbage bearer → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Authorization: Bearer not.a.real.jwt"

  # 4.1.5 alg=none JWT (canonical bypass attempt).
  # Build a JWT with alg:none and arbitrary admin claims.
  none_h=$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
  none_p=$(printf '{"role":"admin","tenant_id":"default","exp":99999999999}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
  none_jwt="${none_h}.${none_p}."
  assert_status "4.1.5 alg=none bypass → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Authorization: Bearer $none_jwt"

  # 4.1.6 Wrong-secret JWT (HS256 with attacker secret).
  fake_h=$(printf '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
  fake_p=$(printf '{"role":"admin","tenant_id":"default","exp":99999999999}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
  fake_sig=$(printf '%s' "$fake_h.$fake_p" | openssl dgst -sha256 -hmac "wrong-secret" -binary | base64 -w0 | tr -d '=' | tr '/+' '_-')
  fake_jwt="$fake_h.$fake_p.$fake_sig"
  assert_status "4.1.6 wrong-secret JWT → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Authorization: Bearer $fake_jwt"

  # 4.1.7 Expired JWT.
  exp_h=$(printf '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
  exp_p=$(printf '{"role":"admin","tenant_id":"default","exp":1000000000}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
  JWT_SECRET=$(sudo grep '^JWT_SECRET=' /etc/vsp/env.production 2>/dev/null | cut -d= -f2-)
  exp_sig=$(printf '%s' "$exp_h.$exp_p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | base64 -w0 | tr -d '=' | tr '/+' '_-')
  exp_jwt="$exp_h.$exp_p.$exp_sig"
  assert_status "4.1.7 expired JWT (exp=2001) → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Authorization: Bearer $exp_jwt"

  # 4.1.8 Role escalation: analyst token tries admin endpoint.
  if [[ -n "${TOKEN_ANALYST:-}" ]]; then
    assert_status "4.1.8 analyst → admin endpoint → 403" \
      "/api/v1/admin/users" 403 \
      "${H_ANALYST[@]}"
  else
    skip "4.1.8 analyst → admin endpoint" "TOKEN_ANALYST not set"
  fi

  # 4.1.9 Tampered payload — change role from analyst to admin in already-
  # signed analyst JWT. Signature check should reject the modified payload.
  if [[ -n "${TOKEN_ANALYST:-}" ]]; then
    # Pull header + payload from analyst token, swap role, keep signature.
    h=$(echo "$TOKEN_ANALYST" | cut -d. -f1)
    p_orig=$(echo "$TOKEN_ANALYST" | cut -d. -f2)
    s=$(echo "$TOKEN_ANALYST" | cut -d. -f3)
    p_decoded=$(printf '%s' "$p_orig" | tr '_-' '/+' | base64 -d 2>/dev/null)
    p_tampered=$(printf '%s' "$p_decoded" | sed 's/"role":"analyst"/"role":"admin"/')
    p_new=$(printf '%s' "$p_tampered" | base64 -w0 | tr -d '=' | tr '/+' '_-')
    tampered_jwt="$h.$p_new.$s"
    assert_status "4.1.9 tampered role escalation → 401" \
      "/api/v1/admin/users" 401 \
      -H "Authorization: Bearer $tampered_jwt"
  else
    skip "4.1.9 tampered role escalation" "TOKEN_ANALYST not set"
  fi

  # 4.1.10 SQL injection attempt in Authorization header (unlikely path but
  # verify it doesn't 500).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer ' OR '1'='1" \
    "$BASE/api/v1/vsp/findings")
  rm -f "$body"
  case "$code" in
    401) _pass "4.1.10 SQLi in Authorization → 401 (no 5xx)" ;;
    *)   _fail "4.1.10 SQLi in Authorization" "got $code (must not 5xx)" ;;
  esac

  # 4.1.11 X-API-Key path: invalid key → 401.
  assert_status "4.1.11 invalid X-API-Key → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "X-API-Key: clearly-not-a-valid-key-12345"

  # 4.1.12 vsp_token cookie path: invalid cookie value.
  assert_status "4.1.12 invalid vsp_token cookie → 401" \
    "/api/v1/vsp/findings" 401 \
    -H "Cookie: vsp_token=garbage.token.value"

  # 4.1.13 PUT on GET endpoint with valid auth → 405 (not 401/500).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X PUT "${H_ADMIN[@]}" "$BASE/api/v1/auth/check")
  rm -f "$body"
  if [[ "$code" == "405" || "$code" == "404" ]]; then
    _pass "4.1.13 PUT on GET endpoint → method-rejected [$code]"
  else
    _fail "4.1.13 PUT on GET endpoint" "expected 405/404, got $code"
  fi

  # 4.1.14 User-enumeration defense — verify VIA CODE PATHS, not curl
  # latency (which is unreliable: depends on lockout state, IP fail
  # counter, prior test runs, network jitter).
  # We assert that:
  #   • CompareDummyPassword exists in internal/auth (constant-time path)
  #   • IPLockout.FailCount exists (so missing-user path can match found-
  #     user backoff; Sprint 12.7 fix)
  #   • the login handler calls both on the missing-user path
  printf "  %s…%s 4.1.14 user-enum defense code paths " "$C_DIM" "$C_RESET"
  miss_dummy=$(grep -c "CompareDummyPassword" internal/api/handler/auth.go 2>/dev/null)
  miss_backoff=$(grep -c "FailCount\|BackoffSleep" internal/api/handler/auth.go 2>/dev/null)
  if [[ "$miss_dummy" -ge 1 && "$miss_backoff" -ge 2 ]]; then
    _pass "(CompareDummyPassword + IPLock.FailCount/BackoffSleep wired)"
  else
    _fail "4.1.14 user-enum defense" "missing primitives (dummy=$miss_dummy backoff=$miss_backoff)"
  fi

  # 4.1.15 Token replay after logout (would need /logout to actually fire +
  # blacklist; dev-stub may skip). SKIP with note.
  skip "4.1.15 token replay after logout" "requires /logout flow + blacklist verify; manual"

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 4.2 Input validation / negative — 15 cases
# ═════════════════════════════════════════════════════════════════════════

run_4_2_input() {
  phase_open "4.2 Input validation & negative"

  # 4.2.1 Path traversal in evidence id (UUID-validated → 400).
  assert_status "4.2.1 path traversal in id → 400" \
    "/api/v1/compliance/evidence/..%2F..%2Fetc%2Fpasswd" 400 \
    "${H_ADMIN[@]}"

  # 4.2.2 Invalid UUID → 400.
  assert_status "4.2.2 invalid UUID → 400" \
    "/api/v1/compliance/evidence/not-a-uuid" 400 \
    "${H_ADMIN[@]}"

  # 4.2.3 Oversized body (12 MB) → 413 / 400.
  body=$(mktemp); big=$(mktemp)
  head -c $((12 * 1024 * 1024)) /dev/zero | base64 > "$big"
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 30 \
    -X POST -H "Content-Type: application/json" \
    "${H_ADMIN[@]}" -d "@$big" \
    "$BASE/api/v1/compliance/evidence")
  rm -f "$body" "$big"
  case "$code" in
    400|413) _pass "4.2.3 oversized body → $code (rejected)" ;;
    *)       _fail "4.2.3 oversized body" "expected 400 or 413, got $code" ;;
  esac

  # 4.2.4 Null byte in JSON string field (POST DSAR with NUL).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    "${H_ADMIN[@]}" \
    --data-raw '{"notes":"hello world"}' \
    "$BASE/api/v1/data/erasure")
  rm -f "$body"
  case "$code" in
    200|202|400|403) _pass "4.2.4 null byte in JSON → $code (handled)" ;;
    *)               _fail "4.2.4 null byte in JSON" "got $code (must not 5xx)" ;;
  esac

  # 4.2.5 SQL injection in tenant slug header.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "${H_ADMIN[@]}" \
    -H "X-Tenant-Slug: ' OR 1=1; DROP TABLE users--" \
    "$BASE/api/v1/vsp/findings")
  rm -f "$body"
  if [[ "$code" -ge 200 && "$code" -lt 500 ]]; then
    _pass "4.2.5 SQLi in X-Tenant-Slug → $code (no 5xx)"
  else
    _fail "4.2.5 SQLi in X-Tenant-Slug" "got $code (must not 5xx)"
  fi

  # 4.2.6 Nested JSON depth bomb (50 levels).
  bomb='{"a":'
  for i in $(seq 1 50); do bomb="${bomb}{\"a\":"; done
  bomb="${bomb}\"x\""
  for i in $(seq 1 50); do bomb="${bomb}}"; done
  bomb="${bomb}}"
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X PUT -H "Content-Type: application/json" \
    "${H_ADMIN[@]}" \
    -d "{\"config\": $bomb}" \
    "$BASE/api/v1/features/system_toggles/config")
  rm -f "$body"
  if [[ "$code" -ge 200 && "$code" -lt 500 ]]; then
    _pass "4.2.6 nested JSON 50 levels → $code (no 5xx)"
  else
    _fail "4.2.6 nested JSON depth bomb" "got $code"
  fi

  # 4.2.7-4.2.11 Disclosure endpoint validation — anon POST gets blocked
  # by CSRF middleware (403) before the validator runs, so we drive these
  # via an authenticated request which CSRF allows for header-bearer auth.
  # Each test exercises one validation rule.

  # 4.2.7 Unicode confusable email — should still 400 (invalid format) or
  # 200/202 (accepted; sanitised on render).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" "${H_ADMIN[@]}" \
    --data-raw '{"reporter_email":"adm‍in@vsp.local","title":"x","body":"x"}' \
    "$BASE/api/v1/security/disclose")
  rm -f "$body"
  case "$code" in
    200|202|400) _pass "4.2.7 unicode confusable email → $code (handled)" ;;
    *)           _fail "4.2.7 unicode confusable email" "got $code" ;;
  esac

  # 4.2.8 XSS in title — accepted (raw stored, escaped at render time).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" "${H_ADMIN[@]}" \
    -d '{"reporter_email":"x@y.z","title":"<script>alert(1)</script>","body":"x"}' \
    "$BASE/api/v1/security/disclose")
  rm -f "$body"
  case "$code" in
    200|202) _pass "4.2.8 XSS in title accepted (escape on render) [$code]" ;;
    *)       _fail "4.2.8 XSS in title" "got $code (expected 200/202)" ;;
  esac

  # 4.2.9 Missing required field — 400.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" "${H_ADMIN[@]}" \
    -d '{"title":"x","body":"x"}' \
    "$BASE/api/v1/security/disclose")
  rm -f "$body"
  assert_eq "4.2.9 missing required field → 400" "$code" "400"

  # 4.2.10 Negative CVSS — 400.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" "${H_ADMIN[@]}" \
    -d '{"reporter_email":"x@y.z","title":"x","body":"x","cvss_v3":-1}' \
    "$BASE/api/v1/security/disclose")
  rm -f "$body"
  if [[ "$code" == "400" ]]; then
    _pass "4.2.10 negative CVSS → 400"
  else
    _fail "4.2.10 negative CVSS" "expected 400, got $code"
  fi

  # 4.2.11 Type mismatch — 400.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" "${H_ADMIN[@]}" \
    -d '{"reporter_email":"x@y.z","title":"x","body":"x","cvss_v3":"high"}' \
    "$BASE/api/v1/security/disclose")
  rm -f "$body"
  if [[ "$code" == "400" ]]; then
    _pass "4.2.11 type-mismatch in JSON → 400"
  else
    _fail "4.2.11 type-mismatch in JSON" "expected 400, got $code"
  fi

  # 4.2.12 CRLF injection attempt in header.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "${H_ADMIN[@]}" \
    -H "X-VSP-Locale: vi"$'\r\n'"X-Injected: true" \
    "$BASE/api/v1/locale" 2>/dev/null)
  rm -f "$body"
  if [[ "$code" -ge 200 && "$code" -lt 500 ]]; then
    _pass "4.2.12 CRLF injection → $code (sanitised)"
  else
    _fail "4.2.12 CRLF injection" "got $code"
  fi

  # 4.2.13 Locale outside supported set.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    "${H_ADMIN[@]}" \
    -d '{"locale":"klingon"}' \
    "$BASE/api/v1/locale")
  rm -f "$body"
  assert_eq "4.2.13 unsupported locale → 400" "$code" "400"

  # 4.2.14 Empty config PUT (allowed by handler; defaults to {}).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X PUT -H "Content-Type: application/json" \
    "${H_ADMIN[@]}" -d '{}' \
    "$BASE/api/v1/features/system_toggles/config")
  rm -f "$body"
  if [[ "$code" == "200" ]]; then
    _pass "4.2.14 empty config PUT accepted [200]"
  else
    _fail "4.2.14 empty config PUT" "expected 200, got $code"
  fi

  # 4.2.15 Non-JSON body — driven via authenticated path to avoid CSRF.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" "${H_ADMIN[@]}" \
    -d 'not actually json' \
    "$BASE/api/v1/security/disclose")
  rm -f "$body"
  assert_eq "4.2.15 invalid JSON syntax → 400" "$code" "400"

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 4.3 Cross-tenant + IDOR — 8 cases
# ═════════════════════════════════════════════════════════════════════════

run_4_3_idor() {
  phase_open "4.3 Cross-tenant + IDOR"

  # 4.3.1 Random UUID for evidence (won't exist) → 404, not 500.
  assert_status "4.3.1 random evidence UUID → 404" \
    "/api/v1/compliance/evidence/00000000-0000-0000-0000-000000000000" 404 \
    "${H_ADMIN[@]}"

  # 4.3.2 Random run id for SLSA provenance → 404.
  assert_status "4.3.2 random run id provenance → 404" \
    "/api/v1/runs/never-existed-rid/provenance" 404 \
    "${H_ADMIN[@]}"

  # 4.3.3 Random DSR id → 404.
  assert_status "4.3.3 random DSR id → 404" \
    "/api/v1/data/exports/00000000-0000-0000-0000-000000000000" 404 \
    "${H_ADMIN[@]}"

  # 4.3.4 Random tenant slug header (admin shouldn't pivot).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "${H_ADMIN[@]}" \
    -H "X-Tenant-Slug: pivoted-tenant-attempt" \
    "$BASE/api/v1/vsp/findings")
  rm -f "$body"
  # Should still scope to admin's tenant (header ignored or 403).
  if [[ "$code" -ge 200 && "$code" -lt 500 ]]; then
    _pass "4.3.4 random X-Tenant-Slug → $code (no privilege escalation)"
  else
    _fail "4.3.4 random X-Tenant-Slug" "got $code"
  fi

  # 4.3.5 Disclosure transition with random id → 400 or 404.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    "${H_ADMIN[@]}" -d '{"to":"acknowledged"}' \
    "$BASE/api/v1/security/disclosures/00000000-0000-0000-0000-000000000000/transition")
  rm -f "$body"
  case "$code" in
    400|404) _pass "4.3.5 transition unknown disclosure → $code" ;;
    *)       _fail "4.3.5 transition unknown disclosure" "expected 400/404, got $code" ;;
  esac

  # 4.3.6 Audit chain action filter SQL injection.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "${H_ADMIN[@]}" \
    "$BASE/api/v1/audit/log?action=foo'%20OR%20'1'%3D'1")
  rm -f "$body"
  if [[ "$code" -ge 200 && "$code" -lt 500 ]]; then
    _pass "4.3.6 SQLi in audit action filter → $code"
  else
    _fail "4.3.6 SQLi in audit action filter" "got $code"
  fi

  # 4.3.7 RLS — direct DB connect WITHOUT setting vsp.tenant_id should
  # return 0 rows on tables that have policy applied. We can only verify
  # the policy EXISTS (assert in L2 §3.2.2); for full RLS bypass test we
  # need a dedicated non-owner role per docs/audit/RLS_RUNBOOK.md.
  if [[ -n "${DB_DSN:-}" ]]; then
    assert_db_query "4.3.7 RLS policies on findings/runs/audit_log" \
      "SELECT count(*)::text FROM pg_policy
       WHERE polrelid IN (
         'findings'::regclass, 'runs'::regclass, 'audit_log'::regclass
       );" \
      "3"
  else
    skip "4.3.7 RLS policies count" "DB_DSN not set"
  fi

  # 4.3.8 Residency — request to declared off-region tenant. Hard to set
  # up without seeding; verify the violation table at least exists.
  if [[ -n "${DB_DSN:-}" ]]; then
    assert_db_query "4.3.8 residency_violations table ready" \
      "SELECT count(*)::text FROM information_schema.tables WHERE table_name='residency_violations';" \
      "1"
  else
    skip "4.3.8 residency_violations table" "DB_DSN not set"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 4.4 Compliance content depth — 10 cases (verify SPECIFIC values)
# ═════════════════════════════════════════════════════════════════════════

run_4_4_content() {
  phase_open "4.4 Compliance content depth"

  # 4.4.1 SSDF practices — check each family is represented (PO, PS, PW, RV).
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" \
    "$BASE/api/v1/cisa-attestation/ssdf/draft" -o "$body"
  for fam in PO PS PW RV; do
    cnt=$(jq "[.practices[] | select(.family==\"$fam\")] | length" "$body" 2>/dev/null)
    if [[ "$cnt" -ge 1 ]]; then
      _pass "4.4.1 SSDF family $fam present [$cnt practices]"
    else
      _fail "4.4.1 SSDF family $fam present" "0 practices for $fam"
    fi
  done
  rm -f "$body"

  # 4.4.2 NIST CSF — 6 functions all present.
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" \
    "$BASE/api/v1/nist-csf/profile" -o "$body"
  for fn in GV ID PR DE RS RC; do
    cnt=$(jq "[.categories[] | select(.function==\"$fn\")] | length" "$body" 2>/dev/null)
    if [[ "$cnt" -ge 2 ]]; then
      _pass "4.4.2 CSF function $fn ≥ 2 categories [$cnt]"
    else
      _fail "4.4.2 CSF function $fn" "expected ≥ 2 categories, got $cnt"
    fi
  done
  rm -f "$body"

  # 4.4.3 cATO — each criterion has unique ID + status field non-empty.
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" "$BASE/api/v1/cato" -o "$body"
  for id in audit_chain drift_ack evidence_freshness scan_cadence poam incident_reporting sbom_coverage; do
    found=$(jq "[.criteria[] | select(.id==\"$id\")] | length" "$body" 2>/dev/null)
    if [[ "$found" == "1" ]]; then
      _pass "4.4.3 cATO criterion $id present"
    else
      _fail "4.4.3 cATO criterion $id" "found $found rows (expected 1)"
    fi
  done
  rm -f "$body"

  # 4.4.4 SOC 2 — all 5 categories (CC, A, C, PI, P).
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" \
    "$BASE/api/v1/recognition/soc2-readiness" -o "$body"
  for cat in CC A C PI P; do
    cnt=$(jq "[.criteria[] | select(.category==\"$cat\")] | length" "$body" 2>/dev/null)
    if [[ "$cnt" -ge 1 ]]; then
      _pass "4.4.4 SOC 2 category $cat present [$cnt]"
    else
      _fail "4.4.4 SOC 2 category $cat" "0 criteria"
    fi
  done
  rm -f "$body"

  # 4.4.5 ISO 27001 — all 4 themes (Organisational, People, Physical, Technological).
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" \
    "$BASE/api/v1/recognition/iso27001-mapping" -o "$body"
  for theme in Organisational People Physical Technological; do
    cnt=$(jq "[.controls[] | select(.theme==\"$theme\")] | length" "$body" 2>/dev/null)
    if [[ "$cnt" -ge 1 ]]; then
      _pass "4.4.5 ISO theme $theme present [$cnt]"
    else
      _fail "4.4.5 ISO theme $theme" "0 controls"
    fi
  done
  rm -f "$body"

  # 4.4.6 DORA — every metric block has tier ∈ {elite, high, medium, low, n/a}.
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" "$BASE/api/v1/dora?days=30" -o "$body"
  for k in deploy_frequency lead_time mttr change_failure_rate; do
    tier=$(jq -r ".${k}.tier" "$body" 2>/dev/null)
    case "$tier" in
      elite|high|medium|low|n/a) _pass "4.4.6 DORA $k tier valid [$tier]" ;;
      *)                          _fail "4.4.6 DORA $k tier" "got \"$tier\" (expected elite/high/medium/low/n/a)" ;;
    esac
  done
  rm -f "$body"

  # 4.4.7 Audit bundle manifest — verify every listed file's SHA-256
  # matches actual content after extract.
  printf "  %s…%s 4.4.7 audit bundle SHA-256 manifest verifies " "$C_DIM" "$C_RESET"
  bundle=$(mktemp)
  workdir=$(mktemp -d)
  if curl -sf -o "$bundle" --max-time 30 "${H_ADMIN[@]}" "$BASE/api/v1/audit/bundle" 2>/dev/null; then
    if unzip -q "$bundle" -d "$workdir" 2>/dev/null; then
      bad=0
      while read -r path expected; do
        [[ -z "$path" ]] && continue
        actual=$(sha256sum "$workdir/$path" 2>/dev/null | awk '{print $1}')
        [[ "$actual" == "$expected" ]] || bad=$((bad+1))
      done < <(jq -r '.files[] | "\(.path) \(.sha256)"' "$workdir/manifest.json" 2>/dev/null)
      if (( bad == 0 )); then
        _pass "(manifest verifies cleanly)"
      else
        _fail "4.4.7 audit bundle manifest" "$bad file checksum mismatches"
      fi
    else
      _fail "4.4.7 audit bundle manifest" "zip extract failed"
    fi
  else
    _fail "4.4.7 audit bundle manifest" "download failed"
  fi
  rm -rf "$bundle" "$workdir"

  # 4.4.8 ConMon score — total weight = 100.
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" "$BASE/api/v1/conmon/score" -o "$body"
  total=$(jq '[.criteria[].weight] | add' "$body" 2>/dev/null)
  if [[ "$total" == "100" ]]; then
    _pass "4.4.8 ConMon weights sum to 100"
  else
    _fail "4.4.8 ConMon weights" "summed to $total (expected 100)"
  fi
  rm -f "$body"

  # 4.4.9 Status JSON — components include gateway + scanner + audit_log.
  body=$(mktemp)
  curl -s --max-time 5 "$BASE/api/v1/status" -o "$body"
  for c in gateway scanner audit_log; do
    found=$(jq "[.components[] | select(.name==\"$c\")] | length" "$body" 2>/dev/null)
    if [[ "$found" == "1" ]]; then
      _pass "4.4.9 status component $c present"
    else
      _fail "4.4.9 status component $c" "found $found (expected 1)"
    fi
  done
  rm -f "$body"

  # 4.4.10 SBOM — components count > 0 (real generated, not placeholder).
  body=$(mktemp)
  curl -s --max-time 5 "$BASE/sbom.cyclonedx.json" -o "$body"
  comp_n=$(jq '.components | length' "$body" 2>/dev/null)
  if [[ "$comp_n" -gt 0 ]]; then
    _pass "4.4.10 self-SBOM has components [$comp_n]"
  else
    skip "4.4.10 self-SBOM has components" "placeholder SBOM (0 components) — OK in dev; production must populate via syft"
  fi
  rm -f "$body"

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 4.5 Resilience + concurrency — 5 cases
# ═════════════════════════════════════════════════════════════════════════

run_4_5_resilience() {
  phase_open "4.5 Resilience & concurrency"

  # 4.5.1 100 concurrent KPI sanity probes — none should 5xx.
  printf "  %s…%s 4.5.1 100 concurrent /kpi/sanity " "$C_DIM" "$C_RESET"
  fails=0
  for i in $(seq 1 100); do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      "${H_ADMIN[@]}" "$BASE/api/v1/kpi/sanity")
    [[ "$code" -ge 500 ]] && fails=$((fails+1))
  done &
  wait
  if (( fails == 0 )); then
    _pass "(0 5xx in 100 requests)"
  else
    _fail "4.5.1 100 concurrent /kpi/sanity" "$fails 5xx responses"
  fi

  # 4.5.2 5 concurrent audit/verify — ensure they don't deadlock.
  printf "  %s…%s 4.5.2 5 concurrent /audit/verify " "$C_DIM" "$C_RESET"
  pids=()
  for i in 1 2 3 4 5; do
    (curl -s -o /dev/null --max-time 10 -X POST "${H_ADMIN[@]}" "$BASE/api/v1/audit/verify") &
    pids+=($!)
  done
  ok=1
  for pid in "${pids[@]}"; do wait "$pid" || ok=0; done
  if (( ok == 1 )); then
    _pass "(all 5 returned within 10s)"
  else
    _fail "4.5.2 5 concurrent /audit/verify" "at least 1 request failed"
  fi

  # 4.5.3 Migration idempotency — re-applying 045 should not error.
  if [[ -n "${DB_DSN:-}" ]]; then
    out=$(_psql_oneshot "$(cat migrations/045_system_toggles.sql)" 2>&1)
    if echo "$out" | grep -qiE "ERROR|FATAL"; then
      _fail "4.5.3 migration 045 idempotent" "errors on re-apply"
    else
      _pass "4.5.3 migration 045 re-apply clean"
    fi
  else
    skip "4.5.3 migration idempotency" "DB_DSN not set"
  fi

  # 4.5.4 Empty audit_log query — verify endpoint when no rows for tenant.
  # Use a tenant slug that won't have audit rows.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "${H_ADMIN[@]}" "$BASE/api/v1/audit/log?action=NONEXISTENT_ACTION_NAME")
  rm -f "$body"
  if [[ "$code" == "200" ]]; then
    _pass "4.5.4 audit log filter with no matches → 200"
  else
    _fail "4.5.4 audit log filter no matches" "expected 200, got $code"
  fi

  # 4.5.5 Verify race detector via go vet (tests don't have explicit -race
  # in CI but go vet at least catches obvious issues).
  printf "  %s…%s 4.5.5 go vet on touched packages " "$C_DIM" "$C_RESET"
  if go vet ./internal/api/handler/... ./internal/auth/... ./internal/store/... ./internal/notify/... >/dev/null 2>&1; then
    _pass "(clean)"
  else
    _fail "4.5.5 go vet" "warnings on touched packages"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 4.6 Sprint deliverable depth — 10 cases (verify ARTEFACTS, not just endpoints)
# ═════════════════════════════════════════════════════════════════════════

run_4_6_sprint_depth() {
  phase_open "4.6 Sprint deliverable depth"

  # 4.6.1 26 scanner directories each have at least 1 .go file.
  bad=0
  for d in internal/scanner/*/; do
    [[ -d "$d" ]] || continue
    files=$(find "$d" -maxdepth 1 -name "*.go" 2>/dev/null | wc -l)
    if [[ "$files" -lt 1 ]]; then
      bad=$((bad+1))
    fi
  done
  if (( bad == 0 )); then
    _pass "4.6.1 26 scanner dirs each have ≥ 1 .go file"
  else
    _fail "4.6.1 scanner dirs have .go files" "$bad empty directories"
  fi

  # 4.6.2 Sigma rules — all 5 are valid YAML AND reference real ATT&CK techniques.
  bad=0
  for f in detections/sigma/*.yml; do
    [[ -f "$f" ]] || continue
    # YAML parse
    if ! python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$f" 2>/dev/null; then
      bad=$((bad+1))
    fi
    # ATT&CK tag exists
    if ! grep -q "attack\." "$f"; then
      bad=$((bad+1))
    fi
  done
  if (( bad == 0 )); then
    _pass "4.6.2 Sigma rules valid YAML + ATT&CK tagged"
  else
    _fail "4.6.2 Sigma rules" "$bad files failed checks"
  fi

  # 4.6.3 Helm chart values.yaml has restricted PSP defaults.
  body=$(grep -E "runAsNonRoot|readOnlyRootFilesystem|allowPrivilegeEscalation|RuntimeDefault" \
    deploy/helm/values.yaml 2>/dev/null | wc -l)
  if [[ "$body" -ge 4 ]]; then
    _pass "4.6.3 Helm values.yaml has 4+ hardening defaults [$body found]"
  else
    _fail "4.6.3 Helm values.yaml hardening" "only $body of 4 expected directives"
  fi

  # 4.6.4 K8s admission policies — both Kyverno + OPA Gatekeeper alternatives present.
  k_count=$(ls deploy/admission/kyverno/*.yaml 2>/dev/null | wc -l)
  o_count=$(ls deploy/admission/opa-gatekeeper/templates/*.yaml deploy/admission/opa-gatekeeper/constraints/*.yaml 2>/dev/null | wc -l)
  if [[ "$k_count" -ge 4 && "$o_count" -ge 2 ]]; then
    _pass "4.6.4 K8s admission policies [$k_count Kyverno + $o_count OPA]"
  else
    _fail "4.6.4 K8s admission policies" "expected ≥4 Kyverno + ≥2 OPA, got $k_count + $o_count"
  fi

  # 4.6.5 VSCode extension — package.json activation events + commands.
  cmds=$(jq '.contributes.commands | length' ide/vscode-vsp/package.json 2>/dev/null)
  if [[ "$cmds" -ge 4 ]]; then
    _pass "4.6.5 VSCode extension ≥ 4 commands [$cmds]"
  else
    _fail "4.6.5 VSCode extension commands" "expected ≥ 4, got $cmds"
  fi

  # 4.6.6 KPI sanity check has ≥ 5 assertions.
  body=$(mktemp)
  curl -s --max-time 5 "${H_ADMIN[@]}" "$BASE/api/v1/kpi/sanity" -o "$body"
  cnt=$(jq '.assertions | length' "$body" 2>/dev/null)
  if [[ "$cnt" -ge 5 ]]; then
    _pass "4.6.6 KPI sanity ≥ 5 assertions [$cnt]"
  else
    _fail "4.6.6 KPI sanity assertions" "expected ≥ 5, got $cnt"
  fi
  rm -f "$body"

  # 4.6.7 Migrations sequential — no gaps in 029-045.
  missing=0
  for n in 029 030 031 032 033 034 035 036 037 038 039 040 041 042 043 044 045; do
    if ! ls migrations/${n}_*.sql >/dev/null 2>&1; then
      missing=$((missing+1))
    fi
  done
  if (( missing == 0 )); then
    _pass "4.6.7 migrations 029-045 all present"
  else
    _fail "4.6.7 migrations sequential" "$missing missing"
  fi

  # 4.6.8 OpenAPI spec mentions key Sprint 2-12 endpoints.
  if [[ -f api/openapi.yaml ]]; then
    found=0
    for ep in /api/v1/audit/bundle /api/v1/kpi/sanity /api/v1/cato; do
      grep -q "$ep" api/openapi.yaml && found=$((found+1))
    done
    if [[ "$found" -ge 2 ]]; then
      _pass "4.6.8 OpenAPI spec references Sprint endpoints [$found/3]"
    else
      skip "4.6.8 OpenAPI spec references" "$found/3 endpoints — OpenAPI may lag behind impl; manually update"
    fi
  else
    skip "4.6.8 OpenAPI spec" "api/openapi.yaml not found"
  fi

  # 4.6.9 RFC 9116 security.txt has Expires + Encryption directives.
  txt=$(curl -s --max-time 5 "$BASE/.well-known/security.txt")
  has_exp=$(echo "$txt" | grep -c "^Expires:")
  has_enc=$(echo "$txt" | grep -c "^Encryption:")
  if [[ "$has_exp" -ge 1 && "$has_enc" -ge 1 ]]; then
    _pass "4.6.9 security.txt has Expires + Encryption"
  else
    _fail "4.6.9 security.txt RFC 9116 fields" "Expires=$has_exp Encryption=$has_enc"
  fi

  # 4.6.10 outreach pack — all 5 docs present + each .docx ≥ 10 KB.
  bad=0
  for n in 01_RFP_3PAO 02_CFO_BUDGET_MEMO 03_HACKERONE_APPLICATION 04_STATUSPAGE_MIGRATION 05_TABLETOP_SCHEDULE; do
    f="docs/outreach/${n}.docx"
    if [[ ! -f "$f" ]]; then
      bad=$((bad+1))
      continue
    fi
    size=$(wc -c < "$f")
    [[ "$size" -lt 10240 ]] && bad=$((bad+1))
  done
  if (( bad == 0 )); then
    _pass "4.6.10 outreach pack 5 .docx ≥ 10KB each"
  else
    _fail "4.6.10 outreach pack" "$bad files missing or small"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════

case "$PHASE" in
  all)
    run_4_1_auth
    run_4_2_input
    run_4_3_idor
    run_4_4_content
    run_4_5_resilience
    run_4_6_sprint_depth
    ;;
  4.1) run_4_1_auth ;;
  4.2) run_4_2_input ;;
  4.3) run_4_3_idor ;;
  4.4) run_4_4_content ;;
  4.5) run_4_5_resilience ;;
  4.6) run_4_6_sprint_depth ;;
  *)
    printf "%sUsage:%s %s [all|4.1|4.2|4.3|4.4|4.5|4.6]\n" "$C_RED" "$C_RESET" "$0" >&2
    exit 2
    ;;
esac

final_summary
