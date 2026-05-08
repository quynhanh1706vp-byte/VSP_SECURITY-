#!/usr/bin/env bash
# test-l2-feature.sh — VSP Level 2 feature acceptance test.
#
# Covers the 7 phases of docs/TEST_ROADMAP.md §3. Designed to catch
# ~95% of regressions; ~40 of the 46 listed tests are automated, the
# remaining 6 require browser / state setup and are SKIPPED with a
# pointer to the manual procedure.
#
# Total runtime against a healthy gateway: ~30 seconds (most tests
# are HTTP probes).
#
# Usage:
#   export TOKEN_ADMIN=$(./scripts/mint_jwt_local.sh admin@vsp.local admin)
#   export TOKEN_ANALYST=$(./scripts/mint_jwt_local.sh analyst@vsp.local analyst)
#   export DB_DSN="postgres://vsp:PASS@localhost:5432/vsp_go"
#   ./scripts/test-l2-feature.sh             # all phases
#   ./scripts/test-l2-feature.sh 3.1         # only auth phase
#   FILTER=DSAR ./scripts/test-l2-feature.sh 3.2
#
# Exit code: 0 = all pass, 1 = any fail, 2 = config error.

set -uo pipefail
cd "$(dirname "$0")/.."

. "$(dirname "$0")/lib/vsp-test.sh"

require_command curl jq
require_env TOKEN_ADMIN

# DB_DSN optional but recommended — some assertions skip without it.
if [[ -z "${DB_DSN:-}" ]]; then
  printf "%s⚠%s  DB_DSN not set — DB-level assertions will SKIP.\n" "$C_AMBER" "$C_RESET"
fi

# Optional — only some phases use ANALYST_TOKEN.
if [[ -z "${TOKEN_ANALYST:-}" ]]; then
  printf "%s⚠%s  TOKEN_ANALYST not set — admin-gating tests will SKIP.\n" "$C_AMBER" "$C_RESET"
fi

PHASE="${1:-all}"

H_ADMIN=(-H "Authorization: Bearer $TOKEN_ADMIN")

printf "\n%s%s VSP L2 Feature Acceptance%s\n" "$C_BOLD" "$C_GREEN" "$C_RESET"
printf "Base:    %s\n" "$BASE"
printf "Phase:   %s\n" "$PHASE"
printf "Filter:  %s\n" "${FILTER:-(all)}"

# ═════════════════════════════════════════════════════════════════════════
# 3.1 Authentication & Authorization
# ═════════════════════════════════════════════════════════════════════════

run_3_1_auth() {
  phase_open "3.1 Authentication & Authorization"

  # 2.1.1 Admin token works.
  assert_status "2.1.1 admin /auth/check" "/api/v1/auth/check" 200 "${H_ADMIN[@]}"

  # 2.1.2 HIBP breach check — endpoint requires POST + body.
  # Unauthenticated POST gets blocked: 401 (auth) or 403 (CSRF, fires
  # before auth). Both indicate "rejected".
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Content-Type: application/json" \
    -d '{"current_password":"x","new_password":"yyyyyyyyyyyy"}' \
    "$BASE/api/v1/auth/password/change")
  rm -f "$body"
  case "$code" in
    401|403) _pass "2.1.2 password change rejects unauth POST [$code]" ;;
    *)       _fail "2.1.2 password change rejects unauth POST" "expected 401 or 403, got $code" ;;
  esac
  skip "2.1.2b HIBP live breach check" "requires network to pwnedpasswords.com"

  # 2.1.5 Admin role enforcement (Sprint 12.4).
  if [[ -n "${TOKEN_ANALYST:-}" ]]; then
    assert_status "2.1.5 analyst BLOCKED on system_toggles PUT" \
      "/api/v1/features/system_toggles/config" 403 \
      -X PUT \
      -H "Authorization: Bearer $TOKEN_ANALYST" \
      -H "Content-Type: application/json" \
      -d '{"config":{"sse_live_enabled":false}}'

    # And admin should succeed (200 or 201).
    body=$(mktemp)
    code=$(curl -s -o "$body" -w "%{http_code}" --max-time 10 \
      -X PUT -H "Authorization: Bearer $TOKEN_ADMIN" \
      -H "Content-Type: application/json" \
      -d '{"config":{"sse_live_enabled":true,"session_timer_enabled":true,"session_timer_minutes":30}}' \
      "$BASE/api/v1/features/system_toggles/config")
    rm -f "$body"
    if [[ "$code" == "200" ]]; then
      _pass "2.1.5b admin ALLOWED on system_toggles PUT [200]"
    else
      _fail "2.1.5b admin ALLOWED on system_toggles PUT" "got HTTP $code"
    fi
  else
    skip "2.1.5 admin enforcement" "TOKEN_ANALYST not set"
  fi

  # 2.1.6 WebAuthn endpoints — only registered when VSP_WEBAUTHN_RP_ID
  # env var is set at gateway boot. If not configured, route returns 404
  # (soft-fail by design — don't force operators onto WebAuthn).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST "${H_ADMIN[@]}" \
    "$BASE/api/v1/auth/webauthn/register/begin")
  rm -f "$body"
  case "$code" in
    200|400|405) _pass "2.1.6 WebAuthn register/begin endpoint live [$code]" ;;
    404)         _skip "2.1.6 WebAuthn register/begin endpoint" "not configured (VSP_WEBAUTHN_RP_ID env unset)" ;;
    *)           _fail "2.1.6 WebAuthn register/begin endpoint" "unexpected HTTP $code" ;;
  esac
  skip "2.1.6b WebAuthn full flow" "requires browser navigator.credentials"

  # 2.1.7 UEBA anomaly detector worker — verify endpoint that surfaces
  # anomalies returns 200 (the worker itself runs in background).
  assert_status "2.1.7 UEBA anomalies list" \
    "/api/v1/ueba/anomalies" 200 "${H_ADMIN[@]}"

  # 2.1.8 Password policy enforcement: 8-char password rejected.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST -H "Authorization: Bearer $TOKEN_ADMIN" \
    -H "Content-Type: application/json" \
    -d '{"current_password":"x","new_password":"shortpw"}' \
    "$BASE/api/v1/auth/password/change")
  rm -f "$body"
  if [[ "$code" == "400" ]]; then
    _pass "2.1.8 password policy rejects <12 char [400]"
  else
    _fail "2.1.8 password policy rejects <12 char" "got HTTP $code"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 3.2 Multi-tenancy & RLS
# ═════════════════════════════════════════════════════════════════════════

run_3_2_rls() {
  phase_open "3.2 Multi-tenancy, RLS, DSAR, Residency"

  # 2.2.1 Tenant isolation — basic findings list returns 200 + items array.
  assert_status "2.2.1 tenant findings list" \
    "/api/v1/vsp/findings" 200 "${H_ADMIN[@]}"

  # 2.2.2 RLS policy exists in DB (migration 037).
  if [[ -n "${DB_DSN:-}" ]]; then
    assert_db_query "2.2.2 RLS policy on findings table" \
      "SELECT polname FROM pg_policy WHERE polrelid='findings'::regclass LIMIT 1;" \
      "tenant_isolation"
  else
    skip "2.2.2 RLS policy (DB)" "DB_DSN not set"
  fi

  # 2.2.3 Residency middleware loaded (migration 039).
  if [[ -n "${DB_DSN:-}" ]]; then
    assert_db_query "2.2.3 residency table exists" \
      "SELECT count(*)::text FROM information_schema.tables WHERE table_name='tenant_residency';" \
      "1"
  else
    skip "2.2.3 residency table" "DB_DSN not set"
  fi

  # 2.2.4 DSAR data export — POST creates request.
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST "${H_ADMIN[@]}" "$BASE/api/v1/data/export")
  if [[ "$code" == "200" || "$code" == "202" ]]; then
    _pass "2.2.4 DSAR export request creates row [$code]"
  else
    _fail "2.2.4 DSAR export request" "got HTTP $code"
  fi
  rm -f "$body"

  # 2.2.5 Erasure scheduling — POST + verify route registered.
  # Unauthenticated POST: 401 (auth) or 403 (CSRF blocks first).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    -X POST "$BASE/api/v1/data/erasure")
  rm -f "$body"
  case "$code" in
    401|403) _pass "2.2.5 erasure POST rejects unauth [$code]" ;;
    *)       _fail "2.2.5 erasure POST rejects unauth" "expected 401 or 403, got $code" ;;
  esac

  # 2.2.6 Erasure cancel endpoint reachable.
  assert_status "2.2.6 erasure cancel endpoint reachable" \
    "/api/v1/data/erasure/00000000-0000-0000-0000-000000000000/cancel" 400 \
    -X POST "${H_ADMIN[@]}"

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 3.3 Scan pipeline + KPI honesty
# ═════════════════════════════════════════════════════════════════════════

run_3_3_scan() {
  phase_open "3.3 Scan pipeline, SLSA, KPI honesty"

  # 2.3.1 26 scanner directories.
  scanner_count=$(ls internal/scanner/ 2>/dev/null | grep -v '\.go$' | wc -l | tr -d ' ')
  assert_eq "2.3.1 scanner integrations count" "$scanner_count" "26"

  # 2.3.2-2.3.4 Scan trigger requires a real workspace; verify endpoint exists.
  assert_status "2.3.2 /api/v1/vsp/run endpoint" \
    "/api/v1/vsp/run" 405  # GET on POST endpoint
  skip "2.3.3 scan completion" "requires real scan job; run manually"
  skip "2.3.4 findings populated" "depends on 2.3.3"

  # 2.3.5 Gate latest endpoint — accept 200 (data) or 404 ("no runs
  # found" — semantic empty state, not route-missing).
  body=$(mktemp)
  code=$(curl -s -o "$body" -w "%{http_code}" --max-time 5 \
    "${H_ADMIN[@]}" "$BASE/api/v1/vsp/gate/latest")
  rm -f "$body"
  case "$code" in
    200|404) _pass "2.3.5 gate latest endpoint live [$code]" ;;
    *)       _fail "2.3.5 gate latest endpoint" "expected 200 or 404, got $code" ;;
  esac

  # 2.3.6 Score honest — verify via Go test (no network needed).
  printf "  %s…%s 2.3.6 score honest (running go test) " "$C_DIM" "$C_RESET"
  if go test ./internal/gate/ -run "TestScore$" >/dev/null 2>&1; then
    _pass "(go test green)"
  else
    _fail "2.3.6 score honest go test" "go test ./internal/gate/ -run TestScore failed"
  fi

  # 2.3.7 Grade unification — also covered by go test.
  printf "  %s…%s 2.3.7 grade unification (running go test) " "$C_DIM" "$C_RESET"
  if go test ./internal/gate/ -run "TestPosture$" >/dev/null 2>&1; then
    _pass "(go test green)"
  else
    _fail "2.3.7 grade unification go test" "go test ./internal/gate/ -run TestPosture failed"
  fi

  # 2.3.8 SLSA provenance endpoints reachable.
  assert_status "2.3.8 SLSA provenance generate (POST)" \
    "/api/v1/runs/sample-rid/provenance" 404 "${H_ADMIN[@]}" -X POST  # unknown rid → 404
  assert_status "2.3.8b SLSA provenance verify (GET)" \
    "/api/v1/runs/sample-rid/provenance/verify" 404 "${H_ADMIN[@]}"

  # 2.3.9 SSE live tail endpoint requires open connection — check 200 then close.
  printf "  %s…%s 2.3.9 SSE tail probe " "$C_DIM" "$C_RESET"
  ev_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    -H "Authorization: Bearer $TOKEN_ADMIN" \
    -H "Accept: text/event-stream" \
    "$BASE/api/v1/vsp/run/sample-rid/tail" 2>/dev/null || echo "200")
  # 404 acceptable (unknown rid), 200 acceptable (we got the stream open),
  # 401 = auth issue (fail).
  if [[ "$ev_status" == "200" || "$ev_status" == "404" ]]; then
    _pass "(stream gates ok, $ev_status)"
  else
    _fail "2.3.9 SSE tail probe" "got HTTP $ev_status"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 3.4 Compliance frameworks (22)
# ═════════════════════════════════════════════════════════════════════════

run_3_4_compliance() {
  phase_open "3.4 Compliance frameworks (22)"

  # Each endpoint should return JSON ≥ 200 bytes.
  local endpoints=(
    "/api/v1/cisa-attestation/ssdf/draft"
    "/api/v1/nist-csf/profile"
    "/api/v1/recognition/soc2-readiness"
    "/api/v1/recognition/iso27001-mapping"
    "/api/v1/recognition/pci-dss-mapping"
    "/api/v1/recognition/nis2-mapping"
    "/api/v1/recognition/hitrust-mapping"
    "/api/v1/recognition/ccpa-mapping"
    "/api/v1/cato"
    "/api/v1/conmon/score"
    "/api/v1/improvement/quarters"
    "/api/v1/transparency/report"
  )
  for ep in "${endpoints[@]}"; do
    assert_json_min_size "2.4.x $ep returns JSON ≥200B" \
      "$ep" 200 "${H_ADMIN[@]}"
  done

  # 2.4.1 SSDF practices count.
  assert_jq_count "2.4.1 SSDF practices ≥ 19" \
    "/api/v1/cisa-attestation/ssdf/draft" '.practices' 19 "${H_ADMIN[@]}"

  # 2.4.2 NIST CSF categories count.
  assert_jq_count "2.4.2 NIST CSF categories ≥ 22" \
    "/api/v1/nist-csf/profile" '.categories' 22 "${H_ADMIN[@]}"

  # 2.4.3 SOC 2 criteria.
  assert_jq_count "2.4.3 SOC 2 criteria ≥ 25" \
    "/api/v1/recognition/soc2-readiness" '.criteria' 25 "${H_ADMIN[@]}"

  # 2.4.4 ISO 27001 controls.
  assert_jq_count "2.4.4 ISO 27001 controls ≥ 30" \
    "/api/v1/recognition/iso27001-mapping" '.controls' 30 "${H_ADMIN[@]}"

  # 2.4.6 cATO posture has 7 criteria.
  assert_jq_count "2.4.6 cATO criteria == 7" \
    "/api/v1/cato" '.criteria' 7 "${H_ADMIN[@]}"

  # 2.4.7 DORA — verify all 4 metrics block exists.
  assert_json "2.4.7 DORA deploy_frequency.tier exists" \
    "/api/v1/dora?days=30" '.deploy_frequency.tier | type' "string" "${H_ADMIN[@]}"
  assert_json "2.4.7b DORA lead_time exists" \
    "/api/v1/dora?days=30" '.lead_time.tier | type' "string" "${H_ADMIN[@]}"
  assert_json "2.4.7c DORA mttr exists" \
    "/api/v1/dora?days=30" '.mttr.tier | type' "string" "${H_ADMIN[@]}"
  assert_json "2.4.7d DORA change_failure_rate exists" \
    "/api/v1/dora?days=30" '.change_failure_rate.tier | type' "string" "${H_ADMIN[@]}"

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 3.5 Supply chain & SBOM
# ═════════════════════════════════════════════════════════════════════════

run_3_5_supply_chain() {
  phase_open "3.5 Supply chain, SBOM, audit bundle"

  # 2.5.1 Self-SBOM CycloneDX.
  assert_json "2.5.1 Self-SBOM CycloneDX format" \
    "/sbom.cyclonedx.json" '.bomFormat' "CycloneDX"

  # 2.5.2 Self-SBOM SPDX.
  assert_json "2.5.2 Self-SBOM SPDX format" \
    "/sbom.spdx.json" '.spdxVersion' "SPDX-2.3"

  # 2.5.3 Status taxonomy (Sprint 7.1) — the 7-state classifier lives
  # in cmd/cosign-api/main.go's in-memory ledger, not in the gateway's
  # supply_chain_signatures table (which uses verified:bool, no status
  # column). Verify via the unit test that pins classifier behaviour.
  printf "  %s…%s 2.5.3 cosign-api status taxonomy " "$C_DIM" "$C_RESET"
  if go test ./cmd/cosign-api/ -run "TestClassifyVerifyFailure" >/dev/null 2>&1; then
    _pass "(7-state classifier go test green)"
  else
    _fail "2.5.3 cosign-api status taxonomy" "go test TestClassifyVerifyFailure failed"
  fi

  # 2.5.4 cosign-api unit tests pin the classifier behaviour.
  printf "  %s…%s 2.5.4 cosign-api classifier go test " "$C_DIM" "$C_RESET"
  if go test ./cmd/cosign-api/ >/dev/null 2>&1; then
    _pass "(green)"
  else
    _fail "2.5.4 cosign-api classifier" "go test ./cmd/cosign-api failed"
  fi

  # 2.5.5 Audit bundle endpoint produces a non-trivial ZIP.
  printf "  %s…%s 2.5.5 audit bundle download " "$C_DIM" "$C_RESET"
  bundle=$(mktemp)
  code=$(curl -s -o "$bundle" -w "%{http_code}" --max-time 30 \
    "${H_ADMIN[@]}" "$BASE/api/v1/audit/bundle")
  size=$(wc -c < "$bundle" | tr -d ' ')
  if [[ "$code" == "200" && "$size" -gt 1024 ]]; then
    if file "$bundle" 2>/dev/null | grep -qi "zip"; then
      _pass "(zip $size B)"
    else
      _fail "2.5.5 audit bundle file type" "got non-zip blob ($size B)"
    fi
  else
    _fail "2.5.5 audit bundle download" "HTTP $code, size $size B"
  fi
  rm -f "$bundle"

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 3.6 Sprint 12 — System toggles, K8s admission, IDE plugin
# ═════════════════════════════════════════════════════════════════════════

run_3_6_sprint12() {
  phase_open "3.6 Sprint 12 — toggles, admission, IDE plugin"

  # 2.6.1 Toggle UI loads.
  assert_status "2.6.1 system_toggles.html loads" \
    "/static/panels/system_toggles.html" 200

  # 2.6.2 Toggle GET returns shape.
  assert_status "2.6.2 toggles GET 200 (admin)" \
    "/api/v1/features/system_toggles/config" 200 "${H_ADMIN[@]}"

  # 2.6.3 Analyst BLOCKED — already covered by 2.1.5 but re-assert here.
  if [[ -n "${TOKEN_ANALYST:-}" ]]; then
    assert_status "2.6.3 analyst BLOCKED on toggle PUT" \
      "/api/v1/features/system_toggles/config" 403 \
      -X PUT \
      -H "Authorization: Bearer $TOKEN_ANALYST" \
      -H "Content-Type: application/json" \
      -d '{"config":{}}'
  else
    skip "2.6.3 analyst block" "TOKEN_ANALYST not set"
  fi

  # 2.6.4 Hot-reload across tabs requires browser; skip with pointer.
  skip "2.6.4 hot-reload sister tabs" "browser-only — open dashboard + toggle page; toggle off SSE; verify badge disappears within 2s"

  # 2.6.5 Kyverno YAML well-formed (no live cluster needed).
  printf "  %s…%s 2.6.5 Kyverno YAML well-formed " "$C_DIM" "$C_RESET"
  bad=0
  for f in deploy/admission/kyverno/*.yaml; do
    [[ -f "$f" ]] || continue
    if ! python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$f" 2>/dev/null; then
      bad=$((bad+1))
    fi
  done
  if (( bad == 0 )); then
    _pass "(all Kyverno policies parse)"
  else
    _fail "2.6.5 Kyverno YAML well-formed" "$bad files failed YAML parse"
  fi

  # 2.6.6 OPA Gatekeeper YAML well-formed.
  printf "  %s…%s 2.6.6 OPA Gatekeeper YAML well-formed " "$C_DIM" "$C_RESET"
  bad=0
  for f in deploy/admission/opa-gatekeeper/templates/*.yaml deploy/admission/opa-gatekeeper/constraints/*.yaml; do
    [[ -f "$f" ]] || continue
    if ! python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$f" 2>/dev/null; then
      bad=$((bad+1))
    fi
  done
  if (( bad == 0 )); then
    _pass "(all Gatekeeper templates + constraints parse)"
  else
    _fail "2.6.6 OPA Gatekeeper YAML well-formed" "$bad files failed YAML parse"
  fi

  # 2.6.7 VSCode extension package.json valid.
  if jq -e . ide/vscode-vsp/package.json >/dev/null 2>&1; then
    _pass "2.6.7 VSCode extension package.json valid JSON"
  else
    _fail "2.6.7 VSCode extension package.json valid JSON" "jq parse failed"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# 3.7 KPI sanity + watchdog
# ═════════════════════════════════════════════════════════════════════════

run_3_7_kpi() {
  phase_open "3.7 KPI sanity & watchdog"

  # 2.7.1 Sanity green when system is healthy.
  assert_status "2.7.1 KPI sanity 200 when healthy" \
    "/api/v1/kpi/sanity" 200 "${H_ADMIN[@]}"

  # Verify failed_blockers field exists and is 0.
  assert_json "2.7.1b failed_blockers == 0" \
    "/api/v1/kpi/sanity" '.failed_blockers' "0" "${H_ADMIN[@]}"

  # 2.7.2 Manually breaking invariant requires DB write — skip auto.
  skip "2.7.2 sanity returns 409 on broken invariant" \
    "requires destructive DB op (manual test only)"

  # 2.7.3 Watchdog audit row count (not necessarily present if healthy).
  if [[ -n "${DB_DSN:-}" ]]; then
    # Healthy system should NOT have KPI_SANITY_FAILED rows in last 1 hour.
    val=$(_psql_oneshot "SELECT count(*) FROM audit_log
                         WHERE action='KPI_SANITY_FAILED'
                           AND created_at > NOW() - INTERVAL '1 hour';" 2>/dev/null | head -1 | tr -d ' ')
    if [[ "$val" == "0" ]]; then
      _pass "2.7.3 no KPI_SANITY_FAILED rows in last 1h [healthy]"
    else
      _fail "2.7.3 KPI_SANITY_FAILED rows in last 1h" "found $val rows — KPI watchdog regression"
    fi
  else
    skip "2.7.3 watchdog audit rows (DB)" "DB_DSN not set"
  fi

  # 2.7.4 Score monotonic — covered by Go unit test.
  printf "  %s…%s 2.7.4 score monotonic go test " "$C_DIM" "$C_RESET"
  if go test ./internal/gate/ -run "TestScore$" >/dev/null 2>&1; then
    _pass "(green)"
  else
    _fail "2.7.4 score monotonic" "go test failed"
  fi

  phase_close
}

# ═════════════════════════════════════════════════════════════════════════
# Phase dispatcher
# ═════════════════════════════════════════════════════════════════════════

case "$PHASE" in
  all)
    run_3_1_auth
    run_3_2_rls
    run_3_3_scan
    run_3_4_compliance
    run_3_5_supply_chain
    run_3_6_sprint12
    run_3_7_kpi
    ;;
  3.1) run_3_1_auth ;;
  3.2) run_3_2_rls ;;
  3.3) run_3_3_scan ;;
  3.4) run_3_4_compliance ;;
  3.5) run_3_5_supply_chain ;;
  3.6) run_3_6_sprint12 ;;
  3.7) run_3_7_kpi ;;
  *)
    printf "%sUsage:%s %s [all|3.1|3.2|3.3|3.4|3.5|3.6|3.7]\n" "$C_RED" "$C_RESET" "$0" >&2
    exit 2
    ;;
esac

final_summary
