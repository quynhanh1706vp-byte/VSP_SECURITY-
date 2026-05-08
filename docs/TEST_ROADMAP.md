---
title: "VSP — Lộ trình Test chuẩn"
subtitle: "Release readiness verification, 3 levels"
author: "VSP Engineering"
date: "8 tháng 5, 2026"
---

# 0. Cách dùng tài liệu này

Tài liệu chia thành **3 level** theo thời gian + risk profile. Chọn level
phù hợp với mục đích:

| Level | Thời gian | Khi nào | Người chạy |
|-------|-----------|---------|------------|
| **L1 — Smoke** | 15 phút | Mỗi commit / mỗi deploy / mỗi sáng | Engineer |
| **L2 — Feature acceptance** | 2-3 giờ | Trước mỗi release / sau mỗi sprint | Engineer + QA |
| **L3 — Comprehensive** | 1 ngày | Trước major release / pentest / audit | QA + Security |

**Quy tắc vàng:**

1. Mỗi test có **PASS criteria rõ ràng** (HTTP status, JSON shape, hoặc visual check)
2. **Fail = stop + diagnose** trước khi tiếp tục — không skip
3. Ghi log vào template ở §10 để có audit trail
4. Phát hiện bug → tạo issue + commit fix + tạo regression test

---

# 1. Pre-flight checklist (5 phút)

Trước khi chạy bất kỳ level nào, verify:

```bash
# Gateway live
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8921/healthz
# Expected: 200 hoặc 404 (404 nếu /healthz chưa wired — không sao)

# Process check
systemctl status vsp-gateway | head -3
# Expected: Active: active (running)

# DB reachable từ gateway
journalctl -u vsp-gateway --since "5 min ago" | grep -i "connected\|database" | tail -3
# Expected: "database connected ✓"

# Migrations up to date
ls migrations/04*.sql | tail -5
# Expected: 040 → 045 present
```

**Auth setup** — bạn cần 3 tokens:

| Token | Role | Mục đích |
|-------|------|----------|
| `$ADMIN_TOKEN` | admin | Test admin endpoints (audit/repair, erasure, system_toggles) |
| `$ANALYST_TOKEN` | analyst | Test analyst endpoints + verify admin gating |
| `$ANON` | (không) | Test public endpoints (status, security.txt) |

```bash
# Mint tokens (dev mode)
ADMIN_TOKEN=$(./scripts/mint_jwt_local.sh admin@vsp.local admin)
ANALYST_TOKEN=$(./scripts/mint_jwt_local.sh analyst@vsp.local analyst)
echo "admin: ${ADMIN_TOKEN:0:30}..."
echo "analyst: ${ANALYST_TOKEN:0:30}..."
```

---

# 2. Level 1 — Smoke test (15 phút)

**Mục đích:** Gateway healthy, core endpoints respond, không regression rõ ràng.

**Pass criteria:** 9/9 checks pass.

| # | Test | Command | Expected |
|---|------|---------|----------|
| 1.1 | Gateway alive | `curl -s -o/dev/null -w "%{http_code}" http://127.0.0.1:8921/api/v1/auth/check -H "Authorization: Bearer $ADMIN_TOKEN"` | `200` |
| 1.2 | Auth required | `curl -s -o/dev/null -w "%{http_code}" http://127.0.0.1:8921/api/v1/findings` | `401` |
| 1.3 | Public status | `curl -s http://127.0.0.1:8921/api/v1/status \| jq .status` | `"operational"` hoặc tương đương |
| 1.4 | KPI sanity | `curl -s -o/dev/null -w "%{http_code}" http://127.0.0.1:8921/api/v1/kpi/sanity -H "Authorization: Bearer $ADMIN_TOKEN"` | `200` (KHÔNG được 409) |
| 1.5 | Audit chain | `curl -s -X POST http://127.0.0.1:8921/api/v1/audit/verify -H "Authorization: Bearer $ADMIN_TOKEN" \| jq .ok` | `true` |
| 1.6 | DORA metrics | `curl -s http://127.0.0.1:8921/api/v1/dora -H "Authorization: Bearer $ADMIN_TOKEN" \| jq .deploy_frequency.tier` | string không rỗng |
| 1.7 | Trust Center | `curl -s -o/dev/null -w "%{http_code}" http://127.0.0.1:8921/trust/` | `200` |
| 1.8 | security.txt | `curl -s http://127.0.0.1:8921/.well-known/security.txt \| grep -c "Contact:"` | `≥ 1` |
| 1.9 | Self-SBOM | `curl -s http://127.0.0.1:8921/sbom.cyclonedx.json \| jq .bomFormat` | `"CycloneDX"` |

**Nếu fail bất kỳ:** dừng + diagnose. Log lỗi vào template §10.

---

# 3. Level 2 — Feature acceptance (2-3 giờ)

**Mục đích:** Verify từng feature shipped trong Sprint 2-12 actually works.

Chia 7 nhóm. Mỗi nhóm có 3-5 acceptance test.

## 3.1 Authentication & Authorization (20 phút)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.1.1 | Login flow | POST `/api/v1/auth/login` với email/password đúng | 200 + JWT + cookie |
| 2.1.2 | HIBP check (Sprint 5.1) | POST `/auth/password/change` với `password` (breached) | 400 "appears in known breach corpus" |
| 2.1.3 | IP lockout (Sprint 6.1) | 21 lần login fail từ 1 IP trong 10 phút | Lần 21+: HTTP 429 "too many failed attempts" |
| 2.1.4 | Constant-time enum (Sprint 6.1) | Login với email không tồn tại + email tồn tại sai password | Cả 2 phải mất tương đương thời gian (≤ 5ms diff) |
| 2.1.5 | Admin role enforcement (Sprint 12.4) | Analyst token PUT `/api/v1/features/system_toggles/config` | 403 "admin role required" |
| 2.1.6 | WebAuthn register (Sprint 5.7) | POST `/api/v1/auth/webauthn/register/begin` với admin token | 200 + challenge JSON |
| 2.1.7 | UEBA session revoke (Sprint 6.2) | Login admin từ 3 IP /16 networks khác nhau trong 30 phút | UEBA detect impossible_travel → audit log có `SECURITY_REVOKE` row |
| 2.1.8 | Password policy | POST `/auth/password/change` với 8 ký tự | 400 "must be at least 12 characters" |

```bash
# 2.1.5 Admin enforcement — quick verify
curl -s -X PUT http://127.0.0.1:8921/api/v1/features/system_toggles/config \
     -H "Authorization: Bearer $ANALYST_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"config":{"sse_live_enabled":false}}'
# Expected: {"error":"forbidden — admin role required for system_toggles"}
```

## 3.2 Multi-tenancy & RLS (15 phút)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.2.1 | Tenant isolation (app-level) | Tenant A's admin token GET `/api/v1/findings` | Chỉ thấy findings của tenant A |
| 2.2.2 | RLS active (Sprint 5.6) | Direct DB query: `SELECT * FROM findings;` từ session-non-owner role | 0 rows (RLS blocks) |
| 2.2.3 | Residency 451 (Sprint 6.5) | Set `VSP_REGION=eu-1` + tenant declared `vn-1` → request | 451 Unavailable For Legal Reasons + audit row in `residency_violations` |
| 2.2.4 | DSAR export (Sprint 5.4) | POST `/api/v1/data/export` | 202 + job id |
| 2.2.5 | Erasure 30-day grace (Sprint 5.5) | POST `/api/v1/data/erasure` + token + `/confirm` + check `scheduled_at` | scheduled_at = now + 30 days |
| 2.2.6 | Erasure cancel | POST `/api/v1/data/erasure/{id}/cancel` trong 30-day window | 200 + status='cancelled' |

## 3.3 Scan pipeline (30 phút)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.3.1 | 26 scanners (Sprint 7 verify) | `ls internal/scanner/ \| grep -v '\.go$' \| wc -l` | `26` |
| 2.3.2 | Trigger scan | POST `/api/v1/vsp/run` với mode=FAST | 200 + rid |
| 2.3.3 | Scan completes | GET `/api/v1/vsp/run/{rid}` 60s sau | `status=COMPLETED` |
| 2.3.4 | Findings populated | GET `/api/v1/findings?rid={rid}` | `total > 0` |
| 2.3.5 | Gate decision | GET `/api/v1/vsp/gate/latest` | `decision ∈ {PASS, WARN, FAIL}` + score numeric |
| 2.3.6 | Score honest (Sprint 7.3) | Run scan với 5 high → check score | ~82 (NOT 60 — old capped math) |
| 2.3.7 | Grade unification (Sprint 7.2) | Scan có Critical>0 → check `posture` | `"F"` (hard-fail dominates) |
| 2.3.8 | SLSA provenance (Sprint 4.2) | POST `/api/v1/runs/{rid}/provenance` → GET `/verify` | `valid: true` |
| 2.3.9 | SSE live tail (Sprint 4.3) | Open EventSource cho `/api/v1/vsp/run/{rid}/tail` | Stream `status` + `finding` events |

```bash
# 2.3.6 Score honest — quick verify
psql ... -c "SELECT (summary->>'score')::int FROM runs WHERE rid='RID_TEST_5HIGH' LIMIT 1;"
# Expected: 80-85 (sqrt math)
# Bug if: 60 (old capped math — Sprint 7.3 regression)
```

## 3.4 Compliance frameworks (20 phút)

22 frameworks — verify mỗi cái trả 200 + JSON shape hợp lệ:

```bash
for ep in \
  /api/v1/cisa-attestation/ssdf/draft \
  /api/v1/nist-csf/profile \
  /api/v1/recognition/soc2-readiness \
  /api/v1/recognition/iso27001-mapping \
  /api/v1/recognition/pci-dss-mapping \
  /api/v1/recognition/nis2-mapping \
  /api/v1/recognition/hitrust-mapping \
  /api/v1/recognition/ccpa-mapping \
  /api/v1/cato \
  /api/v1/conmon/score \
  /api/v1/improvement/quarters \
  /api/v1/transparency/report \
; do
  status=$(curl -s -o /tmp/r.json -w "%{http_code}" \
    "http://127.0.0.1:8921$ep" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  size=$(wc -c < /tmp/r.json)
  echo "$status $size $ep"
done
# Expected: All 200, size > 100 bytes
```

| # | Test | Expected |
|---|------|----------|
| 2.4.1 | CISA SSDF practices | `practices.length == 19` |
| 2.4.2 | NIST CSF categories | `categories.length == 22` (trên 22 categories CSF 2.0) |
| 2.4.3 | SOC 2 criteria | `criteria.length >= 25` |
| 2.4.4 | ISO 27001 controls | `controls.length >= 30` |
| 2.4.5 | OSCAL endpoints | GET `/api/p4/oscal/{catalog,profile,ssp,assessment-plan}` đều 200 |
| 2.4.6 | cATO posture | `criteria.length == 7` + `overall ∈ {ready, at_risk, blocked}` |
| 2.4.7 | DORA metrics | 4 metrics có `tier` và `samples` |

## 3.5 Supply chain & SBOM (15 phút)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.5.1 | Self-SBOM CycloneDX | GET `/sbom.cyclonedx.json` | `bomFormat="CycloneDX"` + `specVersion` |
| 2.5.2 | Self-SBOM SPDX | GET `/sbom.spdx.json` | `spdxVersion="SPDX-2.3"` |
| 2.5.3 | Status taxonomy (Sprint 7.1) | `SELECT status, COUNT(*) FROM supply_chain_signatures GROUP BY 1` | KHÔNG có nhóm "tampered" với reason='no signatures found' |
| 2.5.4 | Cosign verify mock | Test classifyVerifyFailure unit test | `go test ./cmd/cosign-api/...` pass |
| 2.5.5 | Audit bundle | GET `/api/v1/audit/bundle` → save zip | Zip có `manifest.json` + 11 nhóm artefact |

```bash
# 2.5.5 Audit bundle
curl -OJL -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:8921/api/v1/audit/bundle
unzip -l vsp-audit-bundle-*.zip | head -20
# Expected: manifest.json, audit_log.jsonl, evidence/, slsa/, cato.json, dora.json, etc.
```

## 3.6 Sprint 12 — System toggles & K8s admission (15 phút)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.6.1 | Toggle UI loads | GET `/static/panels/system_toggles.html` | 200 + HTML |
| 2.6.2 | Toggle Save (admin) | PUT toggle config với admin token | 200 + DB row appears |
| 2.6.3 | Toggle Save (analyst) | PUT toggle config với analyst token | 403 "admin role required" |
| 2.6.4 | Hot-reload sister tabs | Open dashboard + toggle page → toggle off SSE → save | Dashboard tự reload sau 800ms, badge biến mất |
| 2.6.5 | Kyverno policy syntax | `kubectl apply --dry-run=server -f deploy/admission/kyverno/` | Apply success |
| 2.6.6 | OPA Gatekeeper syntax | `kubectl apply --dry-run=server -f deploy/admission/opa-gatekeeper/templates/` | Apply success |
| 2.6.7 | VSCode extension build | `cd ide/vscode-vsp && npm install && npm run package` | `vsp-security-0.1.0.vsix` produced |

## 3.7 KPI sanity & watchdog (10 phút)

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 2.7.1 | Sanity green | GET `/api/v1/kpi/sanity` healthy | 200 + `failed_blockers=0` |
| 2.7.2 | Sanity red | Manually break invariant (insert critical via DB) → re-run | 409 + assertion describes the break |
| 2.7.3 | Watchdog audit | Wait 5 min → check `audit_log WHERE action='KPI_SANITY_FAILED'` | 0 rows nếu healthy, 1+ nếu invariant broken |
| 2.7.4 | Score monotonic | gate.Score(High:5) > gate.Score(High:50) > gate.Score(High:500) | Strict decrease |

---

# 4. Level 3 — Comprehensive (1 ngày)

Bao gồm L1 + L2 + 3 phase sau:

## 4.1 Negative & security tests (1 giờ)

| # | Test | Attack | Expected defense |
|---|------|--------|------------------|
| 3.1.1 | SQL injection | `?id=1' OR '1'='1` trong tenant_id param | 400 "invalid id" hoặc 0 rows (RLS) |
| 3.1.2 | JWT none-alg | JWT với `alg: none` | 401 |
| 3.1.3 | JWT expired | Expired token | 401 |
| 3.1.4 | JWT tampered | Modified payload | 401 |
| 3.1.5 | CSRF token missing | POST không có X-VSP-CSRF | 403 (nếu CSRF middleware enabled) |
| 3.1.6 | Path traversal | `GET /api/v1/compliance/evidence/../../etc/passwd` | 400 "invalid id" |
| 3.1.7 | Oversized body | POST 11MB JSON | 413 hoặc 400 "too large" |
| 3.1.8 | Unicode normalization | Email với combining chars | Verify dedup hoạt động |
| 3.1.9 | Cross-tenant IDOR | Tenant A's admin GET tenant B's evidence ID | 404 (chứ KHÔNG 200) |
| 3.1.10 | Audit chain tamper | `UPDATE audit_log SET hash='xxx' WHERE seq=100;` | `/audit/verify` returns `ok=false` |

```bash
# 3.1.9 IDOR test
TENANT_B_EVID="f47ac10b-58cc-4372-a567-0e02b2c3d479"  # known evidence id from tenant B
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $ADMIN_TOKEN_TENANT_A" \
  http://127.0.0.1:8921/api/v1/compliance/evidence/$TENANT_B_EVID
# Expected: 404 (NOT 200)
```

## 4.2 Performance & resilience (45 phút)

| # | Test | Tool | Pass |
|---|------|------|------|
| 3.2.1 | k6 SLO baseline | `cd tests/load && make slo BASE_URL=http://127.0.0.1:8921 VSP_TOKEN=$ADMIN_TOKEN` | All 5 thresholds met (p95 < target) |
| 3.2.2 | k6 chaos | `make chaos BASE_URL=...` | 4/4 fault patterns rejected cleanly (no 5xx) |
| 3.2.3 | DB pool saturation | 100 concurrent requests | No timeouts, all succeed |
| 3.2.4 | SSE connection limit | Open 50 EventSource connections | Server handles, no crash |
| 3.2.5 | Memory leak | Run 1h continuous load | RSS growth < 50MB |

## 4.3 End-to-end personas (1.5 giờ)

### Persona 1 — CISO opens Trust Center

```
1. Browse to https://app.vsp.vn/trust/
   → Page loads với 6 attestation cards
   → Live status badges hiển thị
2. Click "Generate draft" trên CISA SSDF card
   → JSON với 19 practices auto-populated
3. Click "Audit bundle"
   → Download .zip
4. Open zip → verify manifest.json, audit_log.jsonl, evidence/, slsa/
```

### Persona 2 — DevSecOps in CI

```
1. Trigger scan từ pipeline
2. Wait for completion
3. GET /api/v1/kpi/sanity
   → 200 = release pass, 409 = release block
4. GET /api/v1/runs/{rid}/provenance
   → DSSE envelope returned
5. Optional: POST /provenance/publish-rekor
   → Rekor UUID returned
```

### Persona 3 — Bug bounty researcher

```
1. POST /api/v1/security/disclose anon (không cần JWT)
   với reporter_email + title + body + cvss
2. Receive 202 + ack_due_at + triage_due_at
3. Wait 1 business day
4. CISO logs in, GET /api/v1/security/disclosures
   → New row visible
5. CISO POST /transition with status='acknowledged'
   → public_ref generated (VSP-VDR-2026-NNNN)
```

### Persona 4 — Auditor / 3PAO

```
1. CISO sends docs/outreach/01_RFP_3PAO.docx
2. 3PAO requests audit bundle
3. CISO downloads /api/v1/audit/bundle → forwards
4. 3PAO unzips, verifies SHA-256 manifest
5. 3PAO verifies audit chain via /api/v1/audit/verify endpoint
6. 3PAO reads docs/audit/SCOPE_OF_TEST.md, RISK_REGISTER.md
```

### Persona 5 — Tenant admin (chủ thể dữ liệu)

```
1. Login as user@tenant.com
2. GET /api/v1/data/export → 202
3. Wait + GET /api/v1/data/exports/{id} → status=ready
4. Download export zip
5. (optional) POST /api/v1/data/erasure → 30-day grace start
6. Get erasure confirm token via email (out of scope — manual)
7. POST /confirm → status='processing'
```

---

# 5. Test log template

Tạo file `test-log-YYYY-MM-DD.md` mỗi ngày test:

```markdown
# VSP Test Log — 2026-05-08

**Tester:** _name_
**Level:** L1 / L2 / L3
**Gateway version:** _commit hash_
**Migration latest:** _NNN_

## L1 — Smoke (15 min)
| # | Test | Result | Notes |
|---|------|--------|-------|
| 1.1 | Gateway alive | ✓ PASS | 200 |
| 1.2 | Auth required | ✓ PASS | 401 |
| 1.3 | Public status | ✓ PASS | "operational" |
| 1.4 | KPI sanity | ✓ PASS | 200 |
| 1.5 | Audit chain | ✓ PASS | ok=true |
| 1.6 | DORA metrics | ✓ PASS | tier=elite |
| 1.7 | Trust Center | ✓ PASS | 200 |
| 1.8 | security.txt | ✓ PASS | Contact: present |
| 1.9 | Self-SBOM | ✓ PASS | CycloneDX |

**L1 result: 9/9 PASS — proceed to L2**

## L2 — Feature acceptance
... (per phase)

## Bugs found
| # | Severity | Description | Issue # |
|---|---------|-------------|---------|
| B-01 | P0 | _bug_ | _link_ |

## Sign-off
- Tester: _signature_
- Reviewer: _signature_
- Decision: ✓ Release / ✗ Block / ⚠ Release with caveats
```

---

# 6. Pre-release release gate checklist

Trước mỗi PR merge → main:

| Item | Check | Required |
|------|-------|----------|
| All Go tests pass | `go test ./...` | ✓ |
| golangci-lint clean | `golangci-lint run --enable=nilerr,sqlclosecheck` | ✓ |
| KPI sanity green | `curl /api/v1/kpi/sanity` returns 200 | ✓ |
| Audit chain intact | `curl -X POST /api/v1/audit/verify` returns `ok=true` | ✓ |
| Migrations sequential | `ls migrations/0*.sql` not skipping numbers | ✓ |
| L1 smoke (15 min) | All 9 checks PASS | ✓ |
| L2 feature acceptance | Affected phase tests PASS | ✓ |
| L3 comprehensive | Run before quarterly release | Optional |
| k6 SLO threshold | `make slo` exits 0 | ✓ before merge to main |
| 3PAO bundle download | Zip valid + SHA-256 manifest verified | ✓ before customer-facing release |

---

# 7. Tự động hoá — script gợi ý

```bash
#!/bin/bash
# scripts/test-l1-smoke.sh
# Run L1 smoke tests, exit 0 = all pass, 1 = any fail.

set -e
BASE="${VSP_BASE:-http://127.0.0.1:8921}"
TOKEN="${ADMIN_TOKEN:?ADMIN_TOKEN required}"
PASS=0; FAIL=0

check() {
  local name="$1"; local cmd="$2"; local expected="$3"
  local got=$(eval "$cmd" 2>&1)
  if [[ "$got" == "$expected" ]]; then
    echo "  ✓ $name"
    PASS=$((PASS+1))
  else
    echo "  ✗ $name (expected $expected, got $got)"
    FAIL=$((FAIL+1))
  fi
}

check "1.1 Gateway alive" \
  "curl -s -o/dev/null -w %{http_code} -H 'Authorization: Bearer $TOKEN' $BASE/api/v1/auth/check" \
  "200"

check "1.2 Auth required" \
  "curl -s -o/dev/null -w %{http_code} $BASE/api/v1/findings" \
  "401"

check "1.4 KPI sanity green" \
  "curl -s -o/dev/null -w %{http_code} -H 'Authorization: Bearer $TOKEN' $BASE/api/v1/kpi/sanity" \
  "200"

# ... (extend per §2)

echo
echo "Result: $PASS pass / $FAIL fail"
exit $FAIL
```

Lưu vào `scripts/test-l1-smoke.sh`, chạy mỗi sáng + mỗi deploy.

---

# 8. Đề xuất cadence

| Tần suất | Level | Owner | Output |
|---------|-------|-------|--------|
| Mỗi commit | L1 (CI auto) | GitHub Actions | Pass/fail check trên PR |
| Mỗi sáng | L1 (manual) | Engineer on-call | Slack #ops report |
| Trước mỗi sprint close | L2 đầy đủ | QA + Engineer | Test log signed |
| Trước mỗi quarterly release | L3 comprehensive | QA + Security + 1 Engineer | Test log + sign-off |
| Sau mỗi pentest finding | Affected L2 phase | Engineer | Regression test added |

---

# 9. Bottom line

- **L1 (15 phút)** → run hàng ngày, catch 80% regression
- **L2 (2-3 giờ)** → run mỗi sprint, catch 95% regression
- **L3 (1 ngày)** → run quarterly, catch 99% — kèm pentest engagement

**Recommend:** bắt đầu L1 ngay hôm nay (đã có sẵn endpoints + tokens), L2 trong tuần này, L3 trước Q3 audit window.

Test code-side issues bằng các test này; **process-side gaps** (3PAO contract, bug bounty platform) không test được trong code — đó là business sign-off.

---

*Tài liệu này pair với `docs/SPRINT_2026Q2_FINAL_REPORT.md` + `docs/EXECUTIVE_REPORT_2026Q2.md`. Update khi thêm feature mới — mỗi feature → ít nhất 1 acceptance test ở §3.*
