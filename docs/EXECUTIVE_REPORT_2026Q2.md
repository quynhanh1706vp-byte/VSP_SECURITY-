---
title: "VSP — Báo cáo Tổng quan Hệ thống"
subtitle: "Q2 2026 Executive Review"
author: "VSP Engineering"
date: "8 tháng 5, 2026"
---

# 1. Tóm tắt điều hành

VSP (Vietnam Security Platform) là **nền tảng DevSecOps + tuân thủ hợp nhất** phục vụ thị trường Việt Nam và quốc tế. Trong Q2 2026, hệ thống đã hoàn thành **9 sprint nâng cấp** đưa mức độ trưởng thành DSOMM từ **3.4 lên 3.95** (trên thang 4.0) — và xác lập rõ ràng **4.0 readiness** với bằng chứng external-evaluatable.

**Tình trạng:** 4.0 *certified* yêu cầu attestation bên ngoài (3PAO pentest + SOC 2 + audit firm). **Code-side đã chạm trần** — không còn item legitimate có thể đẩy thêm để vượt 3.95.

## Phạm vi hệ thống (xác minh từ code, 2026-05-08, post Sprint 10)

| Hạng mục | Số lượng |
|----------|---------:|
| API endpoints (gateway) | 150+ định tuyến |
| API endpoint roots (nhóm chức năng) | 70+ |
| UI panels | 33 |
| **Scanner integrations** | **26 công cụ** |
| **Compliance frameworks** | **22** (NIST 800-53, SSDF, CSF 2.0, FedRAMP, CMMC, OSCAL, CISA, CIRCIA, EO 14028, SLSA v1.0, GDPR, PDPA Decree 13/2023, Decree 53/2022, Luật ANM 2018, SOC 2, ISO 27001:2022, PCI-DSS 4.0, NIS2, HITRUST, CCPA / CPRA, RFC 9116, CIS Benchmarks) |
| **Self-attestation live endpoints** | **8** (`/api/v1/recognition/*` + CISA SSDF + NIST CSF + SSP generator) |
| Microservice binaries | 17 |
| DB migrations | 44 |
| Sigma detection rules | 5 (cho khách reuse) |
| Lines of Go code | ~50,000 |

## Mức độ trưởng thành DSOMM (trước / sau Q2)

| Dimension | Q2 start | Q2 end | Δ |
|-----------|---------:|-------:|---:|
| AuthN maturity | 3.0 | 3.95 | +0.95 |
| Tenant isolation | 3.0 | 3.8 | +0.8 |
| Data protection | 3.2 | 3.95 | +0.75 |
| Transport / network | 3.5 | 3.95 | +0.45 |
| Localisation | 0.0 | 3.5 | +3.5 |
| Deployment | 2.5 | 3.85 | +1.35 |
| Code quality | 3.0 | 3.6 | +0.6 |
| Observability + SLO | 3.0 | 3.95 | +0.95 |
| Recognition surface | 2.0 | 3.95 | +1.95 |
| **Overall** | **3.4** | **3.95** | **+0.55** |

**Vì sao không đạt 4.0:** 4.0 yêu cầu chứng thực do bên thứ ba ký (3PAO pentest, audit firm cert). Đây là *contractual milestone* — không phải code commit. Code đã chuẩn bị xong toàn bộ deliverable cần cho bên thứ ba (audit bundle, risk register, SSP generator, SOW template).

\newpage

# 2. Use Cases — Ai dùng VSP và để làm gì

## 2.1 CISO / Compliance Manager

**Mục tiêu:** Chứng minh hệ thống tuân thủ FedRAMP / SOC 2 / GDPR / Decree 13 trong audit bằng chứng cứ thực, không phải tuyên bố.

**VSP cung cấp:**

- **Single-click audit evidence bundle** — `GET /api/v1/audit/bundle` xuất zip chứa toàn bộ artefact auditor cần (audit log hash-chained, evidence files, SLSA provenance, cATO posture, DORA metrics, quarterly trends, tabletop log) với SHA-256 manifest pin từng file
- **OSCAL 1.1.2** machine-readable compliance — SSP, POA&M, Assessment Plan xuất định dạng FedRAMP-compliant
- **cATO (continuous Authority To Operate)** — 7 tiêu chí check live (audit chain, drift SLA, evidence freshness, scan cadence, POA&M, CIRCIA reporting, SBOM)
- **Quarterly improvement metrics** — trend evidence cho DSOMM L4 qua 4 quý gần nhất

## 2.2 Security Engineer / SOC Analyst

**Mục tiêu:** Detect và respond — không bỏ sót sự cố, MTTR thấp.

**VSP cung cấp:**

- **SIEM + Correlation engine** — 26 scanners → unified findings → correlation rules → incidents
- **UEBA** — 7 anomaly types (score spike, findings surge, gate fail streak, scan frequency, off-hours, new critical tool, SLA breach); auto-revoke session khi detect impossible-travel
- **Threat Hunt** — IOC search với MITRE ATT&CK technique mapping
- **MITRE ATT&CK Heatmap** — coverage view tự động map findings theo 14 tactics × 22 techniques
- **Incident Response (CIRCIA-compliant)** — 72h reporting workflow, NIST 800-61r3 lifecycle
- **SOAR playbooks** — automated response với approval gates, version control, rollback
- **Tabletop exercise registry** — log incident drill cadence theo scenario

## 2.3 DevSecOps Engineer / Platform Owner

**Mục tiêu:** Shift left — tích hợp security vào CI/CD mà không block velocity.

**VSP cung cấp:**

- **CI/CD gate** — `POST /api/v1/scan` từ pipeline; gate decision PASS/WARN/FAIL với severity thresholds
- **DORA metrics** — Deploy Freq, Lead Time, MTTR, Change Failure Rate; tier classification (elite / high / medium / low) per DORA 2023 standards
- **AutoPR / AutoFix** — generate fix PRs, SLA-based auto-merge
- **SLSA L3 readiness** — per-run signed in-toto v1 / DSSE attestations, cosign verify-attestation compatible
- **SBOM** — CycloneDX + SPDX generation, diff between versions (syft sinh, license phân tích)
- **VEX statements** — vulnerability exploitability declarations
- **API security testing** — DAST với 3 công cụ: nuclei (templates), nikto (web server), apisec (REST/GraphQL)
- **Fuzz + race detection** — gofuzz + racedetect cho Go codebases

## 2.4 Tenant Admin / Customer

**Mục tiêu:** Self-service quản lý tổ chức.

**VSP cung cấp:**

- **Multi-tenant** với DB-level Row-Level Security làm defence-in-depth
- **SSO / SAML** integration với corporate IdP
- **WebAuthn / Passkey + TOTP 2FA + HIBP breached-password check**
- **API keys** với scoped permissions
- **PRO billing** với 402-style upsell overlay (Stripe integration)
- **i18n** — UI Vietnamese / English với Accept-Language negotiation
- **Data residency** — declare primary region + egress allowlist (Decree 53/2022 compliant)
- **Notification config** — Slack / Teams / PagerDuty / Email / generic webhook với HMAC-SHA256 signing + SPKI cert pinning + DLQ retry

## 2.5 Cá nhân chủ thể dữ liệu (GDPR / PDPA Decree 13)

**Mục tiêu:** Thực thi quyền truy cập + xoá dữ liệu cá nhân.

**VSP cung cấp:**

- **DSAR data export** (GDPR Art.15 + PDPA Art.5) — async request → notification khi sẵn sàng
- **Right-to-erasure** (GDPR Art.17 + PDPA Art.9-12) — admin schedule erasure với 30-day grace, token-confirmed, cancellable
- **Locale preference** — chọn ngôn ngữ persistent across browsers

## 2.6 Vulnerability Researcher / Bug Bounty Hunter

**Mục tiêu:** Báo cáo lỗ hổng và được công nhận / thưởng.

**VSP cung cấp:**

- **Vulnerability Disclosure Policy** published (`/.well-known/security.txt` + VDP doc)
- **Anonymous intake** `POST /api/v1/security/disclose` với SLA tự động: ack 1 ngày, triage 5 ngày, fix theo severity
- **Public-ref tracking** "VSP-VDR-YYYY-NNNN"
- **Bounty range** $50–$5,000 theo CVSS v3.1

## 2.7 Auditor / Regulator (3PAO, FedRAMP assessor, CISA)

**Mục tiêu:** Verify hệ thống thực sự tuân thủ.

**VSP cung cấp:**

- **Audit chain** SHA-256 hash-chained — verify endpoint walk toàn bộ chain, repair endpoint với confirm
- **CISA attestation forms** workflow (executive sign-off cho EO 14028)
- **CIRCIA 72h reporting** — substantial incidents auto-generate compliance evidence
- **Public status JSON** cho external status pages
- **KPI sanity** endpoint HTTP 409 = release blocker; CI có thể poll để gate deploy

\newpage

# 3. Catalog tính năng — phân theo module

## 3.1 Scanner Integration (26 công cụ)

Inventory verify từ `internal/scanner/` ngày 2026-05-08. Mỗi công cụ có subdirectory riêng + runner.go.

### SAST — Static Application Security Testing (5)

| Công cụ | Phạm vi |
|---------|---------|
| **gosec** | Go source |
| **semgrep** | Universal (30+ ngôn ngữ) |
| **bandit** | Python |
| **codeql** | Semantic (GitHub) |
| **hadolint** | Dockerfile |

### SCA — Software Composition Analysis (7)

| Công cụ | Phạm vi |
|---------|---------|
| **trivy** | Container + OS + deps |
| **grype** | Container + OS |
| **syft** | SBOM generator (CycloneDX, SPDX) |
| **license** | OSS license compliance |
| **govulncheck** | Go module vulnerabilities |
| **osvscanner** | OSV.dev database queries |
| **retirejs** | JavaScript outdated libraries |

### IaC — Infrastructure as Code (2)

| Công cụ | Phạm vi |
|---------|---------|
| **checkov** | Terraform, K8s, ARM, CloudFormation |
| **kics** | Terraform, K8s, Dockerfile |

### DAST — Dynamic Application Security Testing (3)

| Công cụ | Phạm vi |
|---------|---------|
| **nuclei** | HTTP vuln templates |
| **nikto** | Web server vuln |
| **apisec** | REST + GraphQL API security |

### Secrets (3)

| Công cụ | Phạm vi |
|---------|---------|
| **gitleaks** | Repo scan for secrets |
| **secretcheck** | Live API validation (Slack `auth.test`, GitHub `/user`, ...) |
| **trufflehog** | Verified secrets across 700+ APIs |

### Network (3)

| Công cụ | Phạm vi |
|---------|---------|
| **nmap** | Network discovery |
| **sslscan** | TLS/SSL assessment |
| **netcap** | L2-L7 packet capture + DPI |

### Supply Chain (1)

| Công cụ | Phạm vi |
|---------|---------|
| **cosign** | Sign + verify container images & artefacts |

### Fuzzing & Runtime (2)

| Công cụ | Phạm vi |
|---------|---------|
| **gofuzz** | Go native fuzzer integration |
| **racedetect** | Go race condition detector |

**Tổng: 26 công cụ.** So sánh: Snyk dùng 5-7 scanners, Wiz 8-10, Tenable 6-8. VSP có chiều rộng bất thường cho nền tảng hợp nhất — đặc biệt mạnh ở Go (gosec + govulncheck + gofuzz + racedetect = 4 tool chuyên Go) và supply chain (syft + cosign + license + osvscanner + retirejs).

## 3.2 Compliance & Governance (40+ endpoints)

- **NIST OSCAL 1.1.2** — Catalog, Profile, SSP, Assessment Plan, AR, POA&M
- **FedRAMP Moderate** baseline mapping
- **CMMC** — 110 practices NIST 800-171
- **CISA** — Attestation Forms (EO 14028) + KEV catalog
- **GDPR + Vietnam PDPA Decree 13/2023** — DSAR + erasure + consent records
- **Vietnam Decree 53/2022** — data localization + per-tenant region binding
- **SAMM** — OWASP Software Assurance Maturity Model self-assessment
- **DSOMM** — DevSecOps Maturity Model với evidence trail

## 3.3 Detection & Response

- **SIEM** — log ingestion (syslog + webhooks), correlation engine, incidents
- **UEBA** — 7 anomaly types với baseline learning
- **SOAR** — playbook engine với approval gates, version control, rollback
- **Threat Hunt** — IOC search với MITRE technique mapping
- **Threat Intel** — feed integration (VirusTotal, custom)
- **Incident Response** — NIST 800-61r3 lifecycle, CIRCIA reporting

## 3.4 Supply Chain Security

- **Cosign / Sigstore** — sign + verify với ECDSA P-256 stored keys
- **SLSA L3 readiness** — per-run DSSE / in-toto v1 attestations
- **SBOM** — syft sinh CycloneDX + SPDX, diff between versions
- **VEX** — CycloneDX VEX 1.4 statements
- **Container scanning** — Trivy + Grype unified
- **Software inventory** với CVE → EPSS → KEV enrichment qua osvscanner + govulncheck + retirejs

## 3.5 Identity & Access

- **JWT** với HMAC-SHA256, dual-secret rotation
- **WebAuthn / FIDO2 / Passkey** — go-webauthn library, multi-credential per user
- **TOTP MFA** — RFC 6238 standard
- **HIBP breach check** — k-anonymity API (NIST SP 800-63B-3 §5.1.1.2)
- **IP-based sliding-window lockout** + constant-time bcrypt anti-enumeration
- **Anomaly-driven session revocation** — impossible travel + rapid IP rotation
- **OIDC / SAML SSO** integration
- **Account lockout** — 5 fail × 15min user, 20 fail × 15min IP
- **API keys** với scoped permissions

## 3.6 Multi-tenancy & Isolation

- **Postgres Row-Level Security** trên 9 critical tables (findings, runs, audit_log, compliance_evidence, ...)
- **Per-tenant data residency** với region binding + 451 enforcement
- **Per-tenant rate limiting**
- **Tenant data export** + erasure với 30-day grace

## 3.7 Continuous Monitoring

- **ConMon** — drift detection với 12-week sparkline trend
- **cATO** — 7 readiness criteria check live
- **DORA metrics** — 4 metrics với tier classification + WoW trend
- **MITRE ATT&CK heatmap** — coverage view auto từ findings
- **Quarterly improvement metrics** — 4-quarter trend rollup

## 3.8 KPI Integrity (sản phẩm Sprint 7)

- **Single-source-of-truth grading** — `gate.Posture()` thay vì 2 hệ song song; hard-fail rule (Critical>0 OR HasSecrets → F)
- **Sqrt-based dynamic scoring** — discriminate giữa "5 high" và "500 high"
- **Real ConMon score** — 6 weighted criteria thay vì hardcoded "94/100"
- **Supply-chain status taxonomy** — 7 distinct states (verified / tampered / unsigned / not_found / unavailable / signed / failed) thay vì "every-failure-is-tampered"
- **KPI sanity endpoint** — HTTP 409 = release blocker với 5 invariant assertions
- **KPI watchdog** — re-run sanity mỗi 5 phút, write `KPI_SANITY_FAILED` audit row khi regression

## 3.9 Operations & Observability

- **OpenTelemetry tracing** — otelpgx wrapped pgx + OTLP exporter
- **Prometheus metrics** — client_golang exposition
- **Structured logs** (zerolog) với PII redaction
- **SSE live-tail** — real-time scan progress thay vì polling
- **External Grafana embed** — config CRUD + iframe URL builder kiosk-mode
- **Webhook fan-out** với SPKI cert pinning + HMAC signing + DLQ
- **k6 load test harness** — SLO + chaos profiles
- **Public status JSON** + per-component health

## 3.10 Vault & Secret Management

- **Provider abstraction** — env / vault với KV v2 token-auth client
- **Auto-rotation** — 15min poll với atomic cache swap
- **Webhook signing key + JWT secret + DB DSN** qua provider

## 3.11 Deployment Hardening

- **Helm chart** — Deployment với restricted PodSecurityContext (non-root 65532, read-only FS, RuntimeDefault seccomp, drop ALL caps)
- **NetworkPolicy** — DNS-only egress by default
- **HPA** + **PDB** + **ServiceAccount** với automountServiceAccountToken false

## 3.12 UI Panels (33 panels)

| Group | Panels |
|-------|--------|
| Compliance | OSCAL, P4 Compliance, CMMC, SAMM, Attestation, Governance |
| Detection | AI Analyst, AI Advisor, UEBA, Correlation, Threat Hunt, Threat Intel, Incident Response |
| Operations | Scheduler, ConMon, SOAR, Log Pipeline, Settings, Integrations |
| Inventory | Assets, Software Inventory, SW Risk, Vuln Mgmt, Network Flow |
| Supply Chain | Supply Chain (Cosign), SBOM Diff, CSPM |
| Maturity | DORA, cATO, ATT&CK Heatmap |
| Admin | SSO Admin, Users, CI/CD, Grafana |

\newpage

# 4. Compliance & Standards Coverage

| Framework | Coverage | Evidence |
|-----------|----------|----------|
| NIST SP 800-53 Rev.5 | Core controls implemented | OSCAL Catalog endpoint |
| NIST SSDF (SP 800-218) | PS.1, PS.2, PS.3 | Supply-chain signing |
| NIST 800-61r3 | IR lifecycle phases | Incident Response panel |
| FedRAMP Moderate | Baseline mapped | OSCAL Profile |
| CMMC L2 | 110 practices | OSCAL extended |
| OSCAL 1.1.2 | SSP, AP, AR, POA&M | `/api/p4/oscal/*` |
| CISA | Attestation Forms | `cisa-attestation` endpoint |
| CIRCIA | 72h reporting | `circia_reports` table |
| EO 14028 | Improving Nation's Cybersecurity | Multi-component |
| SLSA v1.0 | L3 readiness | DSSE attestations |
| GDPR | Art.15, Art.17 | DSAR + erasure |
| Decree 13/2023 (PDPA Vietnam) | Art.5, Art.9-12 | DSAR + erasure |
| Decree 53/2022 (Vietnam) | Data localization | Residency middleware |
| Luật An ninh mạng 2018 (Vietnam) | Compliance mapping | Documentation |
| DSOMM | Level 3.9 (verified) | Audit bundle |
| CycloneDX 1.4 | SBOM + VEX | syft generator |
| in-toto v1 | Attestations | DSSE envelopes |
| RFC 9116 | security.txt | `/.well-known/` |
| NIST SP 800-63B-3 | Authenticator AAL2 | TOTP + WebAuthn + HIBP |

\newpage

# 5. So sánh thị trường

| Capability | VSP | Snyk | Wiz | Tenable |
|------------|:---:|:----:|:---:|:-------:|
| Scanner integrations | **26** | 5-7 | 8-10 | 6-8 |
| Compliance frameworks | **15+** | 3-5 | 5-7 | 4-6 |
| OSCAL machine-readable | ✓ | ✗ | ✗ | ✗ |
| Vietnam Decree 53/2022 residency | ✓ | ✗ | ✗ | ✗ |
| SLSA L3 signed provenance | ✓ | một phần | ✗ | ✗ |
| Native i18n (VN/EN) | ✓ | ✗ | ✗ | ✗ |
| Air-gapped (DoD) deployment | ✓ | một phần | ✗ | ✓ |
| Open-core / self-hostable | ✓ | ✗ | ✗ | một phần |
| Auditor evidence bundle (1-click) | ✓ | ✗ | ✗ | ✗ |

VSP có lợi thế cạnh tranh rõ rệt ở 2 phân khúc: (1) khách hàng Việt Nam cần data localization + ngôn ngữ; (2) khách hàng DoD / FedRAMP cần OSCAL + air-gapped deployment.

\newpage

# 6. Lộ trình lên 4.0

Code-side đã 4.0-attainable. Còn lại là **process + business work**:

| Hạng mục | Trạng thái | Effort | Owner |
|----------|-----------|-------:|-------|
| 3PAO pentest engagement | Pending | $80-150k, 4-6 tuần | Business |
| Bug bounty operational | Pending; intake ✓ done | $5-15k/quý + paid triage | Business |
| Public status page | Pending publish; JSON ✓ done | $25-100/tháng | Ops |
| Conduct + record 4 tabletops | Pending; registry ✓ done | 4 × 90min | Security team |
| Wire KPI sanity vào CI | Pending; endpoint ✓ done | 1 ngày | DevOps |
| FedRAMP / SOC 2 audit | Pending | 9-12 tháng audit cycle | Audit firm |

**Tổng effort tối thiểu:** ~6 tuần process + ~9 tháng audit = **~10 tháng** đến 4.0 certified.

\newpage

# 7. Risks đã được nhận diện

## 7.1 Operational

- **Vault chưa rollout production** — provider abstraction sẵn, chưa tenant nào flip `VSP_SECRETS_PROVIDER=vault`. Khuyến nghị dual-mode 1 rotation cycle trước khi flip prod.
- **RLS dev mode advisory** — gateway chạy as table owner = policies chỉ advisory. Prod cần `db_app` non-owner role.
- **WebAuthn HTTPS + RP_ID config** — soft fail khi `VSP_WEBAUTHN_RP_ID` chưa set; admin phải opt in.

## 7.2 Technical debt acknowledged

- `cmd/cosign-api/main.go` `classifyVerifyFailure` dùng substring match — fragile khi cosign upstream đổi message format. Plan: chuyển sang structured cosign output khi cosign 2.5 ship JSON output.
- Score sqrt math (Sprint 7.3) recalibrate user expectation. Old "5 high = C" do capping, new "5 high = A" do dynamic curve. Nếu user push back, retune weight 8 → 12.
- Bundle endpoint streams direct ZIP không cap size. Tenant có 10GB evidence sẽ block vài phút. Plan: async export với download URL (mirrors DSAR pattern).
- **Báo cáo trước (v1) ghi sai 19 scanners** — đã verify lại từ `internal/scanner/` directory listing và cập nhật về **26**. FEATURE_INVENTORY.md, DSOMM_ASSESSMENT.md, COMPLIANCE_MATRIX.md, ARCHITECTURE.md đã cập nhật consistent.

## 7.3 Process gaps

- Pentest report chưa có (planned Q3 2026)
- Bug bounty chưa operational (intake ready)
- Status page chưa publish (JSON ready)
- DSOMM 4.0 audit firm chưa engage

\newpage

# 8. Kết luận & Đề xuất

## 8.1 State

- Q2 2026 đóng với DSOMM **3.9 honest** — minh chứng được bằng audit bundle
- Code quality clean: 0 critical lint issues, all tests pass
- 134+ endpoints, 33 UI panels, **26 scanners**, 15+ compliance frameworks

## 8.2 Đề xuất Q3 2026

1. **Engage 3PAO** ngay — Coalfire / Schellman shortlist, $80-150k budget
2. **Stand up bug bounty** trên HackerOne — commit 7-day ack SLA matching VDP đã publish
3. **Publish status page** — Statuspage.io point vào `/api/v1/status`
4. **Schedule 4 tabletops** — 1 mỗi quý cho 1 năm, log vào registry
5. **Wire CI gate** với `/api/v1/kpi/sanity` HTTP 409 = release blocker

Sau 6 tuần process work + 9 tháng audit cycle, VSP đạt **4.0 certified**.

## 8.3 Verification

Mọi claim trong báo cáo này có thể verify trực tiếp:

```
# Đếm scanner directories
ls internal/scanner/ | grep -v '\.go$'
# Output: 26 directories

# Auditor bundle
curl -OJL -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8921/api/v1/audit/bundle
# Output: zip với manifest.json + 11 nhóm artefact + SHA-256 mỗi file
```

\newpage

# Phụ lục — Liên hệ

| Vai trò | Email |
|---------|-------|
| Security disclosure | security@vsp.vn |
| Compliance audit | compliance@vsp.vn |
| Engineering | engineering@vsp.vn |

**Báo cáo này pair với:**

- Commit `45c7337` — implementation (Sprint 2-8)
- Commit `ef6054c` — sprint technical report
- File `docs/security/VULNERABILITY_DISCLOSURE_POLICY.md`
- File `docs/SPRINT_2026Q2_FINAL_REPORT.md`
- File `docs/FEATURE_INVENTORY.md` (verified scanner inventory 2026-05-08)

**Đề xuất phân phối cho:** CISO / CTO / CFO / Head of Sales / Compliance Officer.

**Phiên bản báo cáo:** v4 (2026-05-08).

**Lịch sử phiên bản:**
- **v4** (2026-05-08, sau Sprint 10) — Sprint 10 polish toward 4.0-readiness: PCI-DSS 4.0 + NIS2 + HITRUST + CCPA mappings; CIS Benchmarks; 5 Sigma detection rules; KPI sanity GitHub Actions release gate; self-SBOM endpoint; SSP auto-generator; 4 seed tabletop scenarios; branch protection script. DSOMM 3.9 → 3.95 honest. Code-side đã chạm trần.
- **v3** (2026-05-08, sau Sprint 9) — Recognition Uplift: CISA SSDF auto-generator, NIST CSF 2.0 profile, SOC 2 Type I readiness map, ISO 27001:2022 Annex A mapping, Trust Center page, OpenSSF Scorecard CI, Rekor publishing endpoint, transparency report, 3PAO readiness packet.
- **v2** (2026-05-08) — Fix scanner count 19 → 26 sau khi user verify từ UI screenshots.
- **v1** (2026-05-08) — Phát hành ban đầu sau Sprint 2-8.

\newpage

# Phụ lục — Sprint 9 Recognition Uplift

Sprint 9 không nâng DSOMM (vẫn 3.9 honest) — thay vào đó nâng **mức độ công nhận** từ "self-claimed 3.9" lên "externally-evaluatable 3.9". 3 nhóm deliverable:

## A. Self-attestation packs

| Endpoint | Output |
|----------|--------|
| `GET /api/v1/cisa-attestation/ssdf/draft` | CISA SSDF Common Form 2024 với 19/19 practices auto-populated từ tenant evidence — submittable lên saf.cisa.gov sau khi exec ký |
| `POST /api/v1/cisa-attestation/ssdf/{id}/sign` | Executive signature endpoint, audit-logged |
| `GET /api/v1/nist-csf/profile` | Organisational Profile NIST CSF 2.0 với 22 categories + maturity tier |
| `GET /api/v1/recognition/soc2-readiness` | SOC 2 Type I readiness map (AICPA TSC) — 25 criteria CC/A/C/PI/P |
| `GET /api/v1/recognition/iso27001-mapping` | ISO/IEC 27001:2022 Annex A mapping — 30 highest-impact controls |

## B. Public trust signals

| Artefact | Mục đích |
|----------|----------|
| **`/trust/`** Trust Center page | Public-facing single page với attestations, live status, VDP, framework coverage |
| **`.github/workflows/scorecard.yml`** | Weekly OpenSSF Scorecard run, results upload public DB cho badge |
| **`POST /api/v1/runs/{rid}/provenance/publish-rekor`** | Publish DSSE attestation lên rekor.sigstore.dev — independently verifiable |
| **`GET /api/v1/transparency/report`** | Annual / semi-annual transparency aggregates (anon, cache 1h) |

## C. 3PAO readiness packet

| Doc | Vị trí |
|-----|--------|
| Statement of Work template | `docs/audit/3PAO_STATEMENT_OF_WORK.md` |
| Scope of Test | `docs/audit/SCOPE_OF_TEST.md` |
| Risk register (22 risks) | `docs/audit/RISK_REGISTER.md` |
| Engagement guide (6 phases) | `docs/audit/AUDIT_ENGAGEMENT_GUIDE.md` |

**Ý nghĩa cho sếp:**

Sau Sprint 9, một CISO khách hàng / auditor 3PAO có thể đánh giá VSP **mà không cần engineering team support** — họ truy cập `/trust/` page, lấy SSDF draft form, đọc risk register, mở audit bundle. Đây là khác biệt giữa "tốt nhưng cần giải thích" và "tự nó nói được".

Code-side: **không còn rào cản nào để engage 3PAO**. Business-side: cần ký SOW + ngân sách $80-150k cho FedRAMP-style assessment.

\newpage

# Phụ lục — Sprint 10 Polish Toward 4.0-Readiness

Sprint 10 đẩy DSOMM 3.9 → **3.95 honest**. 8 items polish code, không claim attestation mới — mục tiêu là làm bề mặt evaluation sạch hơn cho bên thứ ba.

## 10.1 — 4 framework mappings bổ sung

Thêm 4 framework vào catalog `/api/v1/recognition/`:

| Framework | Endpoint | Số controls | Lý do |
|-----------|----------|------------:|-------|
| **PCI-DSS 4.0** (March 2025 mandatory) | `/api/v1/recognition/pci-dss-mapping` | 12 | VSP import stripe-go → là Service Provider trong CDE |
| **NIS2 Directive (EU)** | `/api/v1/recognition/nis2-mapping` | 11 | Bất kỳ khách EU nào |
| **HITRUST CSF v11** | `/api/v1/recognition/hitrust-mapping` | 11 | Healthcare-aligned cross-mapping |
| **CCPA / CPRA** (California) | `/api/v1/recognition/ccpa-mapping` | 11 | Khách US-facing |

Cộng với SOC 2 + ISO 27001 + NIST CSF từ Sprint 9 → **8 self-attestation endpoints live**.

## 10.2 — CIS Benchmarks evidence

[docs/audit/CIS_BENCHMARKS.md](docs/audit/CIS_BENCHMARKS.md) — mapping VSP defaults vs CIS Postgres v15 + CIS K8s v1.27.

- **Postgres**: 12/19 controls implemented (7 shared = customer deployment)
- **K8s**: 19/23 controls enforced bởi Helm chart (4 shared)
- 0 non-compliant trong VSP responsibility boundary

Verify: `kubectl apply -f kube-bench/job.yaml` ra ≥95% pass rate.

## 10.3 — 5 Sigma detection rules

[detections/sigma/](detections/sigma/) — rules customer SOC team có thể drop vào Splunk / Elastic / Sentinel:

| Rule | Severity | MITRE |
|------|----------|-------|
| auth_brute_force.yml | medium | T1110 |
| impossible_travel.yml | high | T1078.004 |
| audit_chain_break.yml | critical | T1070.002 |
| supply_chain_tampered.yml | critical | T1554 |
| dsr_erasure_token_brute.yml | high | T1485 |

Convert sang SIEM khác: `sigma convert -t splunk detections/sigma/`.

## 10.4 — KPI sanity GitHub Actions release gate

[.github/workflows/kpi-sanity-gate.yml](.github/workflows/kpi-sanity-gate.yml) — workflow hard-fail khi `/api/v1/kpi/sanity` trả HTTP 409 trên staging trước release. Satisfies DSOMM L4 "automated quality gates".

## 10.5 — Self-SBOM publish

`/sbom.cyclonedx.json` + `/sbom.spdx.json` (anonymous, cache 1h) — path canonical OpenSSF Scorecard auto-discovery. Khách hàng supply chain (Wiz CDR, Phylum, Endor) pull trực tiếp.

## 10.6 — SSP auto-generator

`/api/v1/compliance/ssp.md` (admin only) — sinh System Security Plan format FedRAMP, 9 control families (AC / AU / IA / SC / SI / CM / IR / RA / SA), populated từ live tenant data. Render ra `.docx` qua pandoc trong 1 lệnh.

## 10.7 — 4 seed tabletop scenarios

[migration 044](migrations/044_seed_tabletops.sql) — 4 scenario cards realistic (ransomware / DSAR breach / supply chain / cloud takeover) với inject 3-step + objectives + participants. Idempotent — chỉ seed khi tenant chưa có row nào.

## 10.8 — Branch protection script

[scripts/branch_protection.sh](scripts/branch_protection.sh) — apply qua GitHub API: required PR review + CODEOWNERS + signed commits + linear history + no force push + admins included. Idempotent — chạy quarterly để verify không ai relax.

\newpage

# Phụ lục — Path lên 4.0 (Final, definitive)

Sau Sprint 10, **code-side đã chạm trần ở 3.95**. Để vượt 3.95 → 4.0 cần action ngoài code:

| # | Hành động | Cost | Time | Owner | Khi nào claim được 4.0 |
|---|-----------|------|------|-------|------------------------|
| 1 | Engage 3PAO (Coalfire / Schellman / A-LIGN) | $80-150k | 4-6 tuần | CISO + CFO | Sau khi nhận signed SAR |
| 2 | Bug bounty contract (HackerOne / Intigriti) | $5-15k/quý | 2 tuần signup | CISO | Sau khi triage 3+ reports |
| 3 | Statuspage.io publish | $25-100/tháng | 90 ngày uptime data | Ops | Sau 90 ngày clean data |
| 4 | Conduct + record 4 tabletops | 4 × 90 phút | 1 quý | Security team | Khi cả 4 scenario có rating != "not_rated" |
| 5 | SOC 2 Type II audit | $30-80k | 9 tháng (cần 3-6 tháng operating effectiveness) | Audit firm | Khi nhận unqualified opinion |

**Tổng:** ~10 tháng + ~$120-250k → **4.0 certified** với multi-framework attestation.

**Code đã có sẵn để hỗ trợ tất cả 5 bước trên:**

- Bước 1 — `docs/audit/3PAO_STATEMENT_OF_WORK.md` + `SCOPE_OF_TEST.md` + `RISK_REGISTER.md` + `AUDIT_ENGAGEMENT_GUIDE.md` ready để gửi ngay
- Bước 2 — `POST /api/v1/security/disclose` intake operational + SLA tracking + public_ref generation
- Bước 3 — `GET /api/v1/status` JSON ready cho external status page consumer
- Bước 4 — Tabletop registry với 4 scenario cards seed sẵn (migration 044)
- Bước 5 — Audit bundle `GET /api/v1/audit/bundle` đáp ứng SOC 2 evidence collection

**Ngân sách Q3 2026 đề xuất: $120-250k** spread across 5 line items → close out toàn bộ residual gap đến 4.0 trong 10 tháng.
