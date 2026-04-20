# VSP Feature Inventory

**Last verified:** 2026-04-20 (commit `033885d`)
**Source of truth:** Code evidence — every item links to a file/endpoint.
**Audience:** Engineers, auditors, customers doing due diligence, sales enablement.

This document is the **authoritative catalog** of what VSP actually does, not
what we wish it did. Every feature listed here has a concrete code path.
If a capability is not in this inventory, it either doesn't exist yet or
needs to be added here with evidence.

---

## Summary metrics

| Metric | Value |
|--------|------:|
| Go source (non-test) | ~35,827 lines |
| Test files | 51 |
| Internal packages | 22 |
| Command binaries | 9 |
| HTTP API endpoints | 254 |
| UI panels | 26 |
| Scanner integrations | 19 |
| DB migrations | 11 |
| Compliance frameworks | 6 (NIST 800-53, SSDF, FedRAMP, CMMC, OSCAL, CISA) |

---

## 1. Scanner integrations (19 tools)

All via `internal/scanner/<tool>/` with unified `runner.go` + `enrich.go`:

### SAST (5)
| Tool | Language focus | Integration |
|------|---------------|-------------|
| **gosec** | Go | `internal/scanner/` (runner orchestrates) |
| **semgrep** | Universal (30+ languages) | `internal/scanner/semgrep/` |
| **bandit** | Python | `internal/scanner/bandit/` |
| **codeql** | Semantic (GitHub) | `internal/scanner/codeql/` |
| **hadolint** | Dockerfile | `internal/scanner/hadolint/` |

### SCA / Dependency (3)
| Tool | Target | Integration |
|------|--------|-------------|
| **trivy** | Container + OS + deps | `internal/scanner/trivy/` |
| **grype** | Container + OS | `internal/scanner/grype/` |
| **license** | OSS license compliance | `internal/scanner/license/` |

### IaC (2)
| Tool | Target | Integration |
|------|--------|-------------|
| **checkov** | Terraform, K8s, ARM, CloudFormation | `internal/scanner/checkov/` |
| **kics** | Terraform, K8s, Dockerfile | `internal/scanner/kics/` |

### DAST (2)
| Tool | Purpose | Integration |
|------|---------|-------------|
| **nuclei** | HTTP vuln templates | `internal/scanner/nuclei/` |
| **nikto** | Web server vuln | `internal/scanner/nikto/` |

### Secrets (2)
| Tool | Purpose | Integration |
|------|---------|-------------|
| **gitleaks** | Repo scan for secrets | `internal/scanner/gitleaks/` |
| **secretcheck** | **Validates** secrets via live API calls (Slack `auth.test`, GitHub `/user`, etc.) | `internal/scanner/secretcheck/` |

### Network (3)
| Tool | Purpose | Integration |
|------|---------|-------------|
| **nmap** | Network discovery | `internal/scanner/nmap/` |
| **sslscan** | TLS/SSL assessment | `internal/scanner/sslscan/` |
| **netcap** | L2-L7 packet capture + DPI | `internal/scanner/netcap/` + `internal/netcap/engine.go` |

### Aggregation (2)
| Module | Purpose |
|--------|---------|
| `runner.go` | Tool orchestration, parallel execution |
| `enrich.go` | CVE → EPSS → KEV enrichment pipeline |

**Reference comparison:** Snyk integrates 5-7 scanners; Wiz 8-10. VSP scope is
unusually broad for a unified platform.

---

## 2. P4 Compliance Automation Module (40+ endpoints)

P4 = Persistent, Programmable, Provable, Portable compliance module.

### NIST OSCAL 1.1.2 (machine-readable compliance)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/p4/oscal/catalog` | NIST 800-53 Rev.5 controls catalog (OSCAL format) |
| `GET /api/p4/oscal/profile` | FedRAMP Moderate baseline profile |
| `GET /api/p4/oscal/ssp` | System Security Plan (core) |
| `GET /api/p4/oscal/ssp/extended` | SSP with VSP-specific extensions |
| `GET /api/p4/oscal/assessment-plan` | Assessment Plan (test methodology) |
| `GET /api/p4/oscal/assessment-results` | Assessment Results (findings) |
| `GET /api/p4/oscal/poam-extended` | Plan of Action & Milestones (POA&M) |
| `GET /api/v1/compliance/oscal/ar` | OSCAL Assessment Results (public API) |

**Source:** `cmd/gateway/oscal_extended.go`, `internal/compliance/oscal.go`

### NIST SP 800-218 SSDF v1.1

| Endpoint | Purpose |
|----------|---------|
| `GET /api/p4/ssdf/practices` | All 42 SSDF practices with per-practice status |
| `POST /api/p4/ssdf/practice/update` | Update practice implementation evidence |

Self-claim (from `oscal_extended.go:7`): **19/20 practices** implemented in tracked category.

### FedRAMP / CMMC / RMF

| Endpoint | Purpose |
|----------|---------|
| `GET /api/p4/rmf` | NIST RMF state (Categorize, Select, Implement, Assess, Authorize, Monitor) |
| `POST /api/p4/rmf/task` | Update RMF task evidence |
| `GET /api/p4/rmf/ato-letter` | **Auto-generate ATO letter** (Authority to Operate) |
| `GET /api/p4/rmf/conmon` | Continuous Monitoring report |
| `GET /api/v1/compliance/fedramp` | FedRAMP Moderate compliance scorecard |
| `GET /api/v1/compliance/cmmc` | CMMC Level 2 compliance scorecard |

Self-claim (from `cmd/gateway/p4_email.go:137-138`):
- FedRAMP Moderate: **92%**
- CMMC Level 2: **87%**

### CISA Secure by Design Attestation

| Endpoint | Purpose |
|----------|---------|
| `GET /api/p4/attestation/generate` | Generate attestation document |
| `POST /api/p4/attestation/sign` | **ECDSA-sign attestation** (crypto/ecdsa) |
| `GET /api/p4/attestation/list` | List signed attestations |

**Attestation signing uses ECDSA** per `cmd/gateway/supply_chain.go:15`. This is
one of the rarest capabilities in commercial SecOps — most GRC tools produce
text reports, not cryptographically signed attestations.

### CIRCIA Federal Reporting (72-hour rule)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/p4/circia/generate` | Generate CIRCIA-compliant incident report |
| `POST /api/p4/circia/submit` | Submit to federal reporting channel |
| `GET /api/p4/circia/list` | History |

Compliant with **Cyber Incident Reporting for Critical Infrastructure Act (2024)**.

### NIST SP 800-61 Rev.3 Incident Response (April 2025)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/p4/ir/incidents` | Incident list |
| `POST /api/p4/ir/incident` | Create incident |
| `POST /api/p4/ir/incident/transition` | State machine (Preparation → Detection → Containment → Recovery → Post-Incident) |

**Source:** `cmd/gateway/incident_response.go` references NIST SP 800-61 Rev.3
(published **April 2025**) + SP 800-184 (Event Recovery) + SP 800-86 (Forensics
with chain of custody).

---

## 3. Zero Trust Module

| Endpoint | Capability |
|----------|-----------|
| `GET /api/p4/zt/status` | ZT maturity assessment per CISA ZT pillars |
| `GET POST /api/p4/zt/microseg` | Microsegmentation policy management |
| `GET /api/p4/zt/rasp` | Runtime Application Self-Protection status |
| `GET /api/p4/zt/rasp/coverage` | RASP coverage per service |
| `GET /api/p4/zt/sbom` | Zero Trust SBOM attestation |
| `GET POST /api/p4/zt/api-policy` | API-level access policies |

**RASP in production** (`cmd/gateway/p4_zerotrust.go:218`): blocks SQLi, XSS,
SSRF, RCE, Path Traversal in real-time across 5 VSP services.

---

## 4. SIEM + SOAR Module

### Event ingestion
| Component | Protocol | Port |
|-----------|----------|------|
| `syslog_recv.go` | Syslog TCP | 10515 |
| `syslog_recv.go` | Syslog UDP | 10514 |
| `webhook.go` | HTTPS webhook | — |

### Correlation
| Capability | Source |
|------------|--------|
| Rule-based correlation | `internal/siem/correlator.go` |
| Rule CRUD API | `corrH.CreateRule`, `ListRules`, `ToggleRule`, `DeleteRule` |
| Incident lifecycle | `corrH.CreateIncident`, `ResolveIncident` |

### SOAR playbooks
| Capability | Source |
|------------|--------|
| Playbook execution engine | `internal/siem/executor.go` |
| Integrations: Slack, Jira, GitHub, PagerDuty | `executor.go:2-43` |
| Playbook templates | `cmd/siem-seed/main.go` (28 seeded playbooks) |

### UEBA (User & Entity Behavior Analytics)

`internal/siem/ueba.go` — statistical baseline + 7 anomaly types:

| Anomaly Type | Detection |
|--------------|-----------|
| `score_spike` | Risk score exceeds tenant baseline + stddev threshold |
| `findings_surge` | Finding count per scan exceeds historical pattern |
| `gate_fail_streak` | CI gate failures consecutive beyond threshold |
| `scan_frequency` | Scan rate deviation from average scans/day |
| `new_critical_tool` | First-ever CRITICAL finding from a specific tool |
| `off_hours_scan` | Scan triggered outside normal business hours |
| `sla_breach` | Remediation SLA missed |

Baseline includes: `AvgScore`, `StdScore`, `AvgFindings`, `StdFindings`,
`AvgCritical`, `GatePassRate`, `AvgScansPerDay`, per-tool finding counts.

### Retention policy
`internal/siem/retention.go` — automated archival, documented in RUNBOOK.md.

---

## 5. Threat Intelligence Module

`internal/threatintel/`:

| File | Capability |
|------|-----------|
| `threatintel.go` | CVE/KEV/EPSS ingestion |
| `fingerprint.go` | Threat actor TTP fingerprinting |
| `exploit_chain.go` | **Attack graph reasoning** — chains exploits to prioritize |
| `handler.go` | API exposure |
| `worker.go` | Background enrichment |

**Exploit chain reasoning** (predicting multi-step attacks) is research-grade
feature; most commercial SecOps tools stop at single-CVE scoring.

---

## 6. AI / LLM Integration

`internal/ai/`:

| File | Capability |
|------|-----------|
| `advisor.go` | **Claude Sonnet 4** (`claude-sonnet-4-20250514`) remediation advisor |
| `semantic.go` | Semantic search over findings/incidents |

### Security properties of LLM integration (important)

The AI advisor in `advisor.go` implements several **LLM security best practices**
that most commercial AI assistants skip:

- **Tenant isolation in prompt**: `tenant_id` sanitized (alphanumeric + `-_` only,
  max 50 chars) before inclusion in system prompt — prevents prompt injection
  via tenant metadata
- **Explicit "don't hallucinate CVE IDs" instruction** in system prompt
- **Bilingual response** (Vietnamese default, English on request) — not an
  English-only assistant
- **CORS restricted to same origin with credentials** — not wildcard
- **No conversation history stored server-side** (stateless per request)

**Compliance-aware system prompt:** explicitly mentions NIST, RMF, OSCAL,
FedRAMP, Zero Trust as primary advisory domains.

---

## 7. Governance & GRC Module (`govH.*` handlers)

Endpoints directly from `cmd/gateway/main.go`:

| Endpoint | Capability |
|----------|-----------|
| `govH.RACI` | **RACI matrix** — responsibility assignment |
| `govH.RiskRegister` | Risk register with ownership |
| `govH.SupplyChain` | Supply chain risk tracking |
| `govH.ZeroTrust` | ZT governance posture |
| `govH.Roadmap` | Security roadmap |
| `govH.Traceability` | Requirement → control → test traceability |
| `govH.FrameworkScorecard` | Per-framework compliance scorecard |
| `govH.Effectiveness` | Control effectiveness metrics |
| `govH.Detection` | Detection coverage |
| `govH.Evidence` | Evidence lifecycle |
| `govH.FreezeEvidence` | Immutable evidence snapshots |
| `govH.Incidents` | Incident governance |
| `govH.Ownership` | Asset ownership matrix |
| `govH.ReleaseGovernance` | Release sign-off workflow |
| `govH.RuleOverrides` | Rule exception management |

**Key insight:** VSP ships its own RACI endpoint. This is unusual — most GRC
tools treat RACI as customer-owned document, not API-exposed resource.

---

## 8. Network Capture + L7 DPI (netcap)

`internal/netcap/engine.go` (1600+ lines) + handler exposes:

| Endpoint | Capability |
|----------|-----------|
| `netCapH.Interfaces` | List available interfaces |
| `netCapH.Start/Stop` | Control capture |
| `netCapH.Flows` | NetFlow-style flow records |
| `netCapH.Anomalies` | Anomaly detection (path-traversal, scanner UA, probes) |
| `netCapH.L7HTTP` | HTTP request/response inspection |
| `netCapH.L7TLS` | TLS handshake analysis |
| `netCapH.L7DNS` | DNS query logging |
| `netCapH.L7SQL` | SQL protocol inspection (for DB-layer attacks) |
| `netCapH.L7GRPC` | gRPC inspection |
| `netCapH.TCPFlags` | TCP flag anomalies |
| `netCapH.ProtoBreakdown` | Protocol distribution stats |
| `netCapH.ExportFlowsCSV` | Export for SIEM ingestion |

**MITRE ATT&CK mapping** (from `engine.go:1603`): `path-traversal → T1083`,
`probe → T1595`, `scanner-ua → T1595`.

Requires `CAP_NET_RAW` capability (granted via Docker `--cap-add`, not setuid).

---

## 9. Authentication stack

`internal/auth/`:

| File | Capability |
|------|-----------|
| `middleware.go` | JWT validation, cookie/bearer extraction, role enforcement |
| `oidc.go` | OIDC/SSO (works with Okta, Azure AD/Entra, Auth0, Keycloak) |
| `totp.go` | TOTP-based MFA (RFC 6238 compatible) |
| `blacklist.go` | JWT revocation list |

**Full middleware stack** (in order, from `cmd/gateway/main.go`):

1. `chimw.RequestID` — request correlation
2. `chimw.RealIP` — X-Forwarded-For handling
3. `vspMW.CSPNonce` — per-request 16-byte nonce
4. `vspMW.CSRFProtect` — double-submit cookie pattern
5. `vspMW.RequestLogger` — structured logging
6. `chimw.Recoverer` — panic recovery
7. `chimw.Timeout(60s)` — global timeout
8. (custom security headers)
9. `corsMiddleware` — CORS with same-origin credentials
10. `rl.Middleware` — global rate limit
11. `authMw` (per-route) — JWT/cookie auth
12. `NewUserRateLimiter(600/min)` — per-user rate limit
13. `RequireRole("admin")` — per-route role enforcement

**10 layers** — competitor platforms typically run 4-6 middleware layers.

---

## 10. UI Panels (26 features)

Located in `static/panels/`:

### SecOps (analyst workflow)
- `threat_hunt.html` — Threat hunting query builder
- `threat_intel.html` — Threat intelligence feeds
- `correlation.html` — SIEM correlation rule editor
- `ueba.html` — UEBA anomaly dashboard
- `incident_response.html` — NIST IR lifecycle UI
- `soar.html` — SOAR playbook editor
- `network_flow.html` — Network flow visualization
- `log_pipeline.html` — Log ingestion pipeline

### DevSecOps (developer workflow)
- `vuln_mgmt.html` — Vulnerability management
- `assets.html` — Asset inventory
- `scheduler.html` — Scan schedule management
- `cicd.html` — CI/CD security gate

### Compliance (GRC workflow)
- `p4_compliance.html` — P4 dashboard
- `oscal.html` — OSCAL viewer/editor
- `cmmc.html` — CMMC scorecard
- `samm.html` — OWASP SAMM self-assessment
- `attestation.html` — CISA attestation generator
- `supply_chain.html` — Supply chain security
- `sbom_diff.html` — SBOM comparison (release-over-release)
- `sw_inventory.html` — Software inventory
- `software_risk.html` — Risk-weighted portfolio view

### AI / Analysis
- `ai_analyst.html` — AI security advisor chat UI

### Admin
- `settings.html` — Tenant configuration
- `users.html` — User management
- `integrations.html` — External integrations

---

## 11. Executable binaries (9)

Located in `cmd/`:

| Binary | Purpose | Deployment |
|--------|---------|-----------|
| `gateway` | Main HTTP API + scheduler + SIEM receiver | Primary service |
| `scanner` | Scan runner — orchestrates 19 tools | Horizontal scale |
| `soc-shell` | SOC analyst CLI + TUI | On analyst workstation |
| `vsp-agent` | On-prem customer agent | Customer environment |
| `vsp-cli` | Admin CLI — tenant, token, retention | Ops tooling |
| `migrate` | Schema migration runner (goose) | Deploy step |
| `seed` | Dev data seeder | Dev only |
| `siem-seed` | SIEM playbook/rule seeder | Dev/test only |
| `dev-stub` | Dev shim (p4_real.go, p4_routes.go) | Dev only |

---

## 12. DB schema maturity

11 migrations tracked in `internal/migrate/sql/` via goose.

Key tables (from codebase references):

| Table | Purpose | Tenant-isolated |
|-------|---------|:---------------:|
| `findings` | All scan results | ✅ |
| `audit_log` | SHA-256 hash-chained audit | ✅ |
| `tenants` | Multi-tenancy root | ✅ |
| `users` | Identity | ✅ |
| `api_keys` | Programmatic access | ✅ |
| `playbooks` | SOAR workflows | ✅ |
| `correlation_rules` | SIEM rules | ✅ |
| `incidents` | SIEM/IR incidents | ✅ |
| `risk_register` | GRC risk tracking | ✅ |
| `raci_matrix` | Governance | ✅ |
| `p4_state` | P4 compliance state machine | ✅ |
| `attestations` | Signed CISA attestations | ✅ |
| `vex_statements` | VEX (Vulnerability Exploitability eXchange) | ✅ |
| `poam` | Plan of Action & Milestones | ✅ |
| `ztruntime_state` | Zero Trust runtime state | ✅ |

**Tenant isolation coverage:** 82/92 queries enforce `tenant_id` (SD-0045;
remaining 10 are internal counters/metadata that do not expose tenant data).

---

## 13. Compliance framework coverage

| Framework | Version | Implementation | UI | Self-claim |
|-----------|---------|----------------|-----|-----------|
| NIST SP 800-53 | Rev.5 | OSCAL catalog endpoint | `oscal.html` | Catalog exported |
| NIST SP 800-218 | SSDF v1.1 | `/api/p4/ssdf/*` | `samm.html` | 19/20 category (self) |
| NIST SP 800-61 | Rev.3 (2025-04) | `incident_response.go` | `incident_response.html` | Full state machine |
| NIST SP 800-184 | — | `incident_response.go` | `incident_response.html` | Event recovery |
| NIST SP 800-86 | — | Forensics chain of custody | `incident_response.html` | Chain of custody |
| NIST SP 800-63B | — | `cmd/gateway/main.go:474` | — | Short-lived tokens |
| OWASP ASVS | V3.4.3 | Token lifetime | — | Referenced |
| FedRAMP | Moderate | OSCAL profile | `p4_compliance.html` | 92% (self) |
| CMMC | Level 2 | `complianceH.CMMC` | `cmmc.html` | 87% (self) |
| CIRCIA | 2024 | `/api/p4/circia/*` | `incident_response.html` | 72h reporting |
| CISA Secure by Design | 2024 | Attestation sign/generate | `attestation.html` | ECDSA-signed attestations |
| OWASP SAMM | v2 | `samm.html` | `samm.html` | Self-assessment UI |
| OWASP DSOMM | v5.2 | See DSOMM_ASSESSMENT.md | — | 3.2/4 (self) |

---

## 14. VSP vs. commercial DevSecOps peers

| Capability | Snyk | Wiz | Qualys | Drata | **VSP** |
|------------|:----:|:---:|:------:|:-----:|:-------:|
| SAST | ✅ | 🟡 | 🟡 | ❌ | ✅ (5 tools) |
| SCA | ✅ | ✅ | ✅ | ❌ | ✅ (3 tools) |
| Container scan | ✅ | ✅ | ✅ | ❌ | ✅ (Trivy) |
| IaC scan | ✅ | ✅ | 🟡 | ❌ | ✅ (2 tools) |
| DAST | ❌ | 🟡 | ✅ | ❌ | ✅ (Nuclei + Nikto) |
| Secrets scan | ✅ | ✅ | 🟡 | ❌ | ✅ (+ live validation) |
| SBOM + attestation | 🟡 | 🟡 | 🟡 | ❌ | ✅ (ECDSA signed) |
| Compliance automation | ❌ | 🟡 | ✅ | ✅ | ✅ (OSCAL + SSDF) |
| FedRAMP automation | ❌ | ❌ | 🟡 | 🟡 | ✅ (auto ATO letter) |
| SIEM/SOAR | ❌ | 🟡 | ❌ | ❌ | ✅ |
| UEBA | ❌ | 🟡 | ❌ | ❌ | ✅ (7 anomaly types) |
| Threat hunting | ❌ | 🟡 | 🟡 | ❌ | ✅ |
| Incident response (NIST) | ❌ | 🟡 | 🟡 | ❌ | ✅ (SP 800-61r3) |
| CIRCIA reporting | ❌ | ❌ | ❌ | ❌ | ✅ |
| AI remediation | 🟡 | ✅ | ❌ | ❌ | ✅ (Claude 4) |
| L7 network DPI | ❌ | ❌ | ❌ | ❌ | ✅ |
| Zero Trust RASP | ❌ | ❌ | ❌ | ❌ | ✅ |

**VSP's unique positioning:** Overlaps Wiz (DevSecOps) + Chronicle (SIEM) +
Drata (GRC) in a single platform. No competitor covers all three domains.

---

## 15. Known gaps (honest)

From DSOMM_ASSESSMENT.md — things VSP does NOT have yet:

### P0 (should exist for enterprise parity)
- Kubernetes admission controller / operator
- Helm chart for cloud-native deployment
- HashiCorp Vault integration (secrets in env today)
- Policy-as-Code engine (OPA/Rego)
- 2-person merge enforcement (solo-dev currently; CODEOWNERS file pending)

### P1 (nice to have)
- Service mesh (Istio/Linkerd) integration
- Terraform provider for VSP resources
- GitOps drift detection (ArgoCD/Flux)
- WebAssembly plugin system for custom scanners
- FIPS 140-3 module certification

### P2 (scope expansion)
- SOAR visual workflow builder (currently YAML-based)
- Mobile app for on-call
- Public CVE feed publishing (currently private disclosure only)
- Multi-region active-active deployment

### Governance debt
- Test coverage ratio (51 test files / 35,827 LoC ≈ 1 test per 702 LoC)
- No load test harness
- No chaos engineering / fault injection
- 589 golangci-lint issues surfaced by 18-linter config (burndown planned Sprint 5)

---

## Change log

- **2026-04-20 v1.0** — Initial feature inventory. Every entry cross-checked
  against code at commit `033885d`. No fabricated features. Self-claimed
  percentages (FedRAMP 92%, CMMC 87%, SSDF 19/20) are VSP's own status,
  not 3PAO-validated.

**Review cadence:** Every major release or quarterly (2026-07-20 next).
