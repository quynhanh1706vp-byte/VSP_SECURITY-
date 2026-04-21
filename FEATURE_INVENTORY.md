# VSP — Feature Inventory

**Version:** 1.2
**Last reviewed:** 2026-04-21
**DSOMM self-assessment:** 3.35 / 4 (near Level 3.5 — Advanced)

This document is the authoritative catalog of what VSP ships today. It is written for three audiences: prospective customers doing a capability match, auditors doing evidence review, and new engineers finding their bearings. Entries describe only what is implemented in code in the current release; roadmap items live in `ROADMAP.md`.

---

## Changelog

- **v1.2 (2026-04-21)** — Added sections for Vietnam national standards, L2-L7 Deep Packet Inspection, Security Copilot pattern, Supply chain signing, Forensics & ransomware tracking. Bumped DSOMM score 3.14 → 3.35 after deeper code audit.
- **v1.1 (2026-04-07)** — Initial public inventory. DSOMM 3.14.
- **v1.0 (2026-03-15)** — Internal draft.

---

## 1. Compliance automation

### 1.1 DoD Zero Trust P4 dashboard

11-tab compliance panel (`static/panels/p4_compliance.html`, 2841 lines) covering:

| Tab | Purpose |
| --- | --- |
| Overview | FedRAMP / CMMC / ATO / POA&M scorecards |
| RMF | ATO letter generation, NIST SP 800-37 six-step tracker, OSCAL artifacts, ConMon |
| Zero Trust | 7-pillar grid, capability table, SBOM stats |
| Pipeline | Compliance pipeline runs, framework scores, drift detection, schedules |
| Microseg | Microsegmentation policy editor (service mesh rules) |
| RASP | RASP runtime stats, real-time block list |
| POA&M | Plan of Action & Milestones management |
| ATO expiry | Countdown + renewal checklist |
| SBOM view | Searchable software bill of materials |
| **VN standards** | **Vietnam national standards mapping (§1.2)** |
| Tests | Assessment test detail modal |

Backend: `cmd/gateway/p4_*.go` (11 files covering OSCAL, RMF, ZT, alerts, email, health, integrations, pipeline, security).

### 1.2 Vietnam national standards mapping

Differentiator for the Vietnam market. Maps VSP controls to:

- **TCVN ISO/IEC 27001:2019** — Information security management systems (Vietnamese national translation of ISO/IEC 27001).
- **Nghị định 13/2023/NĐ-CP** — Personal data protection decree (effective 2023-07-01). VSP maps data classification, consent tracking, and breach-notification workflows to Articles 9, 17, 18, 23.
- **Luật An ninh mạng 2018** — Cybersecurity Law. VSP maps data localization indicators, critical information system reporting, and incident notification to Articles 8, 10, 16, 24, 26.
- **TCVN 11930:2017** — Vietnamese national standard on information security risk management.

Panel IDs: `#tab-vn-standards`, `#vn-standards-grid`, `#vn-matrix-tbody`. Exportable to OSCAL-compatible matrix.

### 1.3 OSCAL 1.1.2 export

Full NIST OSCAL 1.1.2 JSON emission for:

- System Security Plan (SSP) — `/api/v1/oscal/ssp`
- Security Assessment Plan (SAP) — `/api/v1/oscal/sap`
- Security Assessment Results (SAR) — `/api/v1/oscal/sar`
- POA&M — `/api/v1/oscal/poam`
- Catalog + Profile — for control baselines (FedRAMP M, CMMC L2, NIST 800-53 Rev 5)

Handlers: `handleOSCALAssessmentPlan`, `handleOSCALAssessmentResults`, `handleOSCALCatalog`, `handleOSCALExport`, `handleOSCALPOAMExtended`, `handleOSCALProfile`, `handleOSCALSSPExtended` in `cmd/gateway/oscal_extended.go`.

### 1.4 ATO (Authority to Operate) automation

- Auto-generated ATO letter with DoD memo formatting (`/api/p4/ato/letter`).
- Six-step RMF state machine: Categorize → Select → Implement → Assess → Authorize → Monitor.
- ATO expiration tracking with 30/60/90-day warning thresholds.
- Renewal checklist synced to POA&M state.

### 1.5 CIRCIA 72-hour incident reporting

US CIRCIA 2024 compliance. When an incident reaches "reportable" status, VSP generates the required CISA report within the 72-hour window and emits it via configured channels (email, webhook, or manual download).

### 1.6 Framework coverage matrix

| Framework              | Implementation | Machine-readable export |
| ---------------------- | -------------- | ----------------------- |
| DoD Zero Trust v2.0 P4 | 7 pillars      | OSCAL + JSON            |
| FedRAMP Moderate       | 325 controls   | OSCAL SSP               |
| CMMC Level 2           | 110 practices  | OSCAL + PDF wizard      |
| NIST SP 800-53 Rev 5   | MOD baseline   | OSCAL                   |
| NIST SP 800-171        | 110 reqs       | OSCAL                   |
| NIST SP 800-37 Rev 2   | RMF 6 steps    | —                       |
| NIST SP 800-61r3       | IR lifecycle   | JSON                    |
| NIST SP 800-86         | Forensics      | Chain-of-custody JSON   |
| SLSA                   | Level 3 ready  | in-toto attestation     |
| OWASP SAMM 2.0         | 5 domains      | CSV                     |
| TCVN ISO/IEC 27001     | Full mapping   | JSON matrix             |
| Nghị định 13/2023      | Articles 9, 17, 18, 23 | JSON             |
| Luật An ninh mạng 2018 | Articles 8, 10, 16, 24, 26 | JSON         |

---

## 2. Security Copilot pattern (AI Analyst)

`static/panels/ai_analyst.html` implements a multi-function AI analyst analogous to Microsoft Security Copilot. Unlike simple chatbots, this module is context-aware and can invoke platform actions.

### 2.1 Functions

| Function | Purpose |
| --- | --- |
| `autoTriage` | AI auto-triage findings by severity, similarity, and historical false-positive rate |
| `runPlaybook` | AI invokes SOAR playbooks based on finding context |
| `runHunt` / `aiHunt` | AI-powered threat hunting — generate queries from natural language prompts |
| `generateReport` | AI report generation (executive summary, technical findings, compliance evidence) |
| `switchTab` + `setContext` | Context-aware multi-tab conversation with memory |
| `exportChat` | Audit trail of AI interactions for compliance review |
| `quickAction` | Preset one-click common analyst tasks |

### 2.2 Audit trail

Every AI interaction is logged with: prompt, model response, context, timestamp, user ID, and action taken. Log is queryable via `/api/v1/ai/interactions` for SOC review and compliance attestation.

---

## 3. L2-L7 Deep Packet Inspection

`static/panels/network_deep.html` (79 KB) provides 9-tab deep network inspection at a level typically associated with dedicated tools (Wireshark, ntopng, Zeek) embedded inside a SecOps platform.

| Tab (`data-tab`) | Function |
| --- | --- |
| `l3l4` | Layer 3/4 flow analysis (IP, TCP, UDP) |
| `http` | HTTP request/response analyzer |
| `dns` | DNS query log and NXDOMAIN analysis |
| `sql` | SQL protocol analyzer (MySQL, PostgreSQL, MSSQL wire protocol) |
| `grpc` | gRPC inspection with protobuf introspection |
| `tls` | TLS handshake analysis, SNI, cipher suite, cert chain |
| `hex` | Raw packet hex viewer |
| `anom` | Anomaly detection on flow statistics |
| `map` | Network topology map |

Not found in any other commercial DevSecOps platform at this depth of integration.

---

## 4. SOAR + incident response

### 4.1 SOAR playbook engine

Panel `static/panels/soar.html`. Key capabilities:

- **MTR KPI tracking** (`k-mtr`) — Mean Time to Respond.
- **Live log streaming** during playbook execution.
- **Real-time progress bar** with percentage and stage label.
- **Rerun capability** from history — re-execute any past run with original context.
- **Playbook builder modal** — create new playbooks with name, description, steps.
- **12 built-in playbooks** for common scenarios (credential leak, ransomware, privilege escalation, etc.).

Integrations: Slack, Microsoft Teams, Jira, PagerDuty, generic webhook.

### 4.2 NIST SP 800-61r3 incident lifecycle

`cmd/gateway/incident_response.go` implements the full lifecycle:

- **Detection & Analysis** — correlation engine feeds incidents.
- **Containment, Eradication, Recovery** — state machine with `transition` events.
- **Post-Incident Activity** — `lesson` tracking (10 lessons-learned fields per incident).
- **Forensics** — `forensic` evidence records (7 fields) with chain of custody per NIST SP 800-86.
- **Ransomware payment tracking** — `ransom-payment` field required by OFAC sanctions screening and CIRCIA 2024 reporting.

### 4.3 Threat hunting

Panel `static/panels/threat_hunt.html` provides query-driven hunts with MITRE ATT&CK mapping. Queries can be saved, scheduled, and invoked by the AI Analyst (§2).

---

## 5. Supply chain integrity (SLSA Level 3 ready)

VSP ships its own signing infrastructure rather than depending on external Cosign-only workflows. Endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET  /api/v1/supply-chain/public-key` | Public signing key for external verification |
| `POST /api/v1/supply-chain/sign` | Sign an artifact (container image, SBOM, release bundle) |
| `POST /api/v1/supply-chain/verify` | Verify a signature offline |
| `GET  /api/v1/supply-chain/signatures` | List all known signatures |
| `GET  /api/v1/supply-chain/provenance` | Retrieve SLSA provenance attestation |
| `GET  /api/p4/vex` | VEX (Vulnerability Exploitability eXchange) statements |

Signatures are Sigstore-compatible and verifiable with `cosign verify` against the published public key. Backend: `cmd/gateway/supply_chain.go`.

---

## 6. Software inventory + password-crack red-team tooling

Panel `static/panels/sw_inventory.html` (1057 lines) has 4 tabs:

| Tab | Function |
| --- | --- |
| Inventory | Approved / unauthorized / EOL software tracking |
| Whitelist | Whitelist + blacklist + warning list management |
| **Crack** | **Password hash cracking / hash analysis (red-team tooling)** |
| License | License compliance classification (OK / GPL / none) |

The **Crack** tab (`hash-input`, `hash-name-input`, `crack-tbody`, `cs-suspicious`, `cs-confirmed`) is unusual in a commercial DevSecOps product — it enables internal red-team validation of password policy enforcement without needing a separate tool like hashcat.

---

## 7. Zero Trust 7-pillar implementation

| Pillar | Current score | Implementation |
| --- | --- | --- |
| User | 96 | MFA (TOTP), PAM integration, UEBA |
| Device | 88 | SW Risk Agent (Linux x64/ARM64, Windows x64), dpkg/rpm inventory |
| Network | 100 | 13 service-mesh rules, mTLS, microsegmentation |
| Application | 91 | RASP 5/5, API policy engine, SBOM attestation |
| Data | 100 | Classification, encryption at rest + in transit, DLP hooks |
| Visibility | 95 | L2-L7 DPI (§3), unified log pipeline, correlation engine |
| Automation | 93 | 12 SOAR playbooks, OPA/Rego policy engine, CIRCIA reporting |

**Overall P4: 100% — all 7 pillars ≥ 85.**

---

## 8. Scan & findings

### 8.1 Scan modes

| Mode | Tools | Typical runtime |
| --- | --- | --- |
| SAST | semgrep, bandit, gosec | 5–30 min |
| SCA | trivy, grype | 2–5 min |
| SECRETS | gitleaks, trufflehog | 1–3 min |
| IAC | kics, checkov | 2–10 min |
| DAST | nuclei, nikto, sslscan | 10–60 min |
| NETWORK | nmap L2–L7 | 5–30 min |
| FULL | all of the above | 30–90 min |
| FULL_SOC | FULL + SOC-level enrichment | 60–120 min |

Total: **19 scanners** integrated.

### 8.2 Finding lifecycle

Triage → Assign → Remediate → Verify → Close. SLA per severity: CRIT 7d / HIGH 14d / MED 30d / LOW 90d. Remediation rate tracked per asset and per team.

### 8.3 Reports

- TT13/2023 (Vietnam circular) HTML + PDF report — 30-page Vietnamese report via `wkhtmltopdf`.
- ConMon PDF — FedRAMP-format continuous monitoring report, monthly.
- OWASP SAMM 2.0 — 5 domains, 15 practices, maturity slider.
- CMMC Level 2 wizard — 110 controls across 14 domains, CSV export.
- Executive report — `report_executive.go` produces one-pager with KPIs.

---

## 9. Platform & ops

- **Audit log rotation** — PostgreSQL function with 90-day retention policy, archive to object storage.
- **Dashboard ConMon KPI row** — score, POA&M count, FedRAMP %, audit log integrity, all live.
- **SW Risk Agent** — 3 OS × 2 arch binaries (Linux x64/ARM64, Windows x64).
- **VN threat feeds** — 27 IOC sources including VNCERT, BKAV, Viettel CS.
- **18 correlation rules** — Port scan, ARP, C2, Ransomware, Lateral movement, etc.

---

## 10. API surface

Base path `/api/v1/` and `/api/p4/`. Endpoints documented in OpenAPI 3.1 (`openapi.yaml`). Authentication: bearer token (issued via `/api/v1/auth/token`) or API key. MFA required for admin and compliance-officer roles (policy-gated; enforcement enabled in v1.4).

API docs live at `/docs` (rendered from `openapi.yaml`).

---

## 11. Deployment & integrations

### 11.1 Integrations shipped

Slack, Microsoft Teams, Jira, PagerDuty, generic webhook. Multi-instance Slack/Teams/Jira (each can be connected more than once with different workspaces).

### 11.2 Deployment modes

- **Docker Compose** — current primary distribution for on-prem.
- **Bare metal** — single-binary + systemd unit file (internal use).
- **Helm chart** — in active development (target Sprint 5).
- **Kubernetes Operator** — roadmap, not yet started.

### 11.3 Supported databases

- PostgreSQL 14+ (primary)
- Redis 7+ (cache, batch queue — see `cmd/gateway/vsp_batch_redis.go`)

---

## 12. DSOMM self-assessment (2026-Q2)

Self-assessed against OWASP DevSecOps Maturity Model (DSOMM) v4.

| Dimension            | Score | Evidence |
| -------------------- | ----- | -------- |
| Implementation       | 3.70  | P4 11 tabs, VN standards, key signing, hex packet viewer, Security Copilot |
| Test & Verification  | 3.60  | 9-tab L2-L7 DPI, password cracking module, 19 scanners, RASP |
| Culture & Org        | 3.30  | Onboarding 125 sections, AI copilot tooling, SOC-analyst-grade UX |
| Build & Deploy       | 2.80  | Supply chain sign/verify = SLSA L3 ready, CI 19 scanners, Helm pending |
| **Overall**          | **3.35** | **Near Level 3.5 — Advanced** |

Gaps to reach Level 4 (target 3.70 by end of 2026-Q2) are tracked in `ROADMAP.md` and `docs/dsomm/2026-Q2-plan.md`. Honest assessment: we are **not yet at 4.0** on Build & Deploy — known gaps are Helm chart, Vault integration, observability shipping config, and CI quality gate stability (SD-0049 history).

---

## 13. How this document is maintained

- Owner: Security Lead.
- Review: quarterly, or when a new major feature ships.
- PR process: changes require review from `@security-team` and `@tech-writers` per CODEOWNERS.
- Accuracy test: every claim in this doc must be traceable to code or a committed artifact. Claims without evidence are removed at the next review, not weakened with "planned" or "upcoming" — those live in `ROADMAP.md`.
