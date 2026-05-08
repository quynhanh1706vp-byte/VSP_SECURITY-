# Statement of Work — Third-Party Security Assessment

**Issued by:** VSP Platform — Compliance & Engineering
**Issue date:** _to be filled at engagement_
**Target effective date:** _to be filled at engagement_
**Document version:** 1.0 (template)

---

## 1. Engagement objective

Engage a Third-Party Assessment Organisation (3PAO) to conduct an
independent security assessment of the VSP platform aligned with one
of the following frameworks (assessor + VSP to confirm scope at
kick-off):

- **FedRAMP Moderate baseline** (NIST SP 800-53 Rev.5 Moderate)
- **SOC 2 Type I — Security & Availability Trust Services Criteria**
- **ISO/IEC 27001:2022 Stage 1 (readiness review)**

The engagement output is a written report identifying findings,
their severity, and corrective actions required to achieve
attestation under the chosen framework.

---

## 2. Scope of system

### In-scope components

| Component | Description |
|-----------|-------------|
| Gateway service | `cmd/gateway` — public HTTP API (134+ endpoints) |
| Cosign API | `cmd/cosign-api` — supply-chain sign / verify |
| DAST API | `cmd/dast-api` — DAST execution |
| Email API | `cmd/email-api` — outbound notifications |
| Trivy API | `cmd/trivy-api` — container vulnerability scan |
| Scheduler API | `cmd/scheduler-api` — cron-based scans |
| Software Inventory | `cmd/sw-inventory` — SBOM aggregation |
| SOC Shell | `cmd/soc-shell` — investigator interface |
| Migration tool | `cmd/migrate` — DB schema management |
| Helm chart | `deploy/helm` — production deployment artefact |
| Database | PostgreSQL 14+, schema in `migrations/` |
| Cache / queue | Redis 6+, used for asynq + JWT blacklist |

### Out of scope

- Customer-deployed infrastructure (datacentre, network, OS hardening)
- Customer-managed identity provider (OIDC / SAML federation partner)
- Third-party SaaS integrations (Stripe, VirusTotal, Slack)
- Pre-existing customer data and prior compliance state
- Hardware security modules (HSM) at customer sites

---

## 3. Assessor deliverables

| Deliverable | Format | Due |
|-------------|--------|-----|
| Engagement plan | PDF | within 5 business days of kickoff |
| Daily standup notes | Email / Slack | every business day |
| Weekly status report | PDF | every Friday |
| Preliminary findings register | XLSX | week 3 |
| Draft Security Assessment Report (SAR) | PDF | week 5 |
| Final SAR with corrective-action verification | PDF + signed letter | week 6 |
| Plan of Action & Milestones (POA&M) | XLSX | with final SAR |

Reports must follow the [FedRAMP SAR template](https://www.fedramp.gov/documents-templates/) when the engagement is FedRAMP-aligned.

---

## 4. VSP-provided artefacts (already available)

| Artefact | Endpoint / file |
|----------|-----------------|
| **Audit evidence bundle** | `GET /api/v1/audit/bundle` (zip with manifest.json + 11 artefact groups + SHA-256 per file) |
| **NIST SSDF Self-Attestation** | `GET /api/v1/cisa-attestation/ssdf/draft` |
| **NIST CSF 2.0 profile** | `GET /api/v1/nist-csf/profile` |
| **SOC 2 readiness map** | `GET /api/v1/recognition/soc2-readiness` |
| **ISO 27001:2022 Annex A map** | `GET /api/v1/recognition/iso27001-mapping` |
| **OSCAL artefacts** | `/api/p4/oscal/{catalog,profile,ssp,assessment-plan,assessment-results,poam}` |
| **SLSA L3 attestations** | `GET /api/v1/runs/{rid}/provenance` (DSSE / in-toto v1) |
| **DSOMM 3.9 evidence** | `docs/SPRINT_2026Q2_FINAL_REPORT.md` |
| **Architecture diagram** | `docs/ARCHITECTURE.md` |
| **Compliance matrix** | `docs/COMPLIANCE_MATRIX.md` |
| **Risk register** | `docs/audit/RISK_REGISTER.md` |
| **Vulnerability disclosure policy** | `docs/security/VULNERABILITY_DISCLOSURE_POLICY.md` |
| **Public status feed** | `GET /api/v1/status` |
| **KPI sanity check** | `GET /api/v1/kpi/sanity` (HTTP 409 = release blocker) |
| **Tabletop exercise log** | `GET /api/v1/tabletop/exercises` |
| **Public Trust Center** | `/trust/` |

---

## 5. Acceptance criteria

The engagement is considered complete when:

1. Final SAR has been delivered, reviewed by VSP CISO, and signed by
   the assessor's quality reviewer.
2. All findings tagged "Critical" or "High" have either:
   - been remediated and re-tested (closed), OR
   - been accepted by VSP with a documented compensating control
     and assigned a POA&M milestone date.
3. The assessor has executed the verification steps in
   [`docs/SPRINT_2026Q2_FINAL_REPORT.md` §6](../SPRINT_2026Q2_FINAL_REPORT.md)
   and confirmed reproducibility from the audit bundle.
4. All documents have been delivered in the formats listed in §3.

---

## 6. Pricing model

VSP requests fixed-price engagement (not time-and-materials) with a
clear change-order process. Indicative ranges:

| Engagement | Indicative range (USD) | Duration |
|------------|----------------------:|----------|
| FedRAMP Moderate readiness assessment | $80,000 – $150,000 | 4 – 6 weeks |
| SOC 2 Type I attestation | $25,000 – $60,000 | 3 – 5 weeks |
| ISO 27001:2022 Stage 1 readiness review | $15,000 – $35,000 | 2 – 4 weeks |
| Combined SOC 2 Type I + ISO 27001 Stage 1 | $35,000 – $80,000 | 4 – 6 weeks |

Re-test fees should be capped at the assessor's daily rate × 5
business days.

---

## 7. Suggested 3PAO firms (FedRAMP-accredited as of 2026)

VSP will issue this SOW to at least three firms and select based on
relevant Vietnam / DoD experience and price:

- **Coalfire Federal**
- **Schellman Compliance**
- **A-LIGN**
- **Kratos Defense / SecureInfo**
- **MorganFranklin**

For SOC 2 / ISO 27001 (non-FedRAMP), additionally:

- **Marcum** (AICPA-licensed)
- **Sensiba San Filippo**
- **BDO Digital**

---

## 8. Confidentiality & data handling

- The 3PAO must execute a Mutual Non-Disclosure Agreement before
  receiving the audit bundle or accessing staging.
- Customer data MUST NOT be included in any 3PAO deliverable.
  Synthetic / anonymised data only.
- All evidence transferred outside VSP's environment must be
  encrypted at rest (AES-256) and in transit (TLS 1.3).
- The 3PAO must destroy or return all VSP material within 90 days
  of engagement closure.

---

## 9. Project contacts

| Role | Name / contact |
|------|----------------|
| VSP CISO | _to be filled_ |
| Engagement sponsor | _to be filled_ |
| Engineering POC | engineering@vsp.vn |
| Compliance POC | compliance@vsp.vn |
| 3PAO partner POC | _filled in by selected firm_ |

---

## 10. Sign-off

By signing below the assessor confirms it has read this SOW, has the
required FedRAMP-PMO accreditation (or AICPA / ANSI accreditation if
SOC 2 / ISO 27001), and accepts the deliverables in §3 and the
acceptance criteria in §5.

| | |
|---|---|
| VSP signatory: | _____________________ |
| Date: | _____________________ |
| 3PAO signatory: | _____________________ |
| Date: | _____________________ |
