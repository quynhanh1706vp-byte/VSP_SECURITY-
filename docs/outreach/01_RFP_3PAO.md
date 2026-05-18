---
title: "Request for Proposal — Third-Party Security Assessment"
subtitle: "VSP Platform — VSP Security Audit Engagement Q3 2026"
author: "VSP Engineering / Compliance"
date: "8 May 2026"
---

# 1. Cover letter

**To:** _[Account Manager — Coalfire Federal / Schellman Compliance / A-LIGN]_
**From:** _[CISO / VSP Engineering]_, security@vsp.vn
**Date:** _to be filled at send_
**Subject:** RFP — Third-Party Security Assessment for VSP Platform v1.4 (FedRAMP Moderate-aligned)

Dear _[Firm Name]_,

VSP (Vietnam Security Platform) is requesting proposals for a
third-party security assessment of our DevSecOps platform aligned
with one of the following frameworks:

- **FedRAMP Moderate baseline** (preferred)
- **SOC 2 Type I — Security & Availability**
- **ISO/IEC 27001:2022 Stage 1 readiness review**

We are at **DSOMM 3.95 self-attested** with full code-side controls
in place, and engaging a 3PAO is the explicit next step on our path
to **DSOMM 4.0 / FedRAMP Moderate ATO**.

This RFP includes everything you need to scope the engagement
without further pre-engagement calls:

- Statement of Work template (`docs/audit/3PAO_STATEMENT_OF_WORK.md`)
- Scope of Test (`docs/audit/SCOPE_OF_TEST.md`)
- Risk Register (`docs/audit/RISK_REGISTER.md`)
- Architecture diagram (`docs/ARCHITECTURE.md`)
- Pre-built audit evidence bundle: `GET /api/v1/audit/bundle`
  (zip with manifest.json + 11 artefact groups + SHA-256 per file)

We expect proposals to be **fixed-price** with a clear change-order
process. Please respond by **30 May 2026**.

Sincerely,

_[CISO Name]_
Chief Information Security Officer
VSP Platform
security@vsp.vn

---

# 2. Engagement summary

## 2.1 Target framework

| Option | Preference | Why |
|--------|:----------:|-----|
| FedRAMP Moderate | ✓ Primary | Targeting US federal customers + DoD pipeline |
| SOC 2 Type I | Acceptable | Required by enterprise SaaS customers |
| ISO 27001:2022 Stage 1 | Acceptable | Required for EU customers under NIS2 |
| Combined SOC 2 + ISO 27001 | Bonus | If your firm offers both with shared evidence |

## 2.2 System scope

| Component | Description |
|-----------|-------------|
| Gateway service | `cmd/gateway` — public HTTP API (150+ endpoints) |
| Cosign API | `cmd/cosign-api` — supply-chain sign / verify |
| DAST API | `cmd/dast-api` — DAST execution |
| Email API | `cmd/email-api` — outbound notifications |
| Scanner orchestrator | `cmd/scanner` — 26-tool unified runner |
| Scheduler API | `cmd/scheduler-api` — cron-based scans |
| Software inventory | `cmd/sw-inventory` — SBOM aggregation |
| Helm chart | `deploy/helm/` — production deployment artefact |
| PostgreSQL 14+ | Schema in `migrations/` (44 migrations) |
| Redis 6+ | Cache + asynq queue + JWT blacklist |

Total Go source: ~50,000 lines across 25+ internal packages.

## 2.3 Out-of-scope

- Customer-deployed infrastructure (datacentre, network, OS hardening)
- Customer-managed identity provider (OIDC / SAML federation partner)
- Third-party SaaS integrations (Stripe, VirusTotal, Slack)
- Production data and live customer-tenanted environments

# 3. Proposal requirements

Please include:

1. **Engagement plan** — phases, weekly milestones, total duration
2. **Lead assessor's CV** — prior FedRAMP Moderate or SOC 2 experience
3. **Fixed price** with capped re-test fees
4. **Insurance** — minimum $5M E&O / Cyber Liability
5. **References** — 2 prior engagements at companies of similar size
6. **3PAO accreditation status** — FedRAMP-PMO or AICPA license #
7. **Deliverables list** — minimum the 7 deliverables in our SOW §3
8. **Vietnam / DoD experience** — if any (preferred, not required)

# 4. Indicative pricing tiers

For reference (you may quote within or outside these ranges):

| Engagement | Indicative range | Duration |
|------------|----------------:|----------|
| FedRAMP Moderate readiness assessment | $80,000–$150,000 | 4–6 weeks |
| SOC 2 Type I attestation | $25,000–$60,000 | 3–5 weeks |
| ISO 27001:2022 Stage 1 readiness review | $15,000–$35,000 | 2–4 weeks |
| Combined SOC 2 Type I + ISO 27001 Stage 1 | $35,000–$80,000 | 4–6 weeks |

# 5. Selection criteria

We will evaluate proposals on (in order):

1. **Lead assessor seniority** — minimum 5 years at FedRAMP-accredited firms
2. **Vietnam / DoD relevance** — preferred, given our market mix
3. **Fixed price + change-order clarity** — no time-and-materials surprises
4. **References** — we will call both before signing
5. **Proposed schedule** — 4–6 weeks preferred; <3 weeks suggests undersized team

# 6. Response logistics

- **Submission deadline:** 30 May 2026, 17:00 ICT
- **Q&A period:** through 23 May 2026 — questions to security@vsp.vn
- **Selection decision:** by 6 June 2026
- **Engagement kickoff target:** 16 June 2026

For technical Q&A, our engineering POC is **engineering@vsp.vn**.
For commercial Q&A, **compliance@vsp.vn**.

# 7. Attachments (sent with this RFP)

- `docs/audit/3PAO_STATEMENT_OF_WORK.md` — Statement of Work template
- `docs/audit/SCOPE_OF_TEST.md` — Scope of Test
- `docs/audit/RISK_REGISTER.md` — Risk register (22 risks)
- `docs/audit/AUDIT_ENGAGEMENT_GUIDE.md` — VSP-side engagement playbook
- `docs/EXECUTIVE_REPORT_2026Q2.docx` — Executive overview of platform
- VSP self-attested mappings (live JSON at):
  - `/api/v1/cisa-attestation/ssdf/draft`
  - `/api/v1/nist-csf/profile`
  - `/api/v1/recognition/soc2-readiness`
  - `/api/v1/recognition/iso27001-mapping`
  - `/api/v1/recognition/pci-dss-mapping`
  - `/api/v1/recognition/nis2-mapping`
  - `/api/v1/recognition/hitrust-mapping`
  - `/api/v1/recognition/ccpa-mapping`

The audit evidence bundle is generated on-demand per tenant — we
will provide a fresh download link upon receiving an engagement
NDA.

Thank you for your time. We look forward to your proposal.

Sincerely,

_[CISO Name]_
VSP Platform
