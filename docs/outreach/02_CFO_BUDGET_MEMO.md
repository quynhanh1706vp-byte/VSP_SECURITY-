---
title: "Budget Memo — Q3 2026 Compliance & Security Investment"
subtitle: "Path from DSOMM 3.95 to 4.0 Certified"
author: "VSP Engineering / CISO"
date: "8 May 2026"
---

# 1. Memorandum

| | |
|---|---|
| **TO:** | Chief Financial Officer, VSP |
| **CC:** | CTO, CISO, CEO |
| **FROM:** | VSP Engineering & Compliance |
| **DATE:** | 8 May 2026 |
| **SUBJECT:** | Q3 2026 budget request — $120,000 to $250,000 for external security attestation |

# 2. Executive summary

VSP has reached **DSOMM 3.95 self-attested** (verified by audit
evidence bundle and 22-framework compliance mapping). The remaining
gap to **DSOMM 4.0 Certified / FedRAMP Moderate ATO / SOC 2 Type II**
is **structurally non-closeable in code** — it requires external
attestation by accredited bodies.

We request **$120,000–$250,000** in Q3 2026 to close this gap across
five line items, unlocking enterprise + government revenue currently
blocked by procurement security reviews.

**ROI:** A single FedRAMP Moderate ATO unlocks the US federal market
(~$130B annually). Even one mid-size government contract recovers
the full $250k budget.

# 3. Current state

| Metric | Value | Verification |
|--------|-------|--------------|
| DSOMM maturity | 3.95 / 4.0 | `/api/v1/audit/bundle` |
| Compliance frameworks self-mapped | 22 | `/trust/` Trust Center |
| Self-attestation endpoints | 8 | `/api/v1/recognition/*` |
| Scanner integrations | 26 | `internal/scanner/` |
| Code-side blocker for 4.0 | **None** | Engineering signed-off |

# 4. The gap explained

DSOMM 4.0 Certified requires three categories of evidence we cannot
produce ourselves:

1. **Independent assessment** — a 3PAO firm verifies our controls
   work as documented. Cannot be self-attested.
2. **Operating effectiveness over time** — SOC 2 Type II requires
   3-6 months of audit-trail evidence the controls operate
   continuously. We have the audit trail; we need an auditor to
   review it.
3. **Public exposure to security researchers** — bug bounty programs
   force the platform to handle external disclosures with
   commitment-level SLAs. Our intake is built; the bounty platform
   contract is missing.

These are commercial relationships, not code.

# 5. Proposed Q3 2026 spend

| Line item | Budget | Recurring | Vendor candidates |
|-----------|-------:|-----------|-------------------|
| 3PAO assessment (FedRAMP Moderate-aligned) | $80k–$150k | One-time | Coalfire Federal, Schellman, A-LIGN |
| Bug bounty platform contract | $5k–$15k/qtr ($20k–$60k/yr) | Recurring | HackerOne, Intigriti |
| Public status page hosting | $25–$100/mo ($300–$1,200/yr) | Recurring | Statuspage.io, Cachet self-host |
| SOC 2 Type II audit firm | $30k–$80k | Annual recurring | Marcum, Sensiba San Filippo, BDO |
| Tabletop facilitator (optional, external) | $5k–$15k | Quarterly | Schellman, Coalfire (overlap with 3PAO) |
| **Total Q3 2026 (worst case)** | **$120k–$246k** | | |
| **Recurring annual after Q3** | **$50k–$140k/year** | | |

## 5.1 Phasing

If full $250k cannot be approved in one quarter, we recommend the
following priority order:

| Priority | Item | Spend | Why first |
|---------:|------|------:|-----------|
| 1 | 3PAO assessment | $80–150k | Unlocks all other certifications + FedRAMP path |
| 2 | Bug bounty Q3 launch | $15k | Public commitment we can publicise immediately |
| 3 | Statuspage.io | $300 | $300 = 90 days uptime evidence; cheapest item |
| 4 | SOC 2 Type II audit firm engagement | $30k | Triggers 3-6 mo operating effectiveness window |
| 5 | External tabletop facilitator | $5k | Optional; internal team can run if budget tight |

# 6. ROI justification

## 6.1 Revenue impact (if we secure FedRAMP ATO)

US federal IT spending in 2024 was approximately **$130B**, of which
**~$22B** went to cloud services subject to FedRAMP. Even capturing
**0.001%** ($220k) of this market in year 1 recovers the entire
$250k budget.

VSP's competitive advantages for the US federal market:

- **OSCAL machine-readable compliance** (rare in our segment)
- **Air-gapped (DoD-compatible) deployment**
- **26-tool scanner integration** (industry-leading breadth)
- **Multi-framework cross-attestation** (NIST + CMMC + CISA SSDF)

## 6.2 Revenue impact (if we secure SOC 2 Type II)

Enterprise SaaS deals routinely require SOC 2 Type II as a hard
prerequisite. VSP currently **cannot bid** on these RFPs without it.
A single typical $200k/year enterprise SaaS contract recovers the
$80k SOC 2 audit cost in 5 months.

## 6.3 Risk mitigation

Without these attestations:

- **Customer churn risk** — existing enterprise customers are
  starting to ask for SOC 2 Type II in renewal cycles
- **Sales cycle stretching** — without attestations, security
  reviews add 3-6 months to every enterprise sale
- **Talent retention** — security-conscious engineers prefer to
  work on certified platforms

# 7. Budget approval flow

**Decision needed by 30 May 2026** to keep Q3 timeline (3PAO
engagement starts 16 June; SOC 2 Type II audit firm contract by
1 July to start the 3-6 month evidence window).

| Approval level | Amount | Approver |
|----------------|-------:|----------|
| Engineering operating budget | $0 | Already covered by Sprint 2-10 work |
| Special compliance budget | $250k | CFO + CEO |
| Annual recurring (Year 2+) | $140k/year | CFO sign-off in Q4 budget cycle |

# 8. Approval signature

I, the undersigned, approve the Q3 2026 compliance & security
investment of up to **$250,000** as outlined in §5 of this memo.

| | |
|---|---|
| Approved by (CFO): | _____________________ |
| Date: | _____________________ |
| Co-signed by (CEO): | _____________________ |
| Date: | _____________________ |
| Engineering POC for execution: | engineering@vsp.vn |

**Once approved**, expected first commit ($80k 3PAO retainer) hits
the ledger by 1 July 2026; first attestation letter (SOC 2 Type I)
expected by 31 August 2026; FedRAMP Moderate ATO targeting 31 January
2027 (with continuous monitoring evidence runway).
