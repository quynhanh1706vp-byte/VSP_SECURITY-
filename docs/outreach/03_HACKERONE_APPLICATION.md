---
title: "HackerOne Program Application"
subtitle: "VSP Bug Bounty Program — pre-filled application content"
author: "VSP Security"
date: "8 May 2026"
---

# 1. Application overview

This document is **pre-filled content** to paste into the HackerOne
Customer onboarding form at `https://hackerone.com/start`. It
mirrors VSP's already-published Vulnerability Disclosure Policy
(`docs/security/VULNERABILITY_DISCLOSURE_POLICY.md`) so the program
launch is immediate.

**Alternative platforms** (use same content, different signup form):

- [Intigriti](https://www.intigriti.com/) — EU-headquartered alternative
- [Bugcrowd](https://www.bugcrowd.com/) — US alternative

Recommend HackerOne as primary; Intigriti has stronger EU coverage
and is the preferred platform for the EU-customer NIS2 attestation
narrative.

# 2. Company profile

| Field | Value |
|-------|-------|
| Company name | VSP — Vietnam Security Platform |
| Industry | Application security / DevSecOps platform |
| HQ country | Vietnam |
| Website | https://vsp.vn |
| Year founded | _2024_ (adjust per actual) |
| Employees | _<50_ (adjust per actual) |
| Revenue tier | _<$10M ARR_ (adjust per actual) |
| Primary contact | security@vsp.vn |
| Triage contact | security-triage@vsp.vn |

# 3. Program type

**Public** (recommended) — researchers can sign up and submit reports
without VSP-side approval.

If launching cautiously, start as **Private** for 30 days (selective
researchers only) then flip to public.

# 4. Asset scope (in-scope)

| Asset | Type | URL pattern |
|-------|------|-------------|
| Production gateway | Web | `https://app.vsp.vn/*` |
| Staging gateway | Web | `https://staging.vsp.vn/*` |
| Public API | API | `https://api.vsp.vn/api/v1/*` |
| Mobile clients (when published) | Mobile | iOS / Android (TBD) |
| Container images | OCI | `ghcr.io/vsp/*` |
| Source repository | Code | `github.com/vsp-platform/vsp` |

# 5. Out-of-scope

Copy-paste from `docs/security/VULNERABILITY_DISCLOSURE_POLICY.md`:

- Third-party services we integrate with (Stripe, Sentry, etc.) —
  report to them directly
- Findings dependent on physical access, social engineering, or
  insider threat
- Self-XSS, missing security headers without exploit, descriptive
  error messages
- Denial-of-service attacks against production
- Spam / phishing of VSP staff

# 6. SLA commitments

These match the VDP we've already published. **DO NOT relax these
on the HackerOne form** — researchers will use them in disputes.

| Phase | SLA |
|-------|-----|
| Acknowledgement | 1 business day |
| Initial triage | 5 business days |
| Severity assignment | 7 business days |
| Critical fix | 14 days |
| High fix | 30 days |
| Medium fix | 60 days |
| Low fix | 90 days |
| Disclosure coordination | 90 days from triage |

# 7. Bounty rewards

| Severity | CVSS v3.1 | Bounty (USD) |
|----------|-----------|-------------:|
| Critical | 9.0–10.0 | $2,000–$5,000 |
| High | 7.0–8.9 | $500–$1,500 |
| Medium | 4.0–6.9 | $100–$500 |
| Low | 0.1–3.9 | $50 |

**Anti-collusion rules:**
- Bounty paid only to first valid reporter
- Duplicates within 7 days = first reporter only
- Reports already triaged through `/api/v1/security/disclose`
  intake do not qualify (we count those as internal)

# 8. Safe harbour

Standard ISO/IEC 29147 safe-harbour text — copy from VDP §"Safe
Harbour":

> We will not pursue civil or criminal action against researchers
> who:
>
> - Comply with this policy
> - Avoid privacy violations, data destruction, and service
>   disruption
> - Do not access more data than necessary to demonstrate the issue
> - Give us reasonable time to remediate before public disclosure

# 9. Triage workflow integration

VSP intake endpoint: **`POST /api/v1/security/disclose`**.

Configure HackerOne to forward submissions to this endpoint via
their **Custom Webhook** integration. The endpoint expects:

```json
{
  "reporter_email": "researcher@example.com",
  "reporter_name": "Researcher Name",
  "title": "Brief title (≤200 chars)",
  "body": "Full report (Markdown OK, ≤64k)",
  "affected": "Component / URL",
  "cvss_v3": 7.5
}
```

Our backend automatically:
- Computes ack-due / triage-due timestamps from VDP SLAs
- Generates public reference `VSP-VDR-YYYY-NNNN` after acknowledgement
- Routes to security@vsp.vn for triage assignment
- Audit-logs every state transition

# 10. Launch checklist (pre-public)

| Item | Owner | Due |
|------|-------|-----|
| HackerOne private program signup | CISO | week 1 |
| 5 researcher private invitations sent | CISO | week 2 |
| Triage rotation calendar set up | Security team | week 2 |
| First valid report processed end-to-end | Security team | week 4 |
| Bounty payment processor verified (wire / Stripe) | CFO | week 4 |
| Flip to public | CISO | week 5 |
| Update `/trust/` Trust Center with HackerOne badge | Engineering | week 5 |
| Update `/.well-known/security.txt` Contact: line | Engineering | week 5 |
| First quarterly report published | Security team | end of Q3 |

# 11. Budget alignment

Per `docs/outreach/02_CFO_BUDGET_MEMO.md` §5: **$5,000–$15,000 per
quarter** ($20k–$60k/year).

Within that envelope, expect:

- Platform fee: $5,000–$10,000/quarter (HackerOne tiered)
- Bounty payouts: $1,000–$5,000/quarter (first 2 quarters; scales with
  program maturity)
- Triage time (internal): security team allocates ~20% of one FTE

# 12. Submission

After CFO approves the $250k Q3 budget:

1. CISO logs into HackerOne and creates the program (15 minutes)
2. Pastes content from §2-§9 of this document
3. Connects payment via Stripe / wire
4. Sends 5 private invitations to vetted researchers
5. After 30 days, flips to public + announces on `/trust/` + Twitter
   + Vietnamese tech community channels

**Total elapsed time from CFO signoff to public launch: ~35 days.**
