# 3PAO Engagement — Operator's Guide

**Audience:** VSP CISO + engineering team running an external audit
**Purpose:** Step-by-step playbook for engaging Coalfire / Schellman /
similar from RFP through final report.

This guide is opinionated and short. Long enough to be useful, short
enough to actually get read.

---

## Phase 0 — Before sending any RFP (1 week)

1. **Run the KPI sanity check** — `curl -s /api/v1/kpi/sanity | jq`.
   It should return HTTP 200 with all assertions `passed: true`. If
   not, fix before engaging an external party.
2. **Generate the audit bundle** — `curl -OJL /api/v1/audit/bundle`.
   Open the zip; verify manifest.json checksums. The assessor will
   ask for this on day 1.
3. **Verify all attestations are current** — the `/trust` page should
   show today's date in the operational status section.
4. **Refresh the risk register** — `docs/audit/RISK_REGISTER.md`
   reviewed at the most recent quarterly checkpoint.
5. **Confirm budget approval** — Coalfire / Schellman quotes have a
   3-month validity; secure budget commitment first.

**Output of Phase 0:** signed-off internal readiness checklist that
proves we are *worth* a 3PAO's time.

---

## Phase 1 — RFP (2 weeks)

Send `docs/audit/3PAO_STATEMENT_OF_WORK.md` and
`docs/audit/SCOPE_OF_TEST.md` to at least three firms. Suggested
shortlist (FedRAMP-PMO accredited as of 2026):

- Coalfire Federal
- Schellman Compliance
- A-LIGN
- Kratos Defense / SecureInfo
- MorganFranklin

For SOC 2 / ISO 27001 (non-FedRAMP) add: Marcum, Sensiba San Filippo,
BDO Digital.

Selection criteria:
1. **Vietnam / DoD experience** — preferred for VSP's market mix.
2. **Fixed price** with capped re-test fees.
3. **Lead assessor's CV** (look for prior FedRAMP Moderate
   engagements at companies our size).
4. **Insurance** — at least $5M E&O / Cyber Liability.
5. **References** — call two prior clients before signing.

**Output of Phase 1:** signed Master Service Agreement + first
Statement of Work + project schedule.

---

## Phase 2 — Kickoff (week 1)

Day 1 actions:

- Issue assessor JWT + API key + GitHub deploy key
  (15-minute task — `cmd/vsp-cli` issues credentials)
- Send the audit bundle (Section §4 of SOW)
- Schedule weekly Friday status calls
- Open #3pao-engagement Slack channel; invite assessor leads

Day 2-5:

- Walk through `docs/ARCHITECTURE.md` (90 min)
- Walk through SSDF + NIST CSF profile (60 min)
- Demo `/trust` Trust Center page (15 min)
- Demo audit bundle reproducibility (run verification block from
  `docs/SPRINT_2026Q2_FINAL_REPORT.md` §6)

**Output of Phase 2:** assessor's engagement plan PDF accepted by
VSP.

---

## Phase 3 — Active assessment (4-6 weeks)

Engineering team commitments:

- **Daily**: respond to assessor questions within 4 business hours
- **Weekly**: triage assessor findings, mark each as
  `accept | dispute | remediate`
- **Per Critical finding**: convene incident response within 4 hours;
  if confirmed, hotfix within 14 days
- **Per High finding**: assign owner + due date within 1 business day

Tools to use:

- **`/api/v1/security/disclose` for Critical findings** — assessor
  uses the same endpoint a researcher would, ensures uniform SLA
  tracking
- **`/api/v1/audit/bundle` re-run** — refresh weekly so assessor sees
  the latest evidence
- **`/api/v1/kpi/sanity` continuous** — if it ever returns 409 during
  the engagement, fix immediately; the assessor will see it

What to **NOT** do during assessment:

- Don't ship new features that touch in-scope code without telling
  the assessor — they'll have to re-test
- Don't disable scoring / sanity checks because the assessor flagged
  noise; fix the underlying issue
- Don't argue with findings in writing — write a "VSP response"
  appendix to the SAR instead

**Output of Phase 3:** draft Security Assessment Report (SAR) +
findings register.

---

## Phase 4 — Remediation + final report (1-2 weeks)

For each finding in the draft SAR:

- **Accept** (with risk-acceptance memo + POA&M milestone)
- **Dispute** (with engineering rebuttal + assessor review)
- **Remediate** (with code change + re-test by assessor)

Issue a final SAR + signed POA&M. Assessor delivers their letter of
attestation (FedRAMP) or unqualified opinion (SOC 2) or Stage 1
report (ISO 27001).

**Output of Phase 4:** signed final SAR + POA&M with milestone dates.

---

## Phase 5 — Public communication (1 week)

After final SAR:

1. Update `/trust/` Trust Center page:
   - Move the relevant attestation from "self-attested" to
     "third-party attested"
   - Link to the assessor's letter (or attestation report excerpt)
2. Update `docs/EXECUTIVE_REPORT_2026Q2.md` and the corresponding
   `.docx` to reflect the actual DSOMM / SOC 2 / ISO 27001 status
3. Send customer notification to enterprise tier
4. Update sales materials with the new badge / attestation
5. Schedule next surveillance audit (typically 12 months out for SOC 2,
   3 years for ISO 27001)

---

## Phase 6 — Surveillance & continuous improvement (ongoing)

- Quarterly: regenerate audit bundle, run KPI sanity, refresh risk
  register
- Quarterly: log a tabletop exercise covering each canonical scenario
- Annually: full re-engagement of 3PAO for surveillance audit
- Triannually (ISO 27001): full recertification audit

The KPI watchdog + improvement metrics endpoints are designed to make
this maintenance work mechanical rather than heroic.

---

## Common pitfalls

| Pitfall | Avoidance |
|---------|-----------|
| Engaging without budget approval | Phase 0 checklist |
| Picking the cheapest assessor | Get references; cheap usually = junior team |
| Letting assessor questions queue up | 4-business-hour SLA enforced internally |
| Disabling KPI sanity to "pass" assessment | Fix underlying invariant; assessor will catch it anyway |
| Treating self-attestation as final | The whole point of this engagement is external validation |
| Forgetting Vietnam-specific requirements | Verify Decree 13/2023 + 53/2022 + Luật ANM 2018 mappings explicitly |

---

## Appendix — pre-signed evidence list

When the assessor asks "show me X", here's where X lives:

| Asked-for evidence | Where |
|--------------------|-------|
| Audit chain integrity | `GET /api/v1/audit/verify` |
| Latest evidence bundle | `GET /api/v1/audit/bundle` (zip) |
| SSDF self-attestation | `GET /api/v1/cisa-attestation/ssdf/draft` |
| NIST CSF profile | `GET /api/v1/nist-csf/profile` |
| SOC 2 readiness | `GET /api/v1/recognition/soc2-readiness` |
| ISO 27001 mapping | `GET /api/v1/recognition/iso27001-mapping` |
| Public status | `GET /api/v1/status` |
| Transparency report | `GET /api/v1/transparency/report` |
| Disclosure SLA hits | `GET /api/v1/security/disclosures` (admin) |
| Tabletop exercise log | `GET /api/v1/tabletop/exercises` (admin) |
| Risk register | `docs/audit/RISK_REGISTER.md` |
| SSP / OSCAL artefacts | `GET /api/p4/oscal/ssp` |
| SLSA provenance per release | `GET /api/v1/runs/{rid}/provenance` |
| Public Rekor entry | UUID returned from `POST /provenance/publish-rekor` |
| OpenSSF Scorecard | GitHub Security tab + scorecard.dev/projects/<repo> |
| KPI sanity (release gate) | `GET /api/v1/kpi/sanity` |

If the assessor asks for something not in this table, treat it as a
gap and triage in the daily standup.
