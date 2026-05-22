---
title: "VSP Incident Response Tabletop Exercise — Q3-Q4 2026 Schedule"
subtitle: "Quarterly cadence, 4 scenarios, recorded in registry"
author: "VSP Security Engineering"
date: "8 May 2026"
---

# 1. Cover

| | |
|---|---|
| **TO:** | VSP Security Team (soc-team@vsp.vn) |
| **CC:** | Engineering Leads, CISO, Legal, CTO |
| **FROM:** | CISO Office |
| **DATE:** | 8 May 2026 |
| **SUBJECT:** | Tabletop exercise schedule — proof-of-practice for DSOMM L4 + 3PAO + SOC 2 |

# 2. Why now

DSOMM Level 4 ("Optimised") and SOC 2 Type II both require
**evidence of incident response practice** — not just runbooks. A
3PAO will ask: "When did you last conduct a ransomware tabletop?"

Today's answer is **"never recorded in our registry"**. We have:

- Migration `044_seed_tabletops.sql` with **4 scenario cards seeded**
  but `conducted_at = NULL` — these are templates, not exercises
- `/api/v1/tabletop/exercises` API ready to record results
- `/api/v1/tabletop/cadence` to surface "overdue" scenarios on the
  dashboard

What we don't have: 4 actually-conducted exercises with timestamps.

This proposal schedules them.

# 3. The 4 scenarios

Already seeded as cards via migration 044. Each has a 3-step inject
sequence and predefined objectives.

| # | Scenario | Family | When |
|---:|---------|--------|------|
| 1 | Ransomware: Postgres encrypted, ransom demand received | `ransomware` | 2026-07-15 (Q3) |
| 2 | Data breach: stolen admin token enables DSAR-driven exfiltration | `data_breach` | 2026-08-19 (Q3) |
| 3 | Supply chain: compromised dependency in nightly build | `supply_chain` | 2026-09-23 (Q3) |
| 4 | Cloud account takeover: compromised CI runner pivots to AWS prod | `cloud_account_takeover` | 2026-10-21 (Q4) |

All scenarios run **monthly mid-month** to avoid release weeks +
holidays. Each session is 90 minutes; budget 2 hours total
including pre-brief and debrief.

# 4. Calendar invite text (paste into the meeting)

> **Subject:** [TABLETOP] {SCENARIO_TITLE} — IR practice exercise
>
> **When:** {DATE} 10:00–11:30 ICT
> **Where:** Google Meet (link TBD) + war-room Slack channel
>
> Hi all,
>
> This is a **scheduled tabletop exercise** for DSOMM L4 +
> SOC 2 Type II evidence of incident response practice.
>
> **Scenario:** {SCENARIO_TEXT_FROM_REGISTRY}
>
> **Format:**
> - 0:00–0:10 — Pre-brief: scenario context, objectives, ground rules
> - 0:10–0:35 — Inject 1 + group response (no spoilers ahead!)
> - 0:35–1:00 — Inject 2 + group response
> - 1:00–1:20 — Inject 3 + group response
> - 1:20–1:30 — Debrief, observations, action items
>
> **Ground rules:**
> - Speak as if it were a real incident
> - No production changes during the exercise
> - "I would" / "I would call X" is acceptable; we're testing
>   decision-making, not access
> - Action items go into `/api/v1/tabletop/exercises` registry
>   immediately after debrief
>
> **Required attendees:** _list per registry seed_
>
> No prep needed — scenario will be shared at exercise start.
>
> _Facilitator_: {FACILITATOR_EMAIL}

# 5. Pre-exercise checklist (facilitator)

Day-of-exercise, 30 min before:

- [ ] Open `/api/v1/tabletop/exercises?scenario_kind={KIND}`
- [ ] Pull the seeded card; print or screen-share scenario text
- [ ] Verify all required attendees joined (chase missing)
- [ ] Open shared Google Doc for live note-taking
- [ ] Open Slack war-room channel for asynchronous comments
- [ ] Open `/api/v1/audit/bundle` in a tab — proves we have evidence
      to point at during the exercise

# 6. During the exercise

The facilitator runs the 3 injects per the seeded card. For each
inject:

1. **Read the inject** verbatim
2. **Open question** to participants: "What do you do?"
3. **Capture decisions in the live Google Doc** with timestamps
4. **Drift toward objectives**: at minute 25/50/85, ask whether the
   objectives listed in the card have been touched
5. **Strict timing**: 25 min per inject is the budget; cut off
   discussion to keep all 3 injects in scope

# 7. Post-exercise checklist (within 24h)

- [ ] Update the seeded card via
      `POST /api/v1/tabletop/exercises/{id}` with:
  - `conducted_at`: actual exercise time
  - `duration_min`: actual minutes (target: 90)
  - `participants`: comma-separated emails of who joined
  - `facilitator`: who ran it
  - `observations`: free-text summary (≥3 paragraphs)
  - `action_items`: JSON array `[{owner, due_date, description}]`
  - `rating`: pass / partial / fail / not_rated
- [ ] File action items as GitHub issues with label
      `tabletop-followup-{Q3|Q4}-2026`
- [ ] Send 1-page debrief email to CISO + CTO
- [ ] If rating is `fail` or `partial`, schedule a re-do within 30 days

# 8. Observation template

Use this 6-section structure for the `observations` field. Auditors
will read this verbatim — make it readable.

> **1. Decision quality.** _What did the team decide, and was it the
> right call given the inject?_
>
> **2. Missed signals.** _What inject details were missed or
> mis-prioritized?_
>
> **3. Communication gaps.** _Where did information stop flowing —
> across roles, between team and customer, between team and legal?_
>
> **4. Tooling gaps.** _What VSP feature would have helped that
> didn't exist or wasn't reached for?_
>
> **5. Runbook gaps.** _What runbook step was missing or wrong?_
>
> **6. Top action item.** _The single most important change to
> implement before the next exercise._

# 9. Q3-Q4 2026 calendar

| Date | Time (ICT) | Scenario | Facilitator | Recorder |
|------|-----------|----------|-------------|----------|
| 2026-07-15 Tue | 10:00–11:30 | Ransomware | _to assign_ | _to assign_ |
| 2026-08-19 Tue | 10:00–11:30 | Data breach | _to assign_ | _to assign_ |
| 2026-09-23 Tue | 10:00–11:30 | Supply chain | _to assign_ | _to assign_ |
| 2026-10-21 Tue | 10:00–11:30 | Cloud takeover | _to assign_ | _to assign_ |

After Q4 2026: rotate scenarios + add 4 more to the seed (insider
threat, DDoS, phishing, third-party outage already exist as scenario
families in the schema).

# 10. Budget

| Item | Cost | Justification |
|------|-----:|---------------|
| Internal facilitator time (4 × 2h) | $0 | Internal labour |
| External facilitator (optional) | $5,000–$15,000 | Coalfire / Schellman post-engagement add-on |
| Google Meet / Slack | $0 | Already provisioned |
| Note-taking tooling | $0 | Already provisioned |

External facilitator is the budget-line item in
`02_CFO_BUDGET_MEMO.md` §5 ("Tabletop facilitator (optional)").
**Recommendation: skip external for Q3, use internal CISO
facilitation; revisit for Q4 if observations show poor decision
quality.**

# 11. Approvals

| | |
|---|---|
| Approved by (CISO): | _____________________ |
| Date: | _____________________ |
| Confirmed by Engineering Leads: | _____________________ |
| Date: | _____________________ |

After CISO sign-off:

1. CISO sends Google Calendar invites for all 4 sessions
2. Facilitator + recorder roles assigned for each
3. Schedule appears in `/api/v1/tabletop/cadence` once first
   exercise is recorded
4. By 31 October 2026, all 4 exercises completed and registered
5. Registry data feeds into the SOC 2 Type II evidence bundle
   from Q1 2027 onwards
