---
title: "Statuspage Migration Plan"
subtitle: "Publishing VSP Public Status Feed"
author: "VSP Engineering / Ops"
date: "8 May 2026"
---

# 1. Goal

Publish VSP's operational status to a public, externally-hosted
status page so that:

1. Customers can subscribe to incident notifications without an
   account
2. Auditors / 3PAOs can verify uptime claims independently
3. The 90-day uptime history starts accruing from launch — required
   for the "operational effectiveness" evidence in SOC 2 Type II
4. Trust Center page (`/trust/`) consumes the same data via API

# 2. Vendor selection

| Vendor | Cost | Fit | Recommendation |
|--------|-----:|-----|----------------|
| **Statuspage.io** (Atlassian) | $29-99/mo | Best brand recognition, mature integrations | **Primary recommendation** |
| Instatus | $20-50/mo | Cheaper, simpler UI | Acceptable budget alternative |
| Cachet (self-hosted) | Free + hosting | Full control, lower trust signal | Only if data residency forces it |
| GitHub Pages + Hugo | $0 + dev time | Full control, lowest trust signal | Not recommended |

**Choose Statuspage.io.** Brand recognition matters for trust
signalling. Cost ($29/mo Hobby = $348/year) is rounding error in
the $250k Q3 budget.

# 3. Components to monitor

Map directly to `GET /api/v1/status` JSON shape:

| Component | Source signal | Statuspage status name |
|-----------|---------------|------------------------|
| Gateway API | `components[].name=="gateway"` | "API Gateway" |
| Scanner pipeline | `components[].name=="scanner"` | "Scan Pipeline" |
| Audit log | `components[].name=="audit_log"` | "Audit Log Integrity" |
| Database | (from /api/v1/status compute) | "Primary Database" |
| Redis | (from /api/v1/status compute) | "Cache & Queue" |
| External integrations (Stripe, VirusTotal) | manual | "Third-Party Integrations" |

Status mapping:

| `/api/v1/status` value | Statuspage status |
|------------------------|-------------------|
| `operational` | Operational |
| `degraded` | Degraded Performance |
| `partial_outage` | Partial Outage |
| `major_outage` | Major Outage |

# 4. Automated polling setup

Statuspage.io supports component status updates via REST API.
Cron-based polling pulls VSP `/api/v1/status` every 60 seconds
and pushes deltas.

## 4.1 GitHub Actions workflow (recommended)

```yaml
# .github/workflows/statuspage-sync.yml
name: Statuspage Sync

on:
  schedule:
    - cron: '* * * * *'  # every minute
  workflow_dispatch:

permissions:
  contents: read

jobs:
  sync:
    runs-on: ubuntu-latest
    timeout-minutes: 2
    steps:
      - name: Pull VSP status
        env:
          VSP_BASE: ${{ secrets.PROD_BASE_URL }}
          SP_PAGE_ID: ${{ secrets.STATUSPAGE_PAGE_ID }}
          SP_API_KEY: ${{ secrets.STATUSPAGE_API_KEY }}
        run: |
          set -euo pipefail
          curl -s "$VSP_BASE/api/v1/status" -o vsp.json
          # Map components to statuspage IDs and PATCH each.
          ./scripts/sync_statuspage.sh vsp.json
```

Implementation script in `scripts/sync_statuspage.sh` (~60 lines)
will:

1. Read `/api/v1/status` JSON
2. For each component, look up Statuspage component ID from
   `STATUSPAGE_COMPONENT_MAP` env var
3. PATCH `https://api.statuspage.io/v1/pages/{page_id}/components/{id}`
   with `{component: {status: ...}}`
4. Idempotent — only patches when status differs from last fetch

## 4.2 Alternative: webhook receiver

If GHA polling is too brittle, deploy a small relay:

- Statuspage.io provides webhook ingestion endpoints
- VSP gateway already emits notifications via DLQ → fanout
- Add a Statuspage destination to `notification_config` table
- Outbound webhooks flow naturally with HMAC signing + cert pinning

# 5. Incident templates

Pre-write 4 incident templates for common scenarios so the on-call
engineer can paste rather than draft mid-incident:

## 5.1 Investigating template

> **{COMPONENT} performance issue — investigating**
>
> We're investigating reports of degraded performance on
> {COMPONENT}. Symptoms: {OBSERVED}. Initial diagnosis underway.
> Updates every 15 minutes.

## 5.2 Identified template

> **{COMPONENT} root cause identified — implementing fix**
>
> We've identified the root cause as {RC}. A fix is being
> deployed; ETA {ETA}. Customer impact: {IMPACT}.

## 5.3 Monitoring template

> **{COMPONENT} fix deployed — monitoring**
>
> The fix has been deployed and metrics are returning to
> baseline. We will monitor for {N} minutes before declaring
> resolved.

## 5.4 Resolved template

> **{COMPONENT} resolved — full post-mortem within 5 business days**
>
> The issue is fully resolved. Total customer-visible impact:
> {DURATION}. Affected: {SCOPE}. A full post-mortem will be
> published at status.vsp.vn within 5 business days.

# 6. Subscriber notification configuration

Statuspage offers email + SMS + Slack + RSS subscriptions. Enable
all by default.

For enterprise customers (PRO tenant tier), additionally:

- **Webhook subscription** — push to their status-aggregation tool
- **Daily digest** — even on green days, send "operational" summary

# 7. Trust Center integration

Update `/trust/index.html` Live Operational Status section to also
embed Statuspage's badge:

```html
<!-- Add below current live status block -->
<a href="https://status.vsp.vn"
   target="_blank"
   class="statuspage-badge">
  <img src="https://status.vsp.vn/badge"
       alt="VSP Status" />
</a>
```

This gives customers a single source of truth across both `/trust/`
(internal-pulled) and `status.vsp.vn` (externally-hosted).

# 8. Migration timeline

| Phase | Duration | Action | Owner |
|-------|----------|--------|-------|
| 1 — Signup | 1 day | CFO approves $348/yr; Ops signs up Statuspage Hobby plan | Ops + CFO |
| 2 — Component setup | 1 day | Create 6 components per §3 | Ops |
| 3 — Sync workflow | 2 days | Deploy `.github/workflows/statuspage-sync.yml` + `scripts/sync_statuspage.sh` | Engineering |
| 4 — Smoke test | 1 day | Manually trigger a fake degraded state; verify it reaches subscribers | Engineering |
| 5 — Launch | 1 day | Update DNS `status.vsp.vn` → Statuspage.io; announce in `/trust/` | Engineering + Marketing |
| **Total** | **~1 week** | | |

90-day uptime data starts accruing from Phase 5. SOC 2 Type II
operational-effectiveness evidence requires ≥3 months of clean
data — so launching by **15 June 2026** ensures we have evidence
ready for a Q4 2026 SOC 2 audit window.

# 9. Cost summary

| Item | Year 1 | Recurring |
|------|-------:|----------:|
| Statuspage.io Hobby plan ($29/mo) | $348 | $348/yr |
| Engineering time (~1 week) | $5,000 | $0 (one-time setup) |
| **Total** | **$5,348** | **$348/yr** |

Within `02_CFO_BUDGET_MEMO.md` §5 line item for "Public status page"
($25–$100/mo = $300–$1,200/yr).
