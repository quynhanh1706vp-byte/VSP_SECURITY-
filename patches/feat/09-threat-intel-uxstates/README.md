# FEAT-10 — Threat Intel Panel UX States (Sprint 6 — Phase B start)

## What
Fifth panel using FEAT-04 shared VSPUXState module. First Phase B sprint.

Strips 3 of 4 mock arrays:
- IOCS (mock indicators) — backend /api/v1/ti/iocs already wired
- FEEDS (mock TI feeds) — backend /api/v1/ti/feeds already wired
- CVES (mock CVE list) — wires to NEW endpoint /api/v1/vulns/top-cves
  (was missing in original loadFromAPI)

Keeps MITRE (10 ATT&CK tactics — enterprise taxonomy, config not data).

## Why
Pattern same as FEAT-05/06/08:
- Mock rendered immediately on load (line 393)
- loadFromAPI fetched 3 endpoints but never CVES
- Panel showed fake CVE-2023-44487 etc. forever even with backend live

## Bonus fix
Original loadFromAPI was missing the CVES fetch — only IOCs/Feeds/Matches
were updated from backend. CVES table stuck on hardcoded mock 8 CVEs.
This patch adds the 4th parallel fetch to /api/v1/vulns/top-cves.

## Defensive design
All VSPUXState calls guarded with `typeof !== 'undefined'` via `hasUX` var.
Panel works (degraded) even if module fails.

## Apply
bash patches/feat/09-threat-intel-uxstates/apply.sh

## Verify
Browser console at https://vsp.local:
  fetch('/panels/threat_intel.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-10 PATCH APPLIED'),
    iocsMockGone: !t.includes("type:'ip',value:'185.220.101.47'"),
    emptyArrays: t.match(/var (IOCS|FEEDS|CVES)=\\[\\];/g)?.length || 0,
    mitreKept: t.includes("tactic:'Initial Access'"),
    cvesFetchAdded: t.includes('/api/v1/vulns/top-cves')
  }))

Expected: marker true, mock gone, emptyArrays=3, mitreKept true, cvesFetch true.

Visual: open Threat Intel panel ->
- IOCs table: skeleton -> real IOCs (or empty)
- Feeds list: skeleton -> real feeds (or empty)
- CVEs table: skeleton -> real top CVEs (or empty)  [NEW — was always mock before]
- MITRE grid: renders immediately (10 tactics, static config)

## Rollback
bash patches/feat/09-threat-intel-uxstates/rollback.sh

## Verified state (dry-run + apply)
- File: 946 -> 971 lines (+25 net)
- 5 patch steps reported success
- 3 empty arrays + MITRE preserved
- 17 VSPUXState integration points (6 skel + 6 empty + 3 error + 2 typeof)
- CVES endpoint /api/v1/vulns/top-cves wired (NEW)

## Phase B status (after this commit)
Sprint 6: threat_intel  DONE (FEAT-10 / this commit)
Sprint 7: sbom_diff     PENDING
Sprint 8: software_risk PENDING
Sprint 9: correlation   PENDING
Sprint 10: soar         PENDING
Sprint 11: log_pipeline DEFERRED (needs backend SSE)
