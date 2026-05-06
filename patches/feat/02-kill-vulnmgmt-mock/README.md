# FEAT-02 — Kill Mock Data in Vuln Mgmt Panel

## What
Removes 4 hardcoded mock arrays from static/panels/vuln_mgmt.html:
- SAMPLE_TREND (IIFE that generates 30 days of fake declining-severity trend)
- SAMPLE_CVES (8 fake CVEs: CVE-2023-44487, CVE-2024-21626, etc.)
- SAMPLE_TOOLS (4 fake tools: semgrep, gosec, trivy, govulncheck with fake counts)
- SAMPLE_SLA (4 fake SLA percentages)

## Why
Pattern was the same as FEAT-01 (assets):
- Mock rendered IMMEDIATELY on panel load (line 447-452: 6 renderX(SAMPLE_*) calls)
- After fetch, fell back to mock if API empty (line 472-479: cd.length ? cd : SAMPLE_CVES)
- Users saw fake CVE-2023-44487 / runc escape data even when real backend had data

## How
- 4 arrays replaced with empty literals
- Initial 6-call mock render block replaced with skeleton trigger
- Fetch fallback pattern X.length ? X : SAMPLE_Y rewritten to use empty state
- New _vmLoadSLA() function fetches /api/v1/vsp/sla_tracker and computes pct
- Helpers _vmShowSkeleton/_vmShowEmpty/_vmShowError injected before </script>
- CSS keyframe vm-shimmer injected before <script>

## Backend endpoints used
- /api/v1/vulns/trend       → SAMPLE_TREND replacement
- /api/v1/vulns/top-cves    → SAMPLE_CVES replacement
- /api/v1/vulns/by-tool     → SAMPLE_TOOLS replacement
- /api/v1/vsp/sla_tracker   → SAMPLE_SLA replacement (NEW wire)

## Apply
bash patches/feat/02-kill-vulnmgmt-mock/apply.sh

## Verify
Browser console at https://vsp.local:

  fetch('/panels/vuln_mgmt.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-02 PATCH APPLIED'),
    trendMockGone: !t.includes('Simulate declining trend'),
    cveMockGone: !t.includes('HTTP/2 Rapid Reset Attack'),
    emptyArrays: t.match(/var SAMPLE_\w+ = \[\];/g)?.length || 0
  }))

Expected: marker true, both mocks gone, emptyArrays=4.

## Rollback
bash patches/feat/02-kill-vulnmgmt-mock/rollback.sh

## Verified state (dry-run)
- File: 1861 → 1858 lines
- 8 stripping/injection steps all reported success
- exit code 0
