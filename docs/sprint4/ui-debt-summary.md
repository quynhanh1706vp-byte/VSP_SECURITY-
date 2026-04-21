# UI debt inventory — Sprint 4 input

**Generated:** 2026-04-21T07:40:57Z
**Branch:** main
**Commit:** 36b8e91

## Risk breakdown

| Risk  | Count | Must fix Sprint 4? |
| ----- | ----- | ------------------ |
| CRIT  | 140 | YES — 100% (all auth tokens in localStorage) |
| HIGH  | 15 | YES — 100% (template literal innerHTML, dynamic data) |
| MED   | 233 | Partial — review each, auto-fix the obvious |
| LOW   | 8 | Later — innerHTML += is rarely exploitable |
| **TOTAL** | **396** | |

## Top 10 files by debt count

```
61 static/index.html
26 static/panels/p4_compliance.html
22 static/vsp_upgrade_v100.js
18 static/network_deep.html
16 static/p4_compliance.html
14 static/panels/correlation.html
13 static/panels/sw_inventory.html
11 static/panels/threat_intel.html
10 static/panels/network_flow.html
10 static/panels/cicd.html
```

## Recommended Sprint 4 plan

- **Week 1:** Fix all CRIT (140 localStorage auth sites) via shared helper.
  See `scripts/sprint4/migrate-localstorage.sh` (to be written).
- **Week 2:** Fix all HIGH (15 template literal innerHTML) via DOMPurify or
  `textContent` replacement.
- **Defer:** MED + LOW to Sprint 5 cleanup pass.

## Files

- `ui-debt-inventory.csv` — spreadsheet-friendly, 1 row per hit
- `ui-debt-inventory.json` — tooling-friendly, same data

## Evidence for DSOMM 3.7 track

- **Test & Verification +0.05:** we now *measure* UI debt, not just *guess* it.
- **Culture & Org +0.03:** research-before-fix instead of estimate-based planning.
