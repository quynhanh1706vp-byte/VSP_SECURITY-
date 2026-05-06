# FEAT-11 — SBOM Diff Panel UX States (Sprint 7 — Phase B continued)

## What
Sixth panel using FEAT-04 shared VSPUXState module. UX upgrade only — no mock to strip (var RUNS=[] already empty).

## Why
Original `runDiff()` used `alert()` for errors (blocking, ugly, no retry).
Empty sections used plain `<tr>` markup instead of consistent UX state component.

## Changes
- runDiff() entry: skeleton on 3 tables (#tbl-new, #tbl-fixed, #tbl-persisted)
- runDiff() per-section: VSPUXState.empty if length === 0 (was plain "<tr>No items</tr>")
- runDiff() catch: VSPUXState.error + retry callback (was alert popup)

loadRuns() unchanged — populates <select> dropdowns, not table.

## Defensive
typeof VSPUXState guard via hasUX var. alert() kept as else fallback.

## Apply
bash patches/feat/10-sbom-diff-uxstates/apply.sh

## Rollback
bash patches/feat/10-sbom-diff-uxstates/rollback.sh

## Verified
- 885 -> ~895 lines
- 3 patch steps success
- skeleton/empty/error: 3/3/3 calls
