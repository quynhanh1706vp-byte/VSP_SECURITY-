# Sprint UX Hardening v1.0 — Closing Notes

**Tag:** v1.0-l2-complete (commit ddf59ad)
**Date closed:** 2026-05-06

## Shipped
- FEAT-23 → FEAT-34: 11 panels with VSPUXState instrumentation
- 160 UX state calls across panels
- 4 zombie silent catches eliminated
- assets.html: render-call-missing fix as bonus

## Deferred (with reasons)
- **FEAT-34b**: drop FEAT-01 self-recursion in loadAssets — FIXME marker in code, low risk to defer
- **FEAT-35 telemetry**: rolled back due to file duplication issue
  - `static/vsp_uxstates.js` (gateway route, used by index.html)
  - `static/js/vsp_uxstates.js` (panel route, used by 10 panels)
  - Two physical copies need architectural fix before telemetry ships
  - Trail visible in commits c500acd → 1aca17d → 8527292 → c06fdec

## Pending verification
- Browser verify FEAT-29 → FEAT-34 (10 panels, ~50 min)
- All FEAT commits passed sanity dial but no manual browser smoke test yet

## Next sprint candidates
- **FEAT-35.5**: address vsp_uxstates.js duplication (symlink, gateway redirect, or refactor)
- **FEAT-35 redo**: after 35.5, retry telemetry with single source of truth
- **FEAT-40**: last-updated indicator (depends on FEAT-35 telemetry)
- See SCOPE_D_TO_I.md for full Phase 2 plan

## Lessons learned
- Multi-script HTML files: use Python parser, not sed for JS extraction
- Patches touching files in multiple paths: grep all references first
- Pattern matching idempotency: marker must be unique to code body, not docs
- File duplication in static/ is architectural smell — fix before piling on patches
