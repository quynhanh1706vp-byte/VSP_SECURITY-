# FEAT-07 — Threat Hunt Panel UX States via VSPUXState (Sprint 5.3)

## What
Third panel using FEAT-04 shared VSPUXState module.

This sprint differs from FEAT-05/06: threat_hunt.html had NO mock data to remove.
SAVED_QUERIES (6 saved hunt patterns: SSH brute force, Sudo commands, etc.) is
legitimate config and is kept as-is.

This sprint upgrades existing loading/empty/error states for consistency:
- Plain "<div class='loading'>⏳ Querying log_events...</div>" -> VSPUXState.skeleton
- Implicit empty (rendered empty table) -> explicit VSPUXState.empty with retry
- Plain "<div class='empty'>Error: ...</div>" -> VSPUXState.error with retry

## Why
After FEAT-05/06, three panels (Users, UEBA, Threat Hunt) use VSPUXState.
Consistent UX across the platform — same shimmer animation, same retry pattern,
same icons (∅ for empty, ⚠ for error).

## Defensive design
All VSPUXState calls guarded with `typeof !== 'undefined'`, with fallback to
original plain DOM updates if module fails to load.

## Backend endpoint (already wired before this patch)
- /api/v1/logs/hunt — full-text + filter search across log_events table

## Apply
bash patches/feat/07-threat-hunt-uxstates/apply.sh

## Verify
Browser console at https://vsp.local:
  fetch('/panels/threat_hunt.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-07 PATCH APPLIED'),
    hasUX: t.includes('VSPUXState.skeleton'),
    hasEmpty: t.includes('VSPUXState.empty'),
    hasError: t.includes('VSPUXState.error'),
    queriesKept: t.includes('SSH brute force')
  }))
Expected: marker + hasUX + hasEmpty + hasError + queriesKept = all true.

Visual: open Threat Hunt, click any saved query button -> skeleton during fetch ->
results render or "No events match these filters" + Retry button.

## Rollback
bash patches/feat/07-threat-hunt-uxstates/rollback.sh

## Verified state (dry-run + apply)
- File: 1205 -> 1213 lines (+8: 3 conditional branches with fallbacks)
- 3 patch steps reported success
- VSPUXState calls: skeleton=1, empty=1, error=1
- typeof guards: 3 (one per state)
- SAVED_QUERIES preserved (intentional config)
