# FEAT-03 — Kill Mock Data in Scheduler Panel

## What
Removes 2 hardcoded mock arrays from static/panels/scheduler.html:
- SAMPLE_SCHEDS (5 fake schedules: Daily production scan, IAC infrastructure, Weekly deep, etc.)
- SAMPLE_RUNS (6 fake runs with RID_SCHED_20260402_* IDs)

Also removes the 2-line "init from mock" block (SCHEDULES = SAMPLE_SCHEDS.slice()
and RECENT_RUNS = SAMPLE_RUNS.slice()) that copied mock into globals on load.

## Why
Pattern same as FEAT-01/02:
- Mock copied to global state immediately on script load (line 308-309)
- loadSchedules() / loadRecentRuns() silently fell back to mock on auth/network failure
- Users saw fake "Daily production scan" entries even when backend had no schedules

## How
- Both arrays replaced with empty literals
- The 2-line init from mock removed entirely (globals already declared empty at line 279)
- loadSchedules() rewritten: skeleton state on entry, proper empty/error states
- loadRecentRuns() rewritten same pattern
- New _schSetState(which, kind, msg) helper handles all 3 states
- CSS keyframe sch-shimmer for skeleton rows

## Backend endpoints used (already wired before patch)
- /api/v1/schedules         → schedule list
- /api/v1/vsp/runs?limit=20 → recent runs

## Apply
bash patches/feat/03-kill-scheduler-mock/apply.sh

## Verify
Browser console at https://vsp.local:

  fetch('/panels/scheduler.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-03 PATCH APPLIED'),
    schedMockGone: !t.includes("id:'sc1',name:'Daily production scan'"),
    runsMockGone: !t.includes('RID_SCHED_20260402_020013'),
    emptyArrays: t.match(/var SAMPLE_(SCHEDS|RUNS) = \[\];/g)?.length || 0,
    helpersInjected: t.includes('FEAT-03 helpers')
  }))

Expected: marker true, both mocks gone, emptyArrays=2, helpers true.

Note: "Daily production scan" still appears as a placeholder hint in the
"Create schedule" form input (UI helper text, not data). This is intentional.

## Rollback
bash patches/feat/03-kill-scheduler-mock/rollback.sh

## Verified state (dry-run)
- File: 1344 → 1355 lines (helpers slightly larger than mock removed)
- All 8 patch steps reported success
- Mock RID_SCHED_2026* count: 0
- Empty arrays: 2
- _schSetState references: 10 (1 def + 9 calls/strings)
