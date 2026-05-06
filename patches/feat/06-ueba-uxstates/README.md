# FEAT-06 — UEBA Panel UX States via VSPUXState (Sprint 5.2)

## What
Second panel using FEAT-04 shared VSPUXState module (after FEAT-05 Users).

Removes:
- var SAMPLE=[3 fake anomalies] (score_spike, gate_fail_streak, sla_breach)
- var SCORE_HIST=[14 fake score history numbers]
- var BL_SCORE=72 (fake baseline score)

Removes mock fallback:
- "if(!ANOMALIES.length)ANOMALIES=SAMPLE.slice()" line 363

Adds:
- loadBaseline() rewritten with VSPUXState.skeleton/empty/error + retry callback
- New loadAnomalies() fetching /api/v1/ueba/analyze
- Skeleton state on #score-bars during load
- Real data populates SCORE_HIST + BL_SCORE from baseline.history + avg_score

Preserved (intentional, config-like):
- var CHECKS=[6 detection rules] — same pattern as DEFAULT_ROLES in FEAT-05

## Why
Same pattern as FEAT-05: panel had hardcoded mock displayed immediately on load,
falling back to mock when API empty. Real flow: fetch /baseline -> apply data ->
fetch /analyze -> render anomalies.

## Defensive design
All VSPUXState calls guarded with `typeof VSPUXState !== 'undefined'`.
Panel works (degraded — no skeleton/empty/error visual) if module fails to load.

## Backend endpoints
- /api/v1/ueba/baseline   — wired (already existed)
- /api/v1/ueba/analyze    — wired (was in endpoint list, now actually called)

## Apply
bash patches/feat/06-ueba-uxstates/apply.sh

## Verify
Browser console at https://vsp.local:

  fetch('/panels/ueba.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-06 PATCH APPLIED'),
    spikeMockGone: !t.includes('Security score dropped 50pts'),
    emptyArrays: t.match(/var (SAMPLE|SCORE_HIST)=\\[\\];|var BL_SCORE=null;/g)?.length || 0,
    hasUX: t.includes('VSPUXState.skeleton'),
    hasLoadAnomalies: t.includes('async function loadAnomalies')
  }))

Expected: marker true, spikeMockGone true, emptyArrays=3, hasUX true, hasLoadAnomalies true.

Visual: open UEBA panel → score bars skeleton during load → real data renders
or empty state. Anomalies list: skeleton -> real anomalies or "No anomalies detected".

## Rollback
bash patches/feat/06-ueba-uxstates/rollback.sh

## Verified state (dry-run)
- File: 941 -> 980 lines (+39: -20 mock, +59 loaders/helpers)
- 6 patch steps reported success
- 4 mock content strings gone
- 3 empty arrays/null
- CHECKS array preserved (intentional)
- 12 VSPUXState integration points
