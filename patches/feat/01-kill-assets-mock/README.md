# FEAT-01 — Kill Mock Data in Assets Panel

## What
Removes hardcoded var ASSETS=[...] (12 fake assets) and var ALL_FINDINGS=[...]
(8 fake findings) from static/panels/assets.html. Replaces with empty arrays.

## Why
Mock data was rendered IMMEDIATELY on panel load before any API call, then
replaced if API succeeded. Users saw "API Gateway / Auth service / PostgreSQL DB"
fake names for ~1s before real data, or permanently if API failed silently.

## How
- Empty arrays only, no fallback to mock
- Rewrote loadAssets() with skeleton + empty + error states
- Removed initial updateKPIs/renderHeatmap/renderAssets call
- Now waits for token, paints skeleton, fetches, renders real data
- Injected CSS keyframe shimmer animation for skeleton rows

## Apply
bash patches/feat/01-kill-assets-mock/apply.sh

## Verify
Open https://vsp.local in browser, F12 console, run:
fetch('/panels/assets.html').then(r=>r.text()).then(t=>console.log({
  marker: t.includes('FEAT-01 PATCH APPLIED'),
  mockGone: !t.includes("name:'API Gateway'"),
  skeleton: t.includes('skel-shimmer')
}))

All three should print true.

## Rollback
bash patches/feat/01-kill-assets-mock/rollback.sh

## Verified state
- File: 60596 bytes -> 56256 bytes (-4.3 KB)
- Marker present, mock removed, skeleton CSS injected — all true
- No console errors after applied
