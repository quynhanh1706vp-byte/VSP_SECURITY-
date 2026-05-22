# FEAT-04 — Shared VSPUXState Module

## What
Creates window.VSPUXState — a shared JS module providing skeleton, empty, and
error UI states reusable across all panels.

Replaces inline helpers _vmShowSkel (FEAT-02) and _schSetState (FEAT-03)
with one unified API.

## Files

Created:
- static/vsp_uxstates.js (canonical, served at /vsp_uxstates.js)
- static/js/vsp_uxstates.js (mirror — repo convention keeps both in sync)

Modified:
- static/index.html (one new <script> tag injected after vsp_dast_panel.js)

## API

VSPUXState.skeleton(target, opts?)
  Paint shimmer rows. opts: { rows: 5, height: 18, kind: "table"|"list"|"card" }
  kind is auto-detected from target (tbody/ul/ol/div).

VSPUXState.empty(target, msg, retryFn?)
  Paint empty state with ∅ icon. retryFn (optional) renders a Retry button.

VSPUXState.error(target, msg, retryFn?)
  Paint error state with ⚠ icon and Retry button if retryFn provided.

VSPUXState.clear(target)
  Remove any state (innerHTML="").

target accepts: HTMLElement, "#id", or ".class" CSS selector.

## Usage example

async function loadAssets() {
  VSPUXState.skeleton("#asset-tbody");
  try {
    const r = await fetch("/api/v1/assets");
    if (!r.ok) return VSPUXState.error("#asset-tbody", `HTTP ${r.status}`, loadAssets);
    const d = await r.json();
    if (!d.assets?.length) return VSPUXState.empty("#asset-tbody", "No assets", loadAssets);
    renderAssets(d.assets);
  } catch (e) {
    VSPUXState.error("#asset-tbody", "Network error", loadAssets);
  }
}

## Apply
bash patches/feat/04-uxstates-module/apply.sh

## Verify
Browser console at https://vsp.local:
  console.log(typeof VSPUXState, Object.keys(VSPUXState));
Expected: "object" ["skeleton","empty","error","clear","VERSION"]

Smoke visual test (3-second sequence — skeleton -> empty -> error):
  var d = document.createElement("div");
  d.id = "smoke";
  document.body.appendChild(d);
  VSPUXState.skeleton("#smoke", {rows: 3});
  setTimeout(() => VSPUXState.empty("#smoke", "No data"), 1500);
  setTimeout(() => VSPUXState.error("#smoke", "HTTP 500", () => alert("retried")), 3000);

## Rollback
bash patches/feat/04-uxstates-module/rollback.sh

## Migration plan (NOT done in this patch)

Existing inline helpers in 3 panels are intentionally left in place:
- assets.html (FEAT-01: skel-row + skel-shimmer CSS, inline strings)
- vuln_mgmt.html (FEAT-02: _vmShowSkel/_vmShowEmpty/_vmShowError)
- scheduler.html (FEAT-03: _schSetState)

They work correctly. Do NOT migrate retroactively until VSPUXState has been
proven across 5+ new panels. Migrating early adds regression risk for zero
user benefit.

Future panels (Sprint 3+) should use VSPUXState directly.

## Verified state (dry-run + apply)
- 2 JS files created, identical md5
- node --check: PARSE OK
- index.html line count: +2 (marker + script tag)
- Browser smoke test: skeleton/empty/error all render correctly
