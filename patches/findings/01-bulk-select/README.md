# Patch F1 v2 — Bulk Select & Bulk Actions Toolbar

**Tab:** Findings (`static/panels/vuln_mgmt.html`)
**Sprint:** 1, Patch 1/8
**Strategy:** **C+ (additive standalone JS)** — zero modification of core scripts
**Backend changes:** YES — adds `POST /api/v1/vulns/bulk[/undo]` to `cmd/dev-stub/main.go`
**Risk:** very low — purely additive; rollback = delete 1 file + 1 HTML block

---

## What changed vs v1

v1 patched the inline core script + HTML in `vuln_mgmt.html`. After analyzing the
full file (1857 lines containing 3 inline runtime patches: VSP-E5, VSP-UNI-POLISH,
VSP-CROSS-LINK-V3), v1 would have caused colspan/render conflicts.

v2 instead:

1. **Drops a standalone IIFE** at `static/js/vsp_bulk_f1.js` (~450 LoC)
2. **Adds one `<script>` tag** before `</body>` in `static/panels/vuln_mgmt.html`
3. The IIFE follows the **exact same pattern** as Block 1/2/3 already in the file:
   - Double-init guard (`window.__VSP_BULK_F1__`)
   - Hooks `window.filterCVEs` after Block 1 has installed its hook
   - Polling re-init for late renders
   - Defers DOM mutation past Block 1's own `setTimeout(50)`

Result: zero conflict, full rollback by removing one file + one block.

---

## What this patch adds

### Frontend

- Checkbox column **prepended** to Top CVEs table (auto-adapts to Block 1's added EPSS/KEV columns; colspan auto-bumps for empty/loading rows)
- Header select-all (only filtered/visible rows)
- Floating action bar at bottom (slides up when selection > 0):
  - **✓ Resolve** · **⊘ Suppress** · **👤 Assign ▾** · **📋 POA&M** · **✕ Clear**
- Optimistic UI: resolved/suppressed rows fade out immediately, restore on error
- 8s **undo banner** with progress bar, **Ctrl+Z** shortcut
- **Esc** clears selection
- Reuses Block 2's toast (`window._vspUNI.toast`) when available, falls back gracefully
- Reuses Block 2's modal pattern for assign-owner picker

### Backend (`cmd/dev-stub/main.go`)

Same as v1:
- `POST /api/v1/vulns/bulk` — accept `{action, cve_ids, metadata}`, return `{ok, affected, action_id, undo_token}`
- `POST /api/v1/vulns/bulk/undo` — accept `{undo_token}`, return `{ok, reverted}`
- 60s in-memory undo token store with GC goroutine
- **TODO comments for DB wiring** in next sprint

---

## Files in this patch

```
01-bulk-select/
├── README.md          ← you are here
├── apply.sh           ← idempotent applier
├── rollback.sh        ← reverses HTML + removes JS
├── frontend.py        ← copies JS into static/js/, injects <script> tag
├── vsp_bulk_f1.js     ← THE actual feature (standalone IIFE, ~450 LoC)
└── backend.go.snippet ← copy-paste handler block for dev-stub
```

---

## Apply

```bash
cd /home/test/Data/GOLANG_VSP
bash patches/findings/01-bulk-select/apply.sh
```

Then follow the manual backend step printed by the script.

After backend is in place + service restarted, test in browser, then commit.

---

## Manual test plan

Open the Findings panel and verify:

| # | Action | Expected |
|---|---|---|
| 1 | Page loads | KPI row + table render. Block 1 (EPSS/KEV) still works. After ~1s, checkbox column appears at left of table. |
| 2 | Click 1 row checkbox | Action bar slides up, "1 selected" |
| 3 | Click header checkbox | All visible rows select; if you filtered by CRITICAL, only those |
| 4 | Click Resolve | Toast "Resolved N CVEs", undo banner appears (8s progress bar), rows fade out |
| 5 | Click Undo (or Ctrl+Z) | Rows restore, toast "Undone" |
| 6 | Wait 8s without undo | Banner disappears |
| 7 | Backend down → click action | Toast error "Bulk action failed"; selection preserved |
| 8 | Click cell text (CVE id, severity) | CVE detail modal opens (existing behavior, NOT broken) |
| 9 | Click checkbox | Modal does NOT open (event.stopPropagation works) |
| 10 | Esc with selection | Selection clears |
| 11 | Block 1 still works | EPSS/KEV cells appear on each row alongside checkbox |
| 12 | Block 3 still works | 🌐 TI badge appears on cells with CVE pattern |

---

## Rollback

```bash
bash patches/findings/01-bulk-select/rollback.sh
```

Restores HTML from `.bak.f1`, deletes `static/js/vsp_bulk_f1.js`, prints
instructions to revert backend changes manually.

---

## Why standalone over inline patch

1. **Zero core modification** — `vuln_mgmt.html` semantic stays untouched
2. **Pattern parity** — repo already has `vsp_iframe_bootstrap.js`, `vsp_fe_sync_patch_v2.js` etc.
3. **Future F2-F8** can follow same pattern: `vsp_filter_f2.js`, `vsp_cvss_sort_f3.js` etc.
4. **Per-feature toggle** — comment one `<script src>` line to disable any feature without re-patching HTML
5. **Clean diff** — git shows 1 new file + 4 lines added to HTML
