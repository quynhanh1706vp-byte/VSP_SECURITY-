#!/usr/bin/env python3
"""
FEAT-19 (Sprint 15): Apply VSPUXState to SW Inventory panel — minimal scope.

Minimal scope decision:
- KILL silent fallback MOCK_INVENTORY in loadInventory() catch (anti-pattern,
  same as FEAT-01 Assets) — replace with VSPUXState.error + retry
- Add VSPUXState.skeleton at loadInventory() entry
- Add empty state if _invData.length === 0

NOT touched (out of Quick Win scope, requires backend wiring):
- MOCK_WHITELIST / MOCK_BLACKLIST / MOCK_WARNING — used as client-side state,
  mutated by removeFromList() (line 1057-1059)
- MOCK_CRACKS / MOCK_LICENSE / MOCK_SCAN_HISTORY — primary data sources,
  no backend fetch yet (endpoints exist: /api/v1/sw/* but not called)

These 6 require dedicated Sprint with backend wiring (Phase B+ scope).
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/sw_inventory.html")
BACKUP = pathlib.Path("static/panels/sw_inventory.html.bak.feat18")
MARKER = "/* FEAT-19 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-19 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Inject skeleton at loadInventory entry ───────────────────
old_entry = "async function loadInventory() {"
new_entry = '''async function loadInventory() {
  if(typeof VSPUXState !== 'undefined') VSPUXState.skeleton('#inv-tbody', {rows: 6});'''
if old_entry not in src:
    print("FAIL: loadInventory entry not found"); sys.exit(1)
src = src.replace(old_entry, new_entry, 1)
print("Injected skeleton at loadInventory entry")

# ─── 2. Kill silent fallback to MOCK_INVENTORY ───────────────────
old_catch = "} catch(e) { _invData = MOCK_INVENTORY; }"
new_catch = '''} catch(e) {
    if(typeof VSPUXState !== 'undefined'){
      VSPUXState.error('#inv-tbody', 'Failed to load inventory: '+(e.message||'network error'), loadInventory);
      _invData = []; // clear, do not silent fallback to mock
      return;
    }
    _invData = MOCK_INVENTORY; // fallback only when VSPUXState unavailable
  }'''
if old_catch not in src:
    print("FAIL: silent fallback not found"); sys.exit(1)
src = src.replace(old_catch, new_catch, 1)
print("Killed silent fallback to MOCK_INVENTORY")

# ─── 3. Add empty state in renderInventory if empty ─────────────
# renderInventory line 829 — find and inject empty check at start
old_render_re = re.compile(r"function renderInventory\(\)\s*\{")
m = old_render_re.search(src)
if not m:
    print("FAIL: renderInventory not found"); sys.exit(1)
inject_point = m.end()
inject_code = """
  if(typeof VSPUXState !== 'undefined' && (!_invData || _invData.length === 0)){
    VSPUXState.empty('#inv-tbody', 'No software inventory data', loadInventory);
    return;
  }"""
src = src[:inject_point] + inject_code + src[inject_point:]
print("Added empty state in renderInventory")

# ─── 4. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
