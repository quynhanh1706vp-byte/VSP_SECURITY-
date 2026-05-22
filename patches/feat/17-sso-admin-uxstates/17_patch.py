#!/usr/bin/env python3
"""
FEAT-18 (Sprint 14): Apply VSPUXState to SSO Admin panel.

No mock. UX upgrade — wires VSPUXState into loadProviders().
Target: #providers-body
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/sso_admin.html")
BACKUP = pathlib.Path("static/panels/sso_admin.html.bak.feat17")
MARKER = "/* FEAT-18 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-18 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Inject skeleton at loadProviders entry ───────────────────
old_entry = "async function loadProviders() {"
new_entry = '''async function loadProviders() {
  if(typeof VSPUXState !== 'undefined') VSPUXState.skeleton('#providers-body', {rows: 4});'''
if old_entry not in src:
    print("FAIL: loadProviders entry not found"); sys.exit(1)
src = src.replace(old_entry, new_entry, 1)
print("Injected skeleton at loadProviders entry")

# ─── 2. Upgrade empty inline ─────────────────────────────────────
old_empty = """tbody.innerHTML = '<tr><td colspan="6" class="empty">No SSO providers configured. Click "+ Add Provider" to create one.</td></tr>';"""
new_empty = """if(typeof VSPUXState !== 'undefined'){VSPUXState.empty('#providers-body','No SSO providers — click + Add Provider to create one',loadProviders);}else{tbody.innerHTML = '<tr><td colspan="6" class="empty">No SSO providers.</td></tr>';}"""
if old_empty not in src:
    print("FAIL: empty inline not found"); sys.exit(1)
src = src.replace(old_empty, new_empty, 1)
print("Upgraded empty state")

# ─── 3. Upgrade error catch ───────────────────────────────────────
old_err = """tbody.innerHTML = `<tr><td colspan="6" class="empty">Error: ${escapeHtml(e.message)}</td></tr>`;"""
new_err = """if(typeof VSPUXState !== 'undefined'){VSPUXState.error('#providers-body', 'Error: '+e.message, loadProviders);}else{tbody.innerHTML = `<tr><td colspan="6" class="empty">Error: ${escapeHtml(e.message)}</td></tr>`;}"""
if old_err not in src:
    print("FAIL: error catch not found"); sys.exit(1)
src = src.replace(old_err, new_err, 1)
print("Upgraded error catch")

# ─── 4. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
