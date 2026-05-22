#!/usr/bin/env python3
"""
FEAT-15 (Sprint 11): Apply VSPUXState to Attestation panel.

No mock data. UX upgrade only — wires VSPUXState into 2 loaders:
- loadDraft() target #draft-body: skeleton entry + error in catch (was alert)
- loadForms() target #forms-tbody: skeleton entry + empty state + error in catch
  (was inline plain HTML for empty, silent console.error)

Sign + download functions unchanged (action handlers, not data loaders).
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/attestation.html")
BACKUP = pathlib.Path("static/panels/attestation.html.bak.feat14")
MARKER = "/* FEAT-15 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-15 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Inject skeleton at loadDraft entry ───────────────────────
old_draft_entry = '''async function loadDraft() {
  try {
    const res = await fetch(\'/api/p4/attestation/generate\');'''
new_draft_entry = '''async function loadDraft() {
  const hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX) VSPUXState.skeleton('#draft-body', {rows: 6, kind: 'card'});
  try {
    const res = await fetch('/api/p4/attestation/generate');'''
if old_draft_entry not in src:
    print("FAIL: loadDraft entry not found"); sys.exit(1)
src = src.replace(old_draft_entry, new_draft_entry, 1)
print("Injected skeleton at loadDraft entry")

# ─── 2. Replace loadDraft catch alert with VSPUXState.error ──────
old_draft_catch = "} catch(e) { alert('Generate error: ' + e.message); }"
new_draft_catch = '''} catch(e) {
    if(typeof VSPUXState !== 'undefined'){
      VSPUXState.error('#draft-body', 'Generate error: '+e.message, loadDraft);
    } else {
      alert('Generate error: ' + e.message);
    }
  }'''
if old_draft_catch not in src:
    print("FAIL: loadDraft catch not found"); sys.exit(1)
src = src.replace(old_draft_catch, new_draft_catch, 1)
print("Replaced loadDraft catch")

# ─── 3. Inject skeleton at loadForms entry ───────────────────────
old_forms_entry = '''async function loadForms() {
  try {
    const res = await fetch(\'/api/p4/attestation/list\');'''
new_forms_entry = '''async function loadForms() {
  const hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX) VSPUXState.skeleton('#forms-tbody', {rows: 4});
  try {
    const res = await fetch('/api/p4/attestation/list');'''
if old_forms_entry not in src:
    print("FAIL: loadForms entry not found"); sys.exit(1)
src = src.replace(old_forms_entry, new_forms_entry, 1)
print("Injected skeleton at loadForms entry")

# ─── 4. Upgrade loadForms empty state ────────────────────────────
old_forms_empty = '''    if (!d.forms || d.forms.length === 0) {
      tbody.innerHTML = \'<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:20px">No forms yet — generate first draft</td></tr>\';
      return;
    }'''
new_forms_empty = '''    if (!d.forms || d.forms.length === 0) {
      if(hasUX){
        VSPUXState.empty('#forms-tbody', 'No forms yet — generate first draft', loadForms);
      } else {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:20px">No forms yet — generate first draft</td></tr>';
      }
      return;
    }'''
if old_forms_empty not in src:
    print("FAIL: loadForms empty block not found"); sys.exit(1)
src = src.replace(old_forms_empty, new_forms_empty, 1)
print("Upgraded loadForms empty state")

# ─── 5. Replace loadForms silent catch with VSPUXState.error ─────
old_forms_catch = "} catch(e) { console.error(e); }"
new_forms_catch = '''} catch(e) {
    console.error(e);
    if(typeof VSPUXState !== 'undefined'){
      VSPUXState.error('#forms-tbody', 'Failed to load forms: '+(e.message||'network error'), loadForms);
    }
  }'''
if old_forms_catch not in src:
    print("FAIL: loadForms catch not found"); sys.exit(1)
src = src.replace(old_forms_catch, new_forms_catch, 1)
print("Replaced loadForms catch")

# ─── 6. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
