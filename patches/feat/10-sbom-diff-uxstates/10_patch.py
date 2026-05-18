#!/usr/bin/env python3
"""
FEAT-11 (Sprint 7): Apply VSPUXState to SBOM Diff panel — Phase B continued.

No mock data to remove (var RUNS=[] already empty). UX upgrade only:
- runDiff() entry: skeleton on 3 tables (#tbl-new, #tbl-fixed, #tbl-persisted)
- runDiff() per-section: VSPUXState.empty if length===0
- runDiff() catch: VSPUXState.error + retry callback (was alert)

loadRuns() unchanged — populates <select> dropdowns, no UX state needed.
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/sbom_diff.html")
BACKUP = pathlib.Path("static/panels/sbom_diff.html.bak.feat10")
MARKER = "/* FEAT-11 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-11 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Inject skeleton at runDiff entry ─────────────────────────
old_entry = '''async function runDiff(){
  var rid1=document.getElementById('rid1').value;
  var rid2=document.getElementById('rid2').value;
  if(!rid1||!rid2){alert('Select two runs');return;}
  if(rid1===rid2){alert('Select different runs');return;}
  var btn=document.getElementById('diff-btn');
  btn.textContent='Loading…';btn.disabled=true;'''
new_entry = '''async function runDiff(){
  var rid1=document.getElementById('rid1').value;
  var rid2=document.getElementById('rid2').value;
  if(!rid1||!rid2){alert('Select two runs');return;}
  if(rid1===rid2){alert('Select different runs');return;}
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX){
    VSPUXState.skeleton('#tbl-new', {rows: 3});
    VSPUXState.skeleton('#tbl-fixed', {rows: 3});
    VSPUXState.skeleton('#tbl-persisted', {rows: 3});
  }
  var btn=document.getElementById('diff-btn');
  btn.textContent='Loading…';btn.disabled=true;'''
if old_entry not in src:
    print("FAIL: runDiff entry not found"); sys.exit(1)
src = src.replace(old_entry, new_entry, 1)
print("Injected skeleton at runDiff entry")

# ─── 2. Replace per-section render with empty-aware version ──────
old_render = '''    // Tables
    renderRows(newItems,'tbl-new');
    renderRows(fixedItems,'tbl-fixed');
    renderRows(persistedItems,'tbl-persisted');'''
new_render = '''    // Tables — use VSPUXState.empty if section empty
    if(newItems.length===0 && hasUX) VSPUXState.empty('#tbl-new', 'No new findings', runDiff);
    else renderRows(newItems,'tbl-new');
    if(fixedItems.length===0 && hasUX) VSPUXState.empty('#tbl-fixed', 'No findings fixed', runDiff);
    else renderRows(fixedItems,'tbl-fixed');
    if(persistedItems.length===0 && hasUX) VSPUXState.empty('#tbl-persisted', 'No persistent findings', runDiff);
    else renderRows(persistedItems,'tbl-persisted');'''
if old_render not in src:
    print("FAIL: render block not found"); sys.exit(1)
src = src.replace(old_render, new_render, 1)
print("Added empty states per section")

# ─── 3. Replace catch alert with VSPUXState.error + retry ────────
old_catch = '''  }catch(e){
    alert('Diff failed: '+e.message);
  }finally{
    btn.textContent='Compare ↗';btn.disabled=false;
  }'''
new_catch = '''  }catch(e){
    if(hasUX){
      VSPUXState.error('#tbl-new', 'Diff failed: '+e.message, runDiff);
      VSPUXState.error('#tbl-fixed', 'Diff failed: '+e.message, runDiff);
      VSPUXState.error('#tbl-persisted', 'Diff failed: '+e.message, runDiff);
    } else {
      alert('Diff failed: '+e.message);
    }
  }finally{
    btn.textContent='Compare ↗';btn.disabled=false;
  }'''
if old_catch not in src:
    print("FAIL: catch block not found"); sys.exit(1)
src = src.replace(old_catch, new_catch, 1)
print("Replaced catch alert with VSPUXState.error + retry")

# ─── 4. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
