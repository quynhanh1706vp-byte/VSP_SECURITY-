#!/usr/bin/env python3
"""
FEAT-14 (Sprint 10): Apply VSPUXState to SOAR panel.

No mock data to strip — PLAYBOOKS=[] and RUN_HISTORY=[] already empty (line 762).
DEF_PB and DEF_RUNS are legitimate DEFAULT fallback config (same pattern
as DEFAULT_ROLES, MITRE, CHECKS, STATIC_EOL).

UX upgrade: wires VSPUXState into loadRunHistory + renderList entry.
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/soar.html")
BACKUP = pathlib.Path("static/panels/soar.html.bak.feat13")
MARKER = "/* FEAT-14 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-14 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Inject skeleton in loadRunHistory() ──────────────────────
old_load_re = re.compile(r"function loadRunHistory\(\)\s*\{")
m = old_load_re.search(src)
if not m:
    print("FAIL: loadRunHistory not found"); sys.exit(1)

inject_point = m.end()
inject_code = """
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX){
    var el = document.querySelector('#runs-list') || document.querySelector('#run-history');
    if(el) VSPUXState.skeleton(el, {rows: 4, kind: 'card'});
  }"""
src = src[:inject_point] + inject_code + src[inject_point:]
print("Injected skeleton in loadRunHistory")

# ─── 2. Inject skeleton in renderList() entry (defensive) ─────────
old_renderlist_re = re.compile(r"function renderList\(\)\s*\{")
m = old_renderlist_re.search(src)
if not m:
    print("FAIL: renderList not found"); sys.exit(1)

inject_point = m.end()
inject_code = """
  /* FEAT-14: empty state if PLAYBOOKS empty */
  if(typeof VSPUXState !== 'undefined' && (!PLAYBOOKS || PLAYBOOKS.length===0)){
    var el = document.querySelector('#pb-list');
    if(el){
      VSPUXState.empty('#pb-list', 'No playbooks configured', function(){location.reload();});
      return;
    }
  }"""
src = src[:inject_point] + inject_code + src[inject_point:]
print("Injected empty state in renderList")

# ─── 3. Marker ───────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
