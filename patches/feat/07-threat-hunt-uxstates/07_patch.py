#!/usr/bin/env python3
"""
FEAT-07 (Sprint 5.3): Apply VSPUXState to Threat Hunt panel.

Note: threat_hunt.html has NO mock data (SAVED_QUERIES is legitimate config —
6 saved hunt query patterns, kept as-is). This sprint upgrades the existing
loading/empty/error states to use VSPUXState for consistency with FEAT-05/06.

Changes:
- Replace plain "<div class='loading'>⏳ Querying...</div>" with VSPUXState.skeleton
- Add explicit empty state when _results.length === 0
- Replace plain error div with VSPUXState.error + retry button
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/threat_hunt.html")
BACKUP = pathlib.Path("static/panels/threat_hunt.html.bak.feat07")
MARKER = "/* FEAT-07 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-07 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Replace loading state ─────────────────────────────────────
old_loading = '''  document.getElementById('results-wrap').innerHTML='<div class="loading">&#9203; Querying log_events...</div>';'''
new_loading = '''  if(typeof VSPUXState!=='undefined'){VSPUXState.skeleton('#results-wrap',{rows:5,kind:'card'});}
  else{document.getElementById('results-wrap').innerHTML='<div class="loading">&#9203; Querying log_events...</div>';}'''
if old_loading not in src:
    print("FAIL: loading state line not found"); sys.exit(1)
src = src.replace(old_loading, new_loading, 1)
print("Replaced loading state with VSPUXState.skeleton")

# ─── 2. Add empty state after fetch (when _results.length === 0) ──
# Anchor: line where we set k-results and before renderResults(q)
old_render_block = '''    document.getElementById('hunt-status').textContent=_results.length+' results';
    document.getElementById('hunt-status').className='pill pill-'+(d.total>0?'blue':'gray');

    renderResults(q);'''
new_render_block = '''    document.getElementById('hunt-status').textContent=_results.length+' results';
    document.getElementById('hunt-status').className='pill pill-'+(d.total>0?'blue':'gray');

    if(_results.length===0){
      if(typeof VSPUXState!=='undefined'){VSPUXState.empty('#results-wrap','No events match these filters',runHunt);}
      else{document.getElementById('results-wrap').innerHTML='<div class="empty">No results</div>';}
    } else {
      renderResults(q);
    }'''
if old_render_block not in src:
    print("FAIL: render block not found"); sys.exit(1)
src = src.replace(old_render_block, new_render_block, 1)
print("Added empty state after fetch")

# ─── 3. Replace error state ───────────────────────────────────────
old_error = '''  }catch(e){
    document.getElementById('results-wrap').innerHTML='<div class="empty">Error: '+e.message+'</div>';
    document.getElementById('hunt-status').textContent='Error';
    document.getElementById('hunt-status').className='pill pill-red';
  }'''
new_error = '''  }catch(e){
    if(typeof VSPUXState!=='undefined'){VSPUXState.error('#results-wrap','Hunt failed: '+e.message,runHunt);}
    else{document.getElementById('results-wrap').innerHTML='<div class="empty">Error: '+e.message+'</div>';}
    document.getElementById('hunt-status').textContent='Error';
    document.getElementById('hunt-status').className='pill pill-red';
  }'''
if old_error not in src:
    print("FAIL: error catch block not found"); sys.exit(1)
src = src.replace(old_error, new_error, 1)
print("Replaced error state with VSPUXState.error + retry")

# ─── 4. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
