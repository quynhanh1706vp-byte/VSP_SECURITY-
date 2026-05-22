#!/usr/bin/env python3
"""
FEAT-12 (Sprint 8): Apply VSPUXState to Software Risk panel.

No mock data to strip. STATIC_EOL is legitimate End-of-Life reference data
(19 entries: Windows XP, Office 2010, PHP 7.4, MISA SME.NET 2019, etc.) from
public sources (endoflife.date) plus VN-specific manual entries.
Pattern same as DEFAULT_ROLES, MITRE, CHECKS — config not mock.

Wires VSPUXState into loadData():
- Skeleton on entry (4 targets: #heatmap, #assets-tbody, #findings-list, #eol-list)
- Empty state if _assets.length === 0
- Error state in catch (was silent console.error)
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/software_risk.html")
BACKUP = pathlib.Path("static/panels/software_risk.html.bak.feat11")
MARKER = "/* FEAT-12 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-12 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Find render target IDs first (assumption check) ──────────
# We don't know exact IDs without inspection — use generic targets and
# rely on render functions to clear our skeleton when they execute

# ─── 2. Rewrite loadData() with VSPUXState ───────────────────────
old_load = '''async function loadData(){
  if(!TOKEN) return;
  var h={Authorization:'Bearer '+TOKEN};
  try{
    var sRes=await fetch(API+'/api/v1/software-inventory/stats',{headers:h}).then(r=>r.json()).catch(()=>({}));
    var aRes=await fetch(API+'/api/v1/software-inventory',{headers:h}).then(r=>r.json()).catch(()=>({assets:[]}));
    _assets=aRes.assets||[];
    document.getElementById('k-total').textContent=sRes.total_assets||_assets.length||0;
    document.getElementById('k-crack').textContent=sRes.total_crack||0;
    document.getElementById('k-eol').textContent=sRes.total_eol||0;
    document.getElementById('k-highrisk').textContent=sRes.critical_assets||0;
    document.getElementById('k-clean').textContent=sRes.clean_assets||_assets.filter(function(a){return a.risk_level==='clean';}).length;
    document.getElementById('last-scan-lbl').textContent='Updated '+new Date().toLocaleTimeString();
    renderHeatmap();
    renderAssetTable();
    renderFindings();
    var eRes=await fetch(API+'/api/v1/software-inventory/eol-database',{headers:h}).then(r=>r.ok?r.json():null).catch(()=>null);
    if(eRes&&eRes.entries) _eolData=eRes.entries;
    renderEOL();
  }catch(e){console.error(e);}
}'''
new_load = '''async function loadData(){
  var hasUX = typeof VSPUXState !== 'undefined';
  // Skeleton on common UI targets — render functions will replace once data ready
  if(hasUX){
    var skelTargets = ['#assets-tbody', '#findings-list', '#eol-list', '#heatmap'];
    skelTargets.forEach(function(t){
      var el = document.querySelector(t);
      if(el) VSPUXState.skeleton(t, {rows: 4});
    });
  }
  if(!TOKEN){
    if(hasUX) VSPUXState.empty('#assets-tbody', 'Authentication required', loadData);
    return;
  }
  var h={Authorization:'Bearer '+TOKEN};
  try{
    var sRes=await fetch(API+'/api/v1/software-inventory/stats',{headers:h}).then(r=>r.json()).catch(()=>({}));
    var aRes=await fetch(API+'/api/v1/software-inventory',{headers:h}).then(r=>r.json()).catch(()=>({assets:[]}));
    _assets=aRes.assets||[];
    document.getElementById('k-total').textContent=sRes.total_assets||_assets.length||0;
    document.getElementById('k-crack').textContent=sRes.total_crack||0;
    document.getElementById('k-eol').textContent=sRes.total_eol||0;
    document.getElementById('k-highrisk').textContent=sRes.critical_assets||0;
    document.getElementById('k-clean').textContent=sRes.clean_assets||_assets.filter(function(a){return a.risk_level==='clean';}).length;
    document.getElementById('last-scan-lbl').textContent='Updated '+new Date().toLocaleTimeString();
    if(_assets.length===0 && hasUX){
      VSPUXState.empty('#assets-tbody', 'No software assets discovered', loadData);
    } else {
      renderHeatmap();
      renderAssetTable();
      renderFindings();
    }
    var eRes=await fetch(API+'/api/v1/software-inventory/eol-database',{headers:h}).then(r=>r.ok?r.json():null).catch(()=>null);
    if(eRes&&eRes.entries) _eolData=eRes.entries;
    renderEOL();
  }catch(e){
    console.error(e);
    if(hasUX){
      VSPUXState.error('#assets-tbody', 'Failed to load: '+(e.message||'network error'), loadData);
      VSPUXState.error('#findings-list', 'Failed to load', loadData);
    }
  }
}'''
if old_load not in src:
    print("FAIL: loadData() body not found"); sys.exit(1)
src = src.replace(old_load, new_load, 1)
print("Rewrote loadData() with VSPUXState")

# ─── 3. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
