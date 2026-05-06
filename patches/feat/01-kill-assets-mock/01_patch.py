#!/usr/bin/env python3
"""
FEAT-01: Kill hardcoded mock data in static/panels/assets.html.
Replaces ASSETS / ALL_FINDINGS literal arrays with empty arrays,
rewrites loadAssets() with proper skeleton + empty + error states,
removes the mock initial render so user never sees fake data.
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/assets.html")
BACKUP = pathlib.Path("static/panels/assets.html.bak.feat01")
MARKER = "/* FEAT-01 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-01 already applied")
    sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Replace ASSETS=[...] block with empty array ──────────────
m = re.search(r"^var ASSETS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: ASSETS literal not found"); sys.exit(1)
src = src[:m.start()] + "var ASSETS=[];" + src[m.end():]
print("Stripped ASSETS literal")

# ─── 2. Replace ALL_FINDINGS=[...] block with empty array ────────
m = re.search(r"^var ALL_FINDINGS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: ALL_FINDINGS literal not found"); sys.exit(1)
src = src[:m.start()] + "var ALL_FINDINGS=[];" + src[m.end():]
print("Stripped ALL_FINDINGS literal")

# ─── 3. Rewrite loadAssets() with proper UX states ───────────────
NEW_LOAD = '''async function loadAssets(){
  var tbody=document.getElementById('asset-tbody');
  var setSkel=function(){if(tbody)tbody.innerHTML='<tr class="skel-row"><td colspan="6"><div class="skel"></div></td></tr>'.repeat(5);};
  var setEmpty=function(msg){if(tbody)tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--t3)"><div style="font-size:32px;margin-bottom:8px">∅</div>'+(msg||'No assets found')+'<div style="margin-top:12px"><button class="btn btn-sm" onclick="loadAssets()">Retry</button></div></td></tr>';};
  var setError=function(msg){if(tbody)tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--red)"><div style="font-size:32px;margin-bottom:8px">⚠</div>'+(msg||'Failed to load')+'<div style="margin-top:12px"><button class="btn btn-sm" onclick="loadAssets()">Retry</button></div></td></tr>';};
  if(!TOKEN){setEmpty('Authentication required');return;}
  setSkel();
  var h={Authorization:'Bearer '+TOKEN};
  try{
    var r=await fetch(API+'/api/v1/assets',{headers:h});
    if(!r.ok){setError('HTTP '+r.status);return;}
    var d=await r.json();
    if(!d.assets||!d.assets.length){ASSETS=[];updateKPIs();renderHeatmap();setEmpty('No assets discovered yet');return;}
    ASSETS=d.assets.map(function(a){return Object.assign({},a,{tool:a.tool||'scanner',findings_count:a.total_findings||a.findings_count||0,risk_score:a.risk_score||Math.round((a.critical||0)*20+(a.high||0)*8+(a.medium||0)*3+(a.low||0)),status:a.critical>0?'critical':a.high>0?'high':a.medium>0?'medium':'clean'});});
    updateKPIs();renderHeatmap();renderAssets();
    // Also load findings
    try{var rf=await fetch(API+'/api/v1/vsp/findings?limit=500',{headers:h});if(rf.ok){var df=await rf.json();ALL_FINDINGS=(df.findings||df.items||[]).map(function(f){return Object.assign({asset_id:f.asset_id||'',asset:f.asset||''},f);});if(typeof renderFindings==='function')renderFindings();}}catch(e){}
  }catch(e){setError('Network error');}
}'''
old_load = re.search(r"async function loadAssets\(\)\{[^}]*?\}\s*\n", src, flags=re.DOTALL)
if not old_load:
    # try greedier match
    m2 = re.search(r"async function loadAssets\(\)\{.*?^\}\s*$", src, flags=re.DOTALL|re.MULTILINE)
    if not m2:
        print("FAIL: loadAssets() not found"); sys.exit(1)
    src = src[:m2.start()] + NEW_LOAD + src[m2.end():]
else:
    src = src[:old_load.start()] + NEW_LOAD + "\n" + src[old_load.end():]
print("Rewrote loadAssets()")

# ─── 4. Remove initial mock render ───────────────────────────────
# Line was: updateKPIs();renderHeatmap();renderAssets();
# Replace with skeleton trigger + auto-call loadAssets when token ready
old_init = "updateKPIs();renderHeatmap();renderAssets();"
new_init = "/* FEAT-01: no initial render — loadAssets() will populate when token ready */ if(TOKEN){loadAssets();}else{var tb=document.getElementById('asset-tbody');if(tb)tb.innerHTML='<tr><td colspan=\"6\" style=\"text-align:center;padding:40px;color:var(--t3)\">Waiting for authentication…</td></tr>';}"
if old_init not in src:
    print("FAIL: initial render call not found"); sys.exit(1)
src = src.replace(old_init, new_init, 1)
print("Replaced initial mock render")

# ─── 5. Inject skeleton CSS just before </style> or first <script> ──
SKEL_CSS = '''<style>
/* FEAT-01 skeleton shimmer */
.skel-row td{padding:6px !important}
.skel{height:18px;border-radius:4px;background:linear-gradient(90deg,var(--surface) 0%,var(--border) 50%,var(--surface) 100%);background-size:200% 100%;animation:skel-shimmer 1.2s ease-in-out infinite}
@keyframes skel-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
</style>
'''
if "FEAT-01 skeleton shimmer" not in src:
    # inject before first <script>
    idx = src.find("<script")
    if idx < 0:
        print("FAIL: no <script> tag to anchor CSS"); sys.exit(1)
    src = src[:idx] + SKEL_CSS + src[idx:]
    print("Injected skeleton CSS")

# ─── 6. Add marker at top ────────────────────────────────────────
src = MARKER + "\n" + src

TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
