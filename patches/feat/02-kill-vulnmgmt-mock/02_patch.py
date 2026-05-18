#!/usr/bin/env python3
"""
FEAT-02: Kill hardcoded mock data in static/panels/vuln_mgmt.html.
Removes SAMPLE_TREND (IIFE) + SAMPLE_CVES + SAMPLE_TOOLS + SAMPLE_SLA literals,
removes initial mock render, removes mock fallback in fetch path,
adds skeleton/empty/error states for trend chart + CVE table + tools table + SLA bars.
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/vuln_mgmt.html")
BACKUP = pathlib.Path("static/panels/vuln_mgmt.html.bak.feat02")
MARKER = "/* FEAT-02 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-02 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. SAMPLE_TREND IIFE → empty array ──────────────────────────
m = re.search(r"^var SAMPLE_TREND = \(function\(\) \{[\s\S]*?\}\)\(\);\s*$", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE_TREND IIFE not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE_TREND = [];" + src[m.end():]
print("Stripped SAMPLE_TREND IIFE")

# ─── 2. SAMPLE_CVES literal → empty array ────────────────────────
m = re.search(r"^var SAMPLE_CVES = \[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE_CVES literal not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE_CVES = [];" + src[m.end():]
print("Stripped SAMPLE_CVES literal")

# ─── 3. SAMPLE_TOOLS literal → empty array ───────────────────────
m = re.search(r"^var SAMPLE_TOOLS = \[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE_TOOLS literal not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE_TOOLS = [];" + src[m.end():]
print("Stripped SAMPLE_TOOLS literal")

# ─── 4. SAMPLE_SLA literal → empty array ─────────────────────────
m = re.search(r"^var SAMPLE_SLA = \[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE_SLA literal not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE_SLA = [];" + src[m.end():]
print("Stripped SAMPLE_SLA literal")

# ─── 5. Remove "render mock immediately" block (the 6 lines at 447-452) ──
# Pattern: 6 consecutive renderX(SAMPLE_*) calls
old_initial = """  renderTrend(SAMPLE_TREND);
  renderCVEs(SAMPLE_CVES);
  renderTools(SAMPLE_TOOLS);
  renderSLA(SAMPLE_SLA);
  renderFixable(SAMPLE_CVES);
  updateKPIs(SAMPLE_CVES, SAMPLE_TOOLS);"""
new_initial = """  /* FEAT-02: no initial mock render — loadFromAPI() will populate */
  _vmShowSkeleton();"""
if old_initial not in src:
    print("FAIL: initial mock render block not found"); sys.exit(1)
src = src.replace(old_initial, new_initial, 1)
print("Replaced initial mock render block")

# ─── 6. Replace fetch fallback pattern (lines ~472-479) ─────────────────
# Original: renderTrend(td.length ? td : SAMPLE_TREND); etc.
# Replace each "X.length ? X : SAMPLE_Y" with just "X" or empty-state call.
src = re.sub(r"renderTrend\(td\.length \? td : SAMPLE_TREND\);",
             "if(td.length){renderTrend(td);}else{_vmShowEmpty('trend');}", src, count=1)
src = re.sub(r"renderCVEs\(\s*cd\.length \? cd : SAMPLE_CVES\);",
             "if(cd.length){renderCVEs(cd);}else{_vmShowEmpty('cves');}", src, count=1)
src = re.sub(r"renderTools\(ld\.length \? ld : SAMPLE_TOOLS\);",
             "if(ld.length){renderTools(ld);}else{_vmShowEmpty('tools');}", src, count=1)
src = re.sub(r"renderSLA\(SAMPLE_SLA\);",
             "_vmLoadSLA();", src, count=1)
src = re.sub(r"renderFixable\(cd\.length \? cd : SAMPLE_CVES\);",
             "if(cd.length){renderFixable(cd);}", src, count=1)
src = re.sub(r"updateKPIs\(cd\.length \? cd : SAMPLE_CVES, ld\.length \? ld : SAMPLE_TOOLS\);",
             "updateKPIs(cd, ld);", src, count=1)
print("Rewrote fetch fallback pattern")

# ─── 7. Inject helper functions + SLA loader before first </script> ──
HELPERS = """
/* FEAT-02 helpers ─ skeleton/empty/error states */
function _vmShowSkeleton(){
  var ids=['trend','cves','tools','sla','fixable'];
  ids.forEach(function(id){var el=document.querySelector('[data-vm="'+id+'"]')||document.getElementById('vm-'+id);if(el)el.innerHTML='<div class="vm-skel" style="height:60px;border-radius:6px;background:linear-gradient(90deg,var(--surface) 0%,var(--border) 50%,var(--surface) 100%);background-size:200% 100%;animation:vm-shimmer 1.2s infinite"></div>';});
}
function _vmShowEmpty(which){
  var el=document.querySelector('[data-vm="'+which+'"]')||document.getElementById('vm-'+which);
  if(el)el.innerHTML='<div style="text-align:center;padding:32px;color:var(--t3);font-size:12px"><div style="font-size:24px;margin-bottom:6px">∅</div>No '+which+' data</div>';
}
function _vmShowError(which,msg){
  var el=document.querySelector('[data-vm="'+which+'"]')||document.getElementById('vm-'+which);
  if(el)el.innerHTML='<div style="text-align:center;padding:32px;color:var(--red);font-size:12px"><div style="font-size:24px;margin-bottom:6px">⚠</div>'+(msg||'Error')+'<div style="margin-top:8px"><button class="btn btn-sm" onclick="location.reload()">Reload</button></div></div>';
}
async function _vmLoadSLA(){
  if(typeof TOKEN==='undefined'||!TOKEN){_vmShowEmpty('sla');return;}
  try{
    var r=await fetch((typeof API!=='undefined'?API:'')+'/api/v1/vsp/sla_tracker',{headers:{Authorization:'Bearer '+TOKEN}});
    if(!r.ok){_vmShowError('sla','HTTP '+r.status);return;}
    var d=await r.json();
    var rows=[
      {label:'Critical (24h)',pct:Math.round(((d.critical_met||0)/Math.max(1,d.critical_total||1))*100),color:'var(--red)'},
      {label:'High (7d)',     pct:Math.round(((d.high_met    ||0)/Math.max(1,d.high_total    ||1))*100),color:'var(--amber)'},
      {label:'Medium (30d)',  pct:Math.round(((d.medium_met  ||0)/Math.max(1,d.medium_total  ||1))*100),color:'var(--blue)'},
      {label:'Low (90d)',     pct:Math.round(((d.low_met     ||0)/Math.max(1,d.low_total     ||1))*100),color:'var(--green)'},
    ];
    if(typeof renderSLA==='function')renderSLA(rows);
  }catch(e){_vmShowError('sla','Network error');}
}
"""
SKEL_CSS = """
<style>
/* FEAT-02 vuln_mgmt skeleton shimmer */
@keyframes vm-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
</style>
"""
# inject before first </script>
idx_close = src.find("</script>")
if idx_close < 0:
    print("FAIL: no </script> tag for helper inject"); sys.exit(1)
src = src[:idx_close] + HELPERS + src[idx_close:]
print("Injected helper functions")

# inject CSS before first <script>
idx_open = src.find("<script")
if idx_open < 0:
    print("FAIL: no <script> tag for CSS anchor"); sys.exit(1)
src = src[:idx_open] + SKEL_CSS + src[idx_open:]
print("Injected skeleton CSS")

# ─── 8. Marker at top ───────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
