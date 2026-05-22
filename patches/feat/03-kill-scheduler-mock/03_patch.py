#!/usr/bin/env python3
"""
FEAT-03: Kill hardcoded mock data in static/panels/scheduler.html.
Removes SAMPLE_SCHEDS + SAMPLE_RUNS literals, removes "init from mock" lines,
adds skeleton/empty/error states to loadSchedules() + loadRecentRuns().
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/scheduler.html")
BACKUP = pathlib.Path("static/panels/scheduler.html.bak.feat03")
MARKER = "/* FEAT-03 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-03 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. SAMPLE_SCHEDS literal → empty ────────────────────────────
m = re.search(r"^var SAMPLE_SCHEDS = \[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE_SCHEDS literal not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE_SCHEDS = [];" + src[m.end():]
print("Stripped SAMPLE_SCHEDS literal")

# ─── 2. SAMPLE_RUNS literal → empty ──────────────────────────────
m = re.search(r"^var SAMPLE_RUNS = \[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE_RUNS literal not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE_RUNS = [];" + src[m.end():]
print("Stripped SAMPLE_RUNS literal")

# ─── 3. Remove "SCHEDULES = SAMPLE_SCHEDS.slice();" + "RECENT_RUNS = ..." ──
old_init = "SCHEDULES = SAMPLE_SCHEDS.slice();\nRECENT_RUNS = SAMPLE_RUNS.slice();"
new_init = "/* FEAT-03: no mock init — start empty, loadSchedules/loadRecentRuns will populate */"
if old_init not in src:
    print("FAIL: mock init lines not found"); sys.exit(1)
src = src.replace(old_init, new_init, 1)
print("Removed mock init lines")

# ─── 4. Rewrite loadSchedules() — skeleton + empty + error ───────
old_load_scheds = '''async function loadSchedules() {
  if (!TOKEN) { renderSchedules(); return; }
  try {
    var r = await fetch(API + '/api/v1/schedules', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (r.ok) {
      var d = await r.json();
      if (d.schedules && d.schedules.length) {
        SCHEDULES = d.schedules.map(function(s) {'''
if old_load_scheds not in src:
    print("FAIL: loadSchedules signature not found"); sys.exit(1)

# Inject _schSetState helper call at start; preserve original mapper logic
new_load_scheds = '''async function loadSchedules() {
  _schSetState('schedules','skeleton');
  if (!TOKEN) { _schSetState('schedules','empty','Waiting for authentication'); return; }
  try {
    var r = await fetch(API + '/api/v1/schedules', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (!r.ok) { _schSetState('schedules','error','HTTP '+r.status); return; }
    var d = await r.json();
    if (!d.schedules || !d.schedules.length) { SCHEDULES=[]; renderSchedules(); _schSetState('schedules','empty','No schedules configured'); return; }
    {
      {
        SCHEDULES = d.schedules.map(function(s) {'''
src = src.replace(old_load_scheds, new_load_scheds, 1)
print("Rewrote loadSchedules() header")

# Replace catch-block silent fail with error state
src = re.sub(
    r"\}\s*\}\s*\}\s*catch\(e\)\s*\{\s*renderSchedules\(\);\s*\}\s*\n\s*\nasync function loadRecentRuns",
    "}}}}\n  catch(e){_schSetState('schedules','error','Network error');}\n}\n\nasync function loadRecentRuns",
    src, count=1
)
print("Patched loadSchedules() catch")

# ─── 5. Rewrite loadRecentRuns() ─────────────────────────────────
old_load_runs = '''async function loadRecentRuns() {
  if (!TOKEN) { renderRecentRuns(); return; }
  try {
    var r = await fetch(API + '/api/v1/vsp/runs?limit=20', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (r.ok) {
      var d = await r.json();
      if (d.runs && d.runs.length) {
        RECENT_RUNS = d.runs.map(function(r) {
          return { rid: r.rid||r.id, sched: r.schedule_name||'Manual', status: r.status, gate: r.gate||'—', findings: r.total_findings||0, dur: '—', ts: (r.created_at||'').slice(0,16), mode: r.mode||'' };
        });
        renderRecentRuns();
      }
    }
  } catch(e) { renderRecentRuns(); }
}'''
new_load_runs = '''async function loadRecentRuns() {
  _schSetState('runs','skeleton');
  if (!TOKEN) { _schSetState('runs','empty','Waiting for authentication'); return; }
  try {
    var r = await fetch(API + '/api/v1/vsp/runs?limit=20', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (!r.ok) { _schSetState('runs','error','HTTP '+r.status); return; }
    var d = await r.json();
    if (!d.runs || !d.runs.length) { RECENT_RUNS=[]; renderRecentRuns(); _schSetState('runs','empty','No runs yet'); return; }
    RECENT_RUNS = d.runs.map(function(r) {
      return { rid: r.rid||r.id, sched: r.schedule_name||'Manual', status: r.status, gate: r.gate||'—', findings: r.total_findings||0, dur: '—', ts: (r.created_at||'').slice(0,16), mode: r.mode||'' };
    });
    renderRecentRuns();
  } catch(e) { _schSetState('runs','error','Network error'); }
}'''
if old_load_runs not in src:
    print("FAIL: loadRecentRuns block not found"); sys.exit(1)
src = src.replace(old_load_runs, new_load_runs, 1)
print("Rewrote loadRecentRuns()")

# ─── 6. Inject _schSetState helper + CSS ─────────────────────────
HELPERS = '''
/* FEAT-03 helpers — skeleton/empty/error states for scheduler */
function _schSetState(which,kind,msg){
  var sel=which==='schedules'?'#sched-tbody':'#runs-list';
  var el=document.querySelector(sel);if(!el)return;
  if(kind==='skeleton'){
    if(which==='schedules'){el.innerHTML='<tr class="sch-skel"><td colspan="6"><div class="sch-shimmer"></div></td></tr>'.repeat(4);}
    else{el.innerHTML='<div class="sch-skel"><div class="sch-shimmer" style="height:48px;margin:6px 0"></div></div>'.repeat(3);}
  } else if(kind==='empty'){
    var inner='<div style="text-align:center;padding:32px;color:var(--t3);font-size:12px"><div style="font-size:28px;margin-bottom:8px">∅</div>'+(msg||'No data')+'</div>';
    el.innerHTML=which==='schedules'?'<tr><td colspan="6">'+inner+'</td></tr>':inner;
  } else if(kind==='error'){
    var inner='<div style="text-align:center;padding:32px;color:var(--red);font-size:12px"><div style="font-size:28px;margin-bottom:8px">⚠</div>'+(msg||'Error')+'<div style="margin-top:10px"><button class="btn btn-sm" onclick="(typeof loadSchedules===\\'function\\'&&loadSchedules());(typeof loadRecentRuns===\\'function\\'&&loadRecentRuns())">Retry</button></div></div>';
    el.innerHTML=which==='schedules'?'<tr><td colspan="6">'+inner+'</td></tr>':inner;
  }
}
'''
SKEL_CSS = '''
<style>
/* FEAT-03 scheduler skeleton */
.sch-shimmer{height:18px;border-radius:4px;background:linear-gradient(90deg,var(--surface) 0%,var(--border) 50%,var(--surface) 100%);background-size:200% 100%;animation:sch-shimmer 1.2s infinite}
@keyframes sch-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
</style>
'''
idx_close = src.find("</script>")
if idx_close < 0:
    print("FAIL: no </script> for helpers"); sys.exit(1)
src = src[:idx_close] + HELPERS + src[idx_close:]
print("Injected helpers")

idx_open = src.find("<script")
if idx_open < 0:
    print("FAIL: no <script> for CSS"); sys.exit(1)
src = src[:idx_open] + SKEL_CSS + src[idx_open:]
print("Injected skeleton CSS")

# ─── 7. Marker ───────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
