#!/usr/bin/env python3
"""
FEAT-06 (Sprint 5.2): Apply VSPUXState to UEBA panel.
- Strip SAMPLE (3 fake anomalies), SCORE_HIST (14 numbers), BL_SCORE (72)
- Keep CHECKS (6 detection rules — config, like ROLES in FEAT-05)
- Rewrite loadBaseline() with VSPUXState skeleton/empty/error
- Add new loadAnomalies() fetching /api/v1/ueba/analyze
- Remove mock fallback "if(!ANOMALIES.length)ANOMALIES=SAMPLE.slice()"
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/ueba.html")
BACKUP = pathlib.Path("static/panels/ueba.html.bak.feat06")
MARKER = "/* FEAT-06 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-06 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. SAMPLE literal → empty ───────────────────────────────────
m = re.search(r"^var SAMPLE=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: SAMPLE literal not found"); sys.exit(1)
src = src[:m.start()] + "var SAMPLE=[];" + src[m.end():]
print("Stripped SAMPLE literal")

# ─── 2. SCORE_HIST → empty array ─────────────────────────────────
old_hist = "var SCORE_HIST=[71,74,69,73,68,75,71,74,72,70,73,68,25,22];"
new_hist = "var SCORE_HIST=[];"
if old_hist not in src:
    print("FAIL: SCORE_HIST literal not found"); sys.exit(1)
src = src.replace(old_hist, new_hist, 1)
print("Stripped SCORE_HIST literal")

# ─── 3. BL_SCORE → null ──────────────────────────────────────────
old_bl = "var BL_SCORE=72;"
new_bl = "var BL_SCORE=null;"
if old_bl not in src:
    print("FAIL: BL_SCORE literal not found"); sys.exit(1)
src = src.replace(old_bl, new_bl, 1)
print("Stripped BL_SCORE literal")

# ─── 4. Remove mock fallback line 363 ────────────────────────────
old_fallback = "if(!ANOMALIES.length)ANOMALIES=SAMPLE.slice();"
new_fallback = "/* FEAT-06: no mock fallback — empty state shown by VSPUXState */"
if old_fallback not in src:
    print("FAIL: mock fallback not found"); sys.exit(1)
src = src.replace(old_fallback, new_fallback, 1)
print("Removed mock fallback")

# ─── 5. Rewrite loadBaseline() ───────────────────────────────────
old_load = '''function loadBaseline(){
  var def={avg_score:72,std_score:8.4,avg_findings:82,gate_pass_rate:.38,avg_scans_per_day:3.2,period:'30d'};
  if(!TOKEN){renderBaseline(def);return;}
  fetch(API+'/api/v1/ueba/baseline',{headers:{Authorization:'Bearer '+TOKEN}}).then(function(r){return r.json();}).then(renderBaseline).catch(function(){renderBaseline(def);});
}'''
new_load = '''async function loadBaseline(){
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX) VSPUXState.skeleton('#score-bars', {rows: 1, height: 80});
  if(!TOKEN){
    if(hasUX) VSPUXState.empty('#score-bars', 'Authentication required', loadBaseline);
    return;
  }
  try{
    var r = await fetch(API+'/api/v1/ueba/baseline', {headers:{Authorization:'Bearer '+TOKEN}});
    if(!r.ok){
      if(hasUX) VSPUXState.error('#score-bars', 'HTTP '+r.status, loadBaseline);
      return;
    }
    var d = await r.json();
    if(!d || (d.avg_score==null && !d.history)){
      if(hasUX) VSPUXState.empty('#score-bars', 'No baseline data', loadBaseline);
      return;
    }
    // Apply real data: history -> SCORE_HIST, avg_score -> BL_SCORE
    if(d.history && d.history.length){
      SCORE_HIST = d.history.map(function(h){return h.val||h.score||h;});
    }
    if(d.avg_score!=null) BL_SCORE = d.avg_score;
    renderBaseline(d);
    if(typeof renderScoreBars==='function') renderScoreBars();
    loadAnomalies();
  }catch(e){
    if(hasUX) VSPUXState.error('#score-bars', 'Network error', loadBaseline);
  }
}

async function loadAnomalies(){
  var hasUX = typeof VSPUXState !== 'undefined';
  var target = '#anomalies-list';
  if(hasUX) VSPUXState.skeleton(target, {rows: 3});
  if(!TOKEN){
    if(hasUX) VSPUXState.empty(target, 'Authentication required', loadAnomalies);
    return;
  }
  try{
    var r = await fetch(API+'/api/v1/ueba/analyze', {headers:{Authorization:'Bearer '+TOKEN}});
    if(!r.ok){
      if(hasUX) VSPUXState.error(target, 'HTTP '+r.status, loadAnomalies);
      return;
    }
    var d = await r.json();
    var arr = d.anomalies || d.results || [];
    if(!arr.length){
      ANOMALIES = [];
      if(hasUX) VSPUXState.empty(target, 'No anomalies detected', loadAnomalies);
      return;
    }
    ANOMALIES = arr;
    if(typeof renderAnomalies==='function') renderAnomalies();
  }catch(e){
    if(hasUX) VSPUXState.error(target, 'Network error', loadAnomalies);
  }
}'''
if old_load not in src:
    print("FAIL: loadBaseline() not found"); sys.exit(1)
src = src.replace(old_load, new_load, 1)
print("Rewrote loadBaseline() + added loadAnomalies()")

# ─── 6. Patch initial render at line 388 ──────────────────────────
# Original: renderScoreBars();renderChecks();loadBaseline();
# Don't call renderScoreBars before data loaded (avoid empty render flash)
old_init = "renderScoreBars();renderChecks();loadBaseline();"
new_init = "/* FEAT-06: defer renderScoreBars until loadBaseline returns data */\nrenderChecks();loadBaseline();"
if old_init not in src:
    print("FAIL: initial render call not found"); sys.exit(1)
src = src.replace(old_init, new_init, 1)
print("Patched initial render call")

# ─── 7. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
