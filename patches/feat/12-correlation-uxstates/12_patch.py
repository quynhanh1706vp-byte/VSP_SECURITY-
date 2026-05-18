#!/usr/bin/env python3
"""
FEAT-13 (Sprint 9): Apply VSPUXState to Correlation panel.

Strips 1 mock array:
- SPARK_DATA (hardcoded sparkline numbers [12,18,9,24,31,19,14,28,44,38,21,17])

Keeps 3 config-like arrays (DEF_* pattern matches DEFAULT_ROLES from FEAT-05):
- DEF_RULES (default correlation rules — fallback config)
- DEF_INCIDENTS (default incidents — fallback config)
- SOURCES (log source config)

Patches initial render block (line 773-777) and adds VSPUXState skeleton
on entry of loadFromAPI().
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/correlation.html")
BACKUP = pathlib.Path("static/panels/correlation.html.bak.feat12")
MARKER = "/* FEAT-13 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-13 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Strip SPARK_DATA ─────────────────────────────────────────
old_spark = "var SPARK_DATA=[12,18,9,24,31,19,14,28,44,38,21,17];"
new_spark = "var SPARK_DATA=[];"
if old_spark not in src:
    print("FAIL: SPARK_DATA literal not found"); sys.exit(1)
src = src.replace(old_spark, new_spark, 1)
print("Stripped SPARK_DATA literal")

# ─── 2. Inject VSPUXState skeleton in loadFromAPI() ──────────────
# Find loadFromAPI function start
old_load_re = re.compile(r"function loadFromAPI\(\)\s*\{")
m = old_load_re.search(src)
if not m:
    print("FAIL: loadFromAPI not found"); sys.exit(1)

inject_point = m.end()
inject_code = """
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX){
    var skelTargets = ['#rules-tbody', '#incidents-list', '#src-health', '#sev-breakdown'];
    skelTargets.forEach(function(t){
      var el = document.querySelector(t);
      if(el) VSPUXState.skeleton(t, {rows: 4});
    });
  }"""
src = src[:inject_point] + inject_code + src[inject_point:]
print("Injected skeleton in loadFromAPI")

# ─── 3. Patch initial mock render (line 773-777) ─────────────────
old_init = """renderRules();
renderIncidents();
renderSevBreakdown();
renderSpark();
renderSrcHealth();"""
new_init = """/* FEAT-13: defer mock render — loadFromAPI populates real data */
renderSrcHealth();  /* SOURCES is config, OK to render immediately */
if(typeof VSPUXState!=='undefined'){
  ['#rules-tbody','#incidents-list'].forEach(function(t){
    var el=document.querySelector(t);
    if(el)VSPUXState.skeleton(t,{rows:4});
  });
}"""
if old_init not in src:
    print("FAIL: initial render block not found"); sys.exit(1)
src = src.replace(old_init, new_init, 1)
print("Patched initial render block")

# ─── 4. Marker ───────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
