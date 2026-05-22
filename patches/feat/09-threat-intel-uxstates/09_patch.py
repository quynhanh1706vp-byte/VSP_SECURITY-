#!/usr/bin/env python3
"""
FEAT-10 (Sprint 6): Apply VSPUXState to Threat Intel panel — Phase B start.

Strips 3 of 4 mock arrays:
- IOCS (mock indicators) — backend /api/v1/ti/iocs already wired
- FEEDS (mock TI feed list) — backend /api/v1/ti/feeds already wired
- CVES (mock CVE list) — wires to /api/v1/vulns/top-cves (was missing)

Keeps MITRE (10 ATT&CK tactics — enterprise taxonomy, config not data).

Rewrites loadFromAPI() to:
- Add VSPUXState skeleton/empty/error on 3 targets
- Add CVES fetch via /api/v1/vulns/top-cves (was missing in original)
- Defensive guards via hasUX

Patches initial render line 393 to skip mock render of IOCS/FEEDS/CVES
(only MITRE config + skeleton placeholders shown until loadFromAPI returns).
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/threat_intel.html")
BACKUP = pathlib.Path("static/panels/threat_intel.html.bak.feat09")
MARKER = "/* FEAT-10 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-10 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Strip IOCS literal (line 199) ────────────────────────────
m = re.search(r"^var IOCS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: IOCS literal not found"); sys.exit(1)
src = src[:m.start()] + "var IOCS=[];" + src[m.end():]
print("Stripped IOCS literal")

# ─── 2. Strip FEEDS literal (line 212) ───────────────────────────
m = re.search(r"^var FEEDS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: FEEDS literal not found"); sys.exit(1)
src = src[:m.start()] + "var FEEDS=[];" + src[m.end():]
print("Stripped FEEDS literal")

# ─── 3. Strip CVES literal (line 220) ────────────────────────────
m = re.search(r"^var CVES=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: CVES literal not found"); sys.exit(1)
src = src[:m.start()] + "var CVES=[];" + src[m.end():]
print("Stripped CVES literal")

# ─── 4. Rewrite loadFromAPI() ────────────────────────────────────
old_load = '''function loadFromAPI(){
  if(!TOKEN)return;
  var h={Authorization:'Bearer '+TOKEN};
  Promise.all([
    fetch(API+'/api/v1/ti/iocs?limit=20',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
    fetch(API+'/api/v1/ti/feeds',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
    fetch(API+'/api/v1/ti/matches',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
  ]).then(function(res){
    if(res[0]&&res[0].iocs&&res[0].iocs.length){IOCS=res[0].iocs.map(function(i){return Object.assign({id:i.id||Math.random().toString(36).slice(2),matched:false,findings:[],mitre:[]},i);});renderIOCs();}
    if(res[1]&&res[1].feeds&&res[1].feeds.length){FEEDS=res[1].feeds.map(function(f){return Object.assign({icon:'◈',lastSync:'—'},f);});renderFeeds();}
    if(res[2]&&res[2].matches)document.getElementById('k-matches').textContent=res[2].matches.length||0;
  });
}'''
new_load = '''async function loadFromAPI(){
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX){
    VSPUXState.skeleton('#ioc-tbody', {rows: 5});
    VSPUXState.skeleton('#feeds-list', {rows: 4, kind: 'card'});
    VSPUXState.skeleton('#cve-tbody', {rows: 5});
  }
  if(!TOKEN){
    if(hasUX){
      VSPUXState.empty('#ioc-tbody', 'Authentication required', loadFromAPI);
      VSPUXState.empty('#feeds-list', 'Authentication required', loadFromAPI);
      VSPUXState.empty('#cve-tbody', 'Authentication required', loadFromAPI);
    }
    return;
  }
  var h={Authorization:'Bearer '+TOKEN};
  try{
    var res = await Promise.all([
      fetch(API+'/api/v1/ti/iocs?limit=20',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
      fetch(API+'/api/v1/ti/feeds',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
      fetch(API+'/api/v1/ti/matches',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
      fetch(API+'/api/v1/vulns/top-cves',{headers:h}).then(function(r){return r.json();}).catch(function(){return null;}),
    ]);
    // IOCs
    if(res[0]&&res[0].iocs&&res[0].iocs.length){
      IOCS=res[0].iocs.map(function(i){return Object.assign({id:i.id||Math.random().toString(36).slice(2),matched:false,findings:[],mitre:[]},i);});
      renderIOCs();
    } else if(hasUX){
      VSPUXState.empty('#ioc-tbody', 'No IOCs in feed', loadFromAPI);
    }
    // Feeds
    if(res[1]&&res[1].feeds&&res[1].feeds.length){
      FEEDS=res[1].feeds.map(function(f){return Object.assign({icon:'◈',lastSync:'—'},f);});
      renderFeeds();
    } else if(hasUX){
      VSPUXState.empty('#feeds-list', 'No feeds configured', loadFromAPI);
    }
    // Matches KPI
    if(res[2]&&res[2].matches)document.getElementById('k-matches').textContent=res[2].matches.length||0;
    // CVEs (NEW — was missing in original)
    if(res[3]&&res[3].cves&&res[3].cves.length){
      CVES=res[3].cves.map(function(c){return Object.assign({id:c.cve||c.id||'CVE-?',matched:false,kev:c.kev||false,findings:[]},c);});
      renderCVEs();
    } else if(hasUX){
      VSPUXState.empty('#cve-tbody', 'No CVE data', loadFromAPI);
    }
  }catch(e){
    if(hasUX){
      VSPUXState.error('#ioc-tbody', 'Network error', loadFromAPI);
      VSPUXState.error('#feeds-list', 'Network error', loadFromAPI);
      VSPUXState.error('#cve-tbody', 'Network error', loadFromAPI);
    }
  }
}'''
if old_load not in src:
    print("FAIL: loadFromAPI() not found"); sys.exit(1)
src = src.replace(old_load, new_load, 1)
print("Rewrote loadFromAPI() with VSPUXState + CVES fetch")

# ─── 5. Patch initial render line 393 ────────────────────────────
old_init = "renderIOCs();renderFeeds();renderCVEs();renderMITRE();"
new_init = "/* FEAT-10: defer mock render — only MITRE config rendered immediately */\nrenderMITRE();\nif(typeof VSPUXState!=='undefined'){\n  VSPUXState.skeleton('#ioc-tbody',{rows:5});\n  VSPUXState.skeleton('#feeds-list',{rows:4,kind:'card'});\n  VSPUXState.skeleton('#cve-tbody',{rows:5});\n}"
if old_init not in src:
    print("FAIL: initial render line not found"); sys.exit(1)
src = src.replace(old_init, new_init, 1)
print("Patched initial render line")

# ─── 6. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
