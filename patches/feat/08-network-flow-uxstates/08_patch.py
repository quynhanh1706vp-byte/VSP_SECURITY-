#!/usr/bin/env python3
"""
FEAT-08 (Sprint 5.4): Apply VSPUXState to Network Flow panel — Phase A final.

Strips 3 of 5 mock arrays:
- CONNS (7 fake connections) — pure mock, gone
- PROTOS (6 fake protocol stats) — pure mock, gone  
- NDR_ALERTS (5 fake alerts) — pure mock, gone

Keeps 2 mock arrays (graph topology template, dynamically updated):
- NODES (8 graph nodes with x/y coordinates)
- EDGES (8 graph edges)

Reason: loadNetworkFlow() already updates NODES/EDGES with real IPs from
/api/v1/logs/hunt fallback (line 220). Topology layout is canvas template.

Wires VSPUXState states into 3 stripped targets + tries to populate from
backend response if d.connections / d.protocols / d.alerts present.
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/network_flow.html")
BACKUP = pathlib.Path("static/panels/network_flow.html.bak.feat08")
MARKER = "/* FEAT-08 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-08 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Strip CONNS literal (line 271) ───────────────────────────
m = re.search(r"^var CONNS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: CONNS literal not found"); sys.exit(1)
src = src[:m.start()] + "var CONNS=[];" + src[m.end():]
print("Stripped CONNS literal")

# ─── 2. Strip PROTOS literal (line 280) ──────────────────────────
m = re.search(r"^var PROTOS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: PROTOS literal not found"); sys.exit(1)
src = src[:m.start()] + "var PROTOS=[];" + src[m.end():]
print("Stripped PROTOS literal")

# ─── 3. Strip NDR_ALERTS literal (line 288) ──────────────────────
m = re.search(r"^var NDR_ALERTS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: NDR_ALERTS literal not found"); sys.exit(1)
src = src[:m.start()] + "var NDR_ALERTS=[];" + src[m.end():]
print("Stripped NDR_ALERTS literal")

# ─── 4. Inject skeleton at start of loadNetworkFlow() ────────────
old_entry = '''async function loadNetworkFlow(){
  if(!TOKEN)return;
  var h={Authorization:'Bearer '+TOKEN};'''
new_entry = '''async function loadNetworkFlow(){
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX){
    VSPUXState.skeleton('#conn-tbody', {rows: 5});
    VSPUXState.skeleton('#proto-list', {rows: 4, kind: 'card'});
    VSPUXState.skeleton('#ndr-alerts', {rows: 3, kind: 'card'});
  }
  if(!TOKEN){
    if(hasUX){
      VSPUXState.empty('#conn-tbody', 'Authentication required', loadNetworkFlow);
      VSPUXState.empty('#proto-list', 'Authentication required', loadNetworkFlow);
      VSPUXState.empty('#ndr-alerts', 'Authentication required', loadNetworkFlow);
    }
    return;
  }
  var h={Authorization:'Bearer '+TOKEN};'''
if old_entry not in src:
    print("FAIL: loadNetworkFlow entry not found"); sys.exit(1)
src = src.replace(old_entry, new_entry, 1)
print("Injected skeleton at loadNetworkFlow entry")

# ─── 5. Add population logic for response.connections/protocols/alerts ────
# Anchor: after the main fetch try, before fallback "if(!d){"
old_fetch = '''    var d=null;
    try{
      var nr=await fetch(API+'/api/v1/logs/network-flow',{headers:h});
      if(nr.ok) d=await nr.json();
    }catch(e){}

    if(!d){'''
new_fetch = '''    var d=null;
    try{
      var nr=await fetch(API+'/api/v1/logs/network-flow',{headers:h});
      if(nr.ok) d=await nr.json();
    }catch(e){}

    // FEAT-08: populate CONNS/PROTOS/NDR_ALERTS from response if available
    if(d){
      if(d.connections && d.connections.length){ CONNS=d.connections; if(typeof renderConns==='function') renderConns(); }
      else if(hasUX){ VSPUXState.empty('#conn-tbody','No connection history',loadNetworkFlow); }

      if(d.protocols && d.protocols.length){ PROTOS=d.protocols; if(typeof renderProtos==='function') renderProtos(); }
      else if(hasUX){ VSPUXState.empty('#proto-list','No protocol data',loadNetworkFlow); }

      if(d.alerts && d.alerts.length){ NDR_ALERTS=d.alerts; if(typeof renderAlerts==='function') renderAlerts(); }
      else if(hasUX){ VSPUXState.empty('#ndr-alerts','No NDR alerts',loadNetworkFlow); }
    }

    if(!d){'''
if old_fetch not in src:
    print("FAIL: fetch block not found"); sys.exit(1)
src = src.replace(old_fetch, new_fetch, 1)
print("Added population logic from backend response")

# ─── 6. Add error state at the end of loadNetworkFlow (in catch if any) ──
# loadNetworkFlow has nested try/catch but no top-level catch.
# Wrap fallback in try/catch: search for end of function
# Find the closing "}" of loadNetworkFlow — pattern: last "}" before "function "
# Conservative: append a top-level catch if no exists
# Skip if too risky — leave existing flow as-is
print("Skipped top-level error wrap (existing logic has nested try/catch)")

# ─── 7. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
