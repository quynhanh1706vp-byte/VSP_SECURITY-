#!/usr/bin/env bash
# Deploy UEBA + Assets panels
set -euo pipefail
BASE="${1:-$HOME/Data/GOLANG_VSP}"
echo "▶ Deploying to $BASE"

# 1. Handler files
cp ueba_handler.go "$BASE/internal/api/handler/ueba.go"
cp assets_handler.go "$BASE/internal/api/handler/assets.go"
echo "✓  Handlers copied"

# 2. Panel HTML
cp ueba.html   "$BASE/static/panels/ueba.html"
cp assets.html "$BASE/static/panels/assets.html"
echo "✓  Panels copied"

# 3. Patch main.go — add routes + handler inits
python3 - << 'PYEOF'
import re, shutil, os
from datetime import datetime

MAIN = os.path.expanduser("~/Data/GOLANG_VSP/cmd/gateway/main.go")
bak  = MAIN + f".bak_ueba_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
shutil.copy2(MAIN, bak)

go = open(MAIN).read()

# Handler inits
INITS = """
\t// ── UEBA + Assets ────────────────────────────────────────
\tuebaH   := &handler.UEBA{DB: db}
\tassetsH := &handler.Assets{DB: db}"""

# Routes
ROUTES = """
\t\t// ── UEBA ────────────────────────────────────────────────
\t\tr.Get("/api/v1/ueba/anomalies", uebaH.ListAnomalies)
\t\tr.Post("/api/v1/ueba/analyze",  uebaH.Analyze)
\t\tr.Get("/api/v1/ueba/baseline",  uebaH.Baseline)
\t\tr.Get("/api/v1/ueba/timeline",  uebaH.Timeline)

\t\t// ── Asset inventory ─────────────────────────────────────
\t\tr.Get("/api/v1/assets",                assetsH.List)
\t\tr.Post("/api/v1/assets",               assetsH.Create)
\t\tr.Get("/api/v1/assets/summary",        assetsH.Summary)
\t\tr.Get("/api/v1/assets/{id}/findings",  assetsH.Findings)"""

# Inject inits after corrH
if "corrH" in go and "uebaH" not in go:
    go = re.sub(r'(corrH\s*:=\s*&handler\.Correlation\{[^}]+\})', r'\1' + INITS, go, count=1)
    print("✓  Handler inits injected")

# Inject routes after correlation routes
if "corrH.ListRules" in go and "uebaH.ListAnomalies" not in go:
    go = re.sub(r'(r\.Post\("/api/v1/correlation/incidents"[^\n]+\n)', r'\1' + ROUTES + '\n', go, count=1)
    print("✓  Routes injected")

open(MAIN, "w").write(go)
print(f"✓  main.go updated ({len(go):,} bytes)")
PYEOF

# 4. Patch vsp_siem_patch.js — add UEBA + Assets to panel loaders
python3 - << 'PYEOF'
import os
f = os.path.expanduser("~/Data/GOLANG_VSP/static/panels/vsp_siem_patch.js")
js = open(f).read()

# Add panel meta
if "'ueba'" not in js:
    js = js.replace(
        "{ name:'Threat intelligence'",
        "{ name:'UEBA analytics',      icon:'◉', p:'ueba',       desc:'Behavioral baseline · anomaly detection' },\n    { name:'Asset inventory',     icon:'◫', p:'assets',     desc:'CMDB · risk scoring · coverage' },\n    { name:'Threat intelligence'"
    )
    print("✓  QS panels added")

# Add loaders
if "loadUEBA" not in js:
    js = js.replace(
        "// 6. Auto-trigger SOAR",
        """async function loadUEBA() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const frame = document.querySelector('#panel-ueba iframe');
  if (frame) try { frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*'); } catch(e) {}
}

async function loadAssets() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const frame = document.querySelector('#panel-assets iframe');
  if (frame) try { frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*'); } catch(e) {}
}

// 6. Auto-trigger SOAR"""
    )
    print("✓  Loaders added")

# Add to showPanel hook
if "'ueba': loadUEBA" not in js:
    js = js.replace(
        "const loaders = {",
        "const loaders = {\n      ueba:        loadUEBA,\n      assets:      loadAssets,"
    )
    print("✓  showPanel hooks added")

open(f, "w").write(js)
PYEOF

# 5. Patch index.html — add nav + panels
python3 - << 'PYEOF'
import re, os
f = os.path.expanduser("~/Data/GOLANG_VSP/static/index.html")
html = open(f).read()

# Nav buttons
if "showPanel('ueba'" not in html:
    html = html.replace(
        """<button class="nav-item" onclick="showPanel('threatintel',this)">""",
        """<button class="nav-item" onclick="showPanel('ueba',this)">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6.5"/><circle cx="8" cy="8" r="2.5"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2"/></svg></span>
        UEBA
      </button>
      <button class="nav-item" onclick="showPanel('assets',this)">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="3" width="14" height="10" rx="1.5"/><path d="M5 3V2M8 3V2M11 3V2M4 7h2M4 10h2M8 7h4M8 10h3"/></svg></span>
        Assets
      </button>
      <button class="nav-item" onclick="showPanel('threatintel',this)">"""
    )
    print("✓  Nav buttons added")

# Panel divs
if 'id="panel-ueba"' not in html:
    html = html.replace(
        '<div id="panel-threatintel" class="panel">',
        '''<div id="panel-ueba" class="panel">
      <iframe src="/panels/ueba.html" style="width:100%;height:calc(100vh - 52px);border:none;background:transparent" allowtransparency="true"></iframe>
    </div>
    <div id="panel-assets" class="panel">
      <iframe src="/panels/assets.html" style="width:100%;height:calc(100vh - 52px);border:none;background:transparent" allowtransparency="true"></iframe>
    </div>
    <div id="panel-threatintel" class="panel">'''
    )
    print("✓  Panel divs added")

# PANEL_META
if "'ueba'" not in html:
    html = html.replace(
        "threatintel: { title:'Threat intelligence'",
        "ueba:        { title:'UEBA analytics',     sub:'VSP / SIEM / Behavioral baseline · anomalies' },\n  assets:      { title:'Asset inventory',    sub:'VSP / SIEM / CMDB · risk scoring · findings' },\n  threatintel: { title:'Threat intelligence'"
    )
    print("✓  PANEL_META added")

open(f, "w").write(html)
PYEOF

# 6. Build
echo "▶ Building..."
cd "$BASE"
go build ./cmd/gateway/... 2>&1 | head -20
echo "Exit: $?"

echo ""
echo "▶ Restart:"
echo "  bash start.sh"
echo ""
echo "✓  Done — UEBA + Assets deployed"
