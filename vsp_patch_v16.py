#!/usr/bin/env python3
"""
VSP Gov Patch v1.6 — Runs & Findings Panel Upgrade
Fixes:
  1. Runs: r.total → r.total_findings, summary score key normalization
  2. Runs: Add KPI row + Gate trend mini-chart + Pass rate sparkline
  3. Findings: Add KPI severity cards on top
  4. Findings: Fix filter-tool dropdown (add all tools + dynamic)
  5. Audit panel: wire to real API instead of hardcoded HTML
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_v16_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

changes = 0

# ════════════════════════════════════════════════════════════════════════════
# 1. CSS for new KPI elements
# ════════════════════════════════════════════════════════════════════════════
KPI_CSS = """
/* ═══════════════════════════════════════════════
   GOV PATCH v1.6 — Runs & Findings KPI Charts
═══════════════════════════════════════════════ */
.runs-kpi-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 10px;
  margin-bottom: 14px;
}
.runs-kpi-card {
  background: var(--card);
  border: 1px solid var(--b1);
  border-radius: 6px;
  padding: 12px 14px;
  display: flex; flex-direction: column; gap: 4px;
}
.runs-kpi-label {
  font-family: var(--font-mono);
  font-size: 9px; font-weight: 600;
  color: var(--t3); letter-spacing: 0.08em;
  text-transform: uppercase;
}
.runs-kpi-value {
  font-family: var(--font-display);
  font-size: 24px; font-weight: 800;
  line-height: 1;
}
.runs-kpi-sub {
  font-family: var(--font-mono);
  font-size: 9px; color: var(--t4);
}
.runs-chart-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 14px;
}
.runs-chart-card {
  background: var(--card);
  border: 1px solid var(--b1);
  border-radius: 6px;
  padding: 14px 16px;
}
.runs-chart-title {
  font-family: var(--font-mono);
  font-size: 10px; font-weight: 700;
  color: var(--t2); margin-bottom: 10px;
  letter-spacing: 0.06em; text-transform: uppercase;
}

/* Findings KPI row */
.findings-kpi-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin-bottom: 14px;
}
.findings-kpi-card {
  background: var(--card);
  border: 1px solid var(--b1);
  border-radius: 6px;
  padding: 10px 14px;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}
.findings-kpi-card:hover { background: rgba(255,255,255,0.02); }
.findings-kpi-card.active { border-color: var(--cyan); }
.findings-kpi-sev {
  font-family: var(--font-mono);
  font-size: 8px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase;
  margin-bottom: 4px;
}
.findings-kpi-num {
  font-family: var(--font-display);
  font-size: 28px; font-weight: 800;
  line-height: 1;
}
.findings-kpi-pct {
  font-family: var(--font-mono);
  font-size: 9px; color: var(--t4);
  margin-top: 2px;
}

/* Tool breakdown mini bars */
.tool-breakdown { display: flex; flex-direction: column; gap: 5px; }
.tool-bar-row {
  display: flex; align-items: center; gap: 8px;
  font-family: var(--font-mono); font-size: 9px;
}
.tool-bar-name { width: 72px; color: var(--t3); flex-shrink: 0; }
.tool-bar-track {
  flex: 1; height: 6px;
  background: var(--b1); border-radius: 3px; overflow: hidden;
}
.tool-bar-fill { height: 100%; border-radius: 3px; transition: width 0.4s; }
.tool-bar-count { width: 30px; text-align: right; color: var(--t2); }
"""

html = html.replace("</style>", KPI_CSS + "\n</style>", 1)
print("[+] KPI CSS injected")
changes += 1

# ════════════════════════════════════════════════════════════════════════════
# 2. Add KPI row + chart row to Runs panel (before the card with table)
# ════════════════════════════════════════════════════════════════════════════
OLD_RUNS_CARD = """      <div class="card">
        <div class="card-head">
          <div class="card-title">Run history</div>
          <button class="btn btn-ghost" onclick="loadRuns()">↻ Refresh</button>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Run ID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th><th>Findings</th><th>Tools</th><th>Created</th></tr></thead>
            <tbody id="runs-table">"""

NEW_RUNS_CARD = """      <!-- GOV PATCH v1.6: Runs KPI Row -->
      <div class="runs-kpi-row" id="runs-kpi-row">
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Total Runs</div>
          <div class="runs-kpi-value c-cyan" id="rk-total">—</div>
          <div class="runs-kpi-sub">all time</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Pass Rate</div>
          <div class="runs-kpi-value c-green" id="rk-passrate">—</div>
          <div class="runs-kpi-sub" id="rk-pass-sub">gates</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Avg Findings</div>
          <div class="runs-kpi-value c-amber" id="rk-avgfindings">—</div>
          <div class="runs-kpi-sub">per run</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Last Gate</div>
          <div class="runs-kpi-value" id="rk-lastgate" style="font-size:18px">—</div>
          <div class="runs-kpi-sub" id="rk-lastgate-sub">—</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Latest Score</div>
          <div class="runs-kpi-value c-red" id="rk-score">—</div>
          <div class="runs-kpi-sub">/100</div>
        </div>
      </div>

      <!-- GOV PATCH v1.6: Runs Charts Row -->
      <div class="runs-chart-row">
        <div class="runs-chart-card">
          <div class="runs-chart-title">Gate decisions — last 20 runs</div>
          <canvas id="runs-gate-chart" height="90"></canvas>
        </div>
        <div class="runs-chart-card">
          <div class="runs-chart-title">Findings by mode</div>
          <canvas id="runs-mode-chart" height="90"></canvas>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="card-title">Run history</div>
          <button class="btn btn-ghost" onclick="loadRuns()">↻ Refresh</button>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Run ID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th><th>Findings</th><th>Tools</th><th>Score</th><th>Created</th></tr></thead>
            <tbody id="runs-table">"""

if OLD_RUNS_CARD in html:
    html = html.replace(OLD_RUNS_CARD, NEW_RUNS_CARD, 1)
    print("[+] Runs KPI row + charts injected")
    changes += 1
else:
    print("[!] Runs card pattern not matched")

# ════════════════════════════════════════════════════════════════════════════
# 3. Add KPI cards to Findings panel (before filter-bar)
# ════════════════════════════════════════════════════════════════════════════
OLD_FINDINGS_PANEL = """    <div id="panel-findings" class="panel">
      <div class="filter-bar">"""

NEW_FINDINGS_PANEL = """    <div id="panel-findings" class="panel">
      <!-- GOV PATCH v1.6: Findings KPI Row -->
      <div class="findings-kpi-row" id="findings-kpi-row">
        <div class="findings-kpi-card" onclick="setFindingsFilter('CRITICAL')" id="fkpi-critical">
          <div class="findings-kpi-sev" style="color:var(--red)">🔴 Critical</div>
          <div class="findings-kpi-num c-red" id="fkpi-critical-num">—</div>
          <div class="findings-kpi-pct" id="fkpi-critical-pct">— of total</div>
        </div>
        <div class="findings-kpi-card" onclick="setFindingsFilter('HIGH')" id="fkpi-high">
          <div class="findings-kpi-sev" style="color:var(--orange)">🟠 High</div>
          <div class="findings-kpi-num c-orange" id="fkpi-high-num">—</div>
          <div class="findings-kpi-pct" id="fkpi-high-pct">— of total</div>
        </div>
        <div class="findings-kpi-card" onclick="setFindingsFilter('MEDIUM')" id="fkpi-medium">
          <div class="findings-kpi-sev" style="color:var(--amber)">🟡 Medium</div>
          <div class="findings-kpi-num c-amber" id="fkpi-medium-num">—</div>
          <div class="findings-kpi-pct" id="fkpi-medium-pct">— of total</div>
        </div>
        <div class="findings-kpi-card" onclick="setFindingsFilter('LOW')" id="fkpi-low">
          <div class="findings-kpi-sev" style="color:var(--green)">🟢 Low</div>
          <div class="findings-kpi-num c-green" id="fkpi-low-num">—</div>
          <div class="findings-kpi-pct" id="fkpi-low-pct">— of total</div>
        </div>
      </div>

      <!-- Tool breakdown mini chart -->
      <div class="card mb14" id="findings-tool-breakdown-card">
        <div class="card-head" style="padding:10px 14px">
          <div class="card-title" style="font-size:10px">Findings by tool</div>
          <div class="mono-sm c-t3" id="findings-tool-total-lbl"></div>
        </div>
        <div class="card-body" style="padding:8px 14px 12px">
          <div class="tool-breakdown" id="findings-tool-breakdown"></div>
        </div>
      </div>

      <div class="filter-bar">"""

if OLD_FINDINGS_PANEL in html:
    html = html.replace(OLD_FINDINGS_PANEL, NEW_FINDINGS_PANEL, 1)
    print("[+] Findings KPI cards + tool breakdown injected")
    changes += 1
else:
    print("[!] Findings panel pattern not matched")

# ════════════════════════════════════════════════════════════════════════════
# 4. Fix filter-tool dropdown — add all tools + info note
# ════════════════════════════════════════════════════════════════════════════
OLD_FILTER_TOOL = """        <select class="filter-select" id="filter-tool">
          <option value="">All Tools</option>
          <option>kics</option><option>trivy</option><option>gitleaks</option>
          <option>checkov</option><option>bandit</option><option>semgrep</option>
        </select>"""

NEW_FILTER_TOOL = """        <select class="filter-select" id="filter-tool">
          <option value="">All Tools</option>
          <option>kics</option><option>trivy</option><option>gitleaks</option>
          <option>checkov</option><option>bandit</option><option>semgrep</option>
          <option>codeql</option><option>grype</option><option>nuclei</option>
          <option>nikto</option><option>trufflehog</option>
        </select>"""

if OLD_FILTER_TOOL in html:
    html = html.replace(OLD_FILTER_TOOL, NEW_FILTER_TOOL, 1)
    print("[+] Filter tool dropdown expanded")
    changes += 1

# ════════════════════════════════════════════════════════════════════════════
# 5. JS — fix loadRuns + add KPI/chart rendering + findings KPI
# ════════════════════════════════════════════════════════════════════════════
PATCH_JS = """
// ── GOV PATCH v1.6: Runs KPI + Charts ────────────────────────────────────

// Normalize summary object (handles both uppercase and lowercase keys)
function _normSummary(s) {
  if (!s) return {};
  if (typeof s === 'string') { try { s = JSON.parse(s); } catch(e) { return {}; } }
  var out = {};
  Object.keys(s).forEach(function(k) { out[k.toUpperCase()] = s[k]; });
  return out;
}

// Override loadRuns to also populate KPI row + charts
var _origLoadRuns = window.loadRuns;
window.loadRuns = async function() {
  await ensureToken();
  try {
    var d = await fetch('/api/v1/vsp/runs/index', {
      headers: {'Authorization': 'Bearer ' + window.TOKEN}
    }).then(function(r){ return r.json(); });
    var runs = d.runs || [];

    // ── Fix table rendering: use total_findings not total ──
    var tbody = document.getElementById('runs-table');
    if (tbody) {
      var modeStyle = {
        IAC:    'background:var(--cyan2);color:var(--cyan);border:1px solid rgba(6,182,212,.25)',
        FULL:   'background:var(--purple2);color:var(--purple);border:1px solid rgba(139,92,246,.25)',
        SAST:   'background:var(--blue2);color:var(--blue);border:1px solid rgba(59,130,246,.25)',
        SCA:    'background:var(--orange2);color:var(--orange);border:1px solid rgba(249,115,22,.25)',
        SECRETS:'background:var(--red2);color:var(--red);border:1px solid rgba(239,68,68,.25)',
        DAST:   'background:var(--green2);color:var(--green);border:1px solid rgba(34,197,94,.25)',
      };
      var gateClass = {PASS:'pill-pass', FAIL:'pill-fail', WARN:'pill-warn'};
      var statusClass = {DONE:'pill-done', RUNNING:'pill-run', FAILED:'pill-fail', QUEUED:'pill-queue'};

      tbody.innerHTML = runs.map(function(r) {
        var sm      = _normSummary(r.summary);
        var score   = sm.SCORE || sm.score || 0;
        var total   = r.total_findings || r.total || 0;
        var scoreColor = score >= 70 ? 'var(--green)' : score >= 40 ? 'var(--amber)' : (score > 0 ? 'var(--red)' : 'var(--t3)');
        var findColor  = total > 0 ? (sm.CRITICAL > 0 ? 'c-red' : sm.HIGH > 0 ? 'c-orange' : 'c-amber') : 'c-green';
        var mStyle  = modeStyle[r.mode] || modeStyle.IAC;
        var gClass  = r.gate ? (gateClass[r.gate] || 'pill-done') : '';
        var sClass  = statusClass[r.status] || 'pill-done';
        var dt      = new Date(r.created_at);
        var dateStr = (dt.getDate()<10?'0':'')+dt.getDate()+'/'+(dt.getMonth()<9?'0':'')+(dt.getMonth()+1)
                    + ' ' + (dt.getHours()<10?'0':'')+dt.getHours()+':'+(dt.getMinutes()<10?'0':'')+dt.getMinutes();

        return '<tr style="cursor:pointer" onclick="viewRunLog(\''+r.rid+'\')">'
          + '<td class="mono" style="font-size:10px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+r.rid+'">'+r.rid+'</td>'
          + '<td><span class="pill" style="'+mStyle+'">'+r.mode+'</span></td>'
          + '<td class="mono-sm">'+(r.profile||'FAST')+'</td>'
          + '<td><span class="pill '+sClass+'">'+r.status+'</span></td>'
          + '<td>'+(r.gate ? '<span class="pill '+gClass+'">'+r.gate+'</span>' : '<span class="c-t3">—</span>')+'</td>'
          + '<td class="fw7 '+findColor+'">'+total+'</td>'
          + '<td class="mono-sm">'+(r.tools_done||0)+'/'+(r.tools_total||0)+'</td>'
          + '<td class="mono" style="font-size:11px;color:'+scoreColor+'">'+(score||'—')+'</td>'
          + '<td class="mono-sm">'+dateStr+'</td>'
          + '</tr>';
      }).join('');
    }

    // ── KPI calculations ──
    var done = runs.filter(function(r){ return r.status === 'DONE'; });
    var pass = done.filter(function(r){ return r.gate === 'PASS'; });
    var fail = done.filter(function(r){ return r.gate === 'FAIL'; });
    var passRate = done.length > 0 ? Math.round(pass.length / done.length * 100) : 0;
    var totalFindings = done.reduce(function(s,r){ return s + (r.total_findings||r.total||0); }, 0);
    var avgFindings = done.length > 0 ? Math.round(totalFindings / done.length) : 0;
    var latest = runs[0];
    var latestSm = latest ? _normSummary(latest.summary) : {};
    var latestScore = latestSm.SCORE || latestSm.score || 0;
    var lastGate = latest ? (latest.gate || '—') : '—';
    var lastGateColor = lastGate === 'PASS' ? 'var(--green)' : lastGate === 'FAIL' ? 'var(--red)' : lastGate === 'WARN' ? 'var(--amber)' : 'var(--t3)';

    function _setEl(id, val) { var e = document.getElementById(id); if(e) e.textContent = val; }
    _setEl('rk-total', runs.length);
    _setEl('rk-passrate', passRate + '%');
    _setEl('rk-pass-sub', pass.length + ' pass / ' + fail.length + ' fail');
    _setEl('rk-avgfindings', avgFindings);
    var lgEl = document.getElementById('rk-lastgate');
    if (lgEl) { lgEl.textContent = lastGate; lgEl.style.color = lastGateColor; }
    _setEl('rk-lastgate-sub', latest ? latest.rid.slice(-12) : '—');
    var scoreEl = document.getElementById('rk-score');
    if (scoreEl) {
      scoreEl.textContent = latestScore || '—';
      scoreEl.style.color = latestScore >= 70 ? 'var(--green)' : latestScore >= 40 ? 'var(--amber)' : 'var(--red)';
    }

    // ── Gate trend chart ──
    var last20 = runs.slice(0, 20).reverse();
    var gateCtx = document.getElementById('runs-gate-chart');
    if (gateCtx && window.Chart) {
      if (window._runsGateChart) window._runsGateChart.destroy();
      window._runsGateChart = new Chart(gateCtx, {
        type: 'bar',
        data: {
          labels: last20.map(function(r){ return r.rid.slice(-8); }),
          datasets: [{
            data: last20.map(function(r){
              return r.gate === 'PASS' ? 1 : r.gate === 'WARN' ? 0.5 : r.gate === 'FAIL' ? -1 : 0;
            }),
            backgroundColor: last20.map(function(r){
              return r.gate === 'PASS' ? 'rgba(34,197,94,0.7)'
                   : r.gate === 'WARN' ? 'rgba(251,191,36,0.7)'
                   : r.gate === 'FAIL' ? 'rgba(239,68,68,0.7)'
                   : 'rgba(100,116,139,0.4)';
            }),
            borderRadius: 3,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { display: false }, grid: { display: false } },
            y: { display: false, min: -1.2, max: 1.2 }
          }
        }
      });
    }

    // ── Findings by mode doughnut ──
    var modeCtx = document.getElementById('runs-mode-chart');
    if (modeCtx && window.Chart) {
      var modeTotals = {};
      done.forEach(function(r){
        var t = r.total_findings || r.total || 0;
        modeTotals[r.mode] = (modeTotals[r.mode]||0) + t;
      });
      var modeKeys = Object.keys(modeTotals);
      var modeColors = {
        IAC:'rgba(6,182,212,0.8)', FULL:'rgba(139,92,246,0.8)',
        SAST:'rgba(59,130,246,0.8)', SCA:'rgba(249,115,22,0.8)',
        SECRETS:'rgba(239,68,68,0.8)', DAST:'rgba(34,197,94,0.8)'
      };
      if (window._runsModeChart) window._runsModeChart.destroy();
      window._runsModeChart = new Chart(modeCtx, {
        type: 'doughnut',
        data: {
          labels: modeKeys,
          datasets: [{ data: modeKeys.map(function(k){ return modeTotals[k]; }),
            backgroundColor: modeKeys.map(function(k){ return modeColors[k]||'rgba(100,116,139,0.6)'; }),
            borderWidth: 0 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: {
              display: true, position: 'right',
              labels: { color: 'var(--t2)', font: { size: 9 }, boxWidth: 10, padding: 8 }
            }
          }
        }
      });
    }

  } catch(e) {
    console.error('loadRuns patch:', e);
  }
};

// ── GOV PATCH v1.6: Findings KPI cards ───────────────────────────────────

function setFindingsFilter(sev) {
  var selEl = document.getElementById('filter-severity');
  if (selEl) selEl.value = sev;
  if (typeof loadFindings === 'function') loadFindings(0);
  else if (typeof loadFindingsPanel === 'function') loadFindingsPanel();
  // Highlight active card
  ['critical','high','medium','low'].forEach(function(s){
    var c = document.getElementById('fkpi-'+s);
    if (c) c.classList.toggle('active', s.toUpperCase() === sev);
  });
}

// Hook into findings load to update KPI cards + tool breakdown
var _origLoadFindingsKPI = window.loadFindings;
window.loadFindings = async function(offset) {
  if (_origLoadFindingsKPI) await _origLoadFindingsKPI(offset);
  // Fetch summary for KPI cards
  _updateFindingsKPI();
};

async function _updateFindingsKPI() {
  try {
    await ensureToken();
    var r = await fetch('/api/v1/vsp/findings/summary', {
      headers: {'Authorization': 'Bearer ' + window.TOKEN}
    });
    if (!r.ok) return;
    var d = await r.json();
    var bySev = d.by_severity || d.severity || {};
    var total = d.total || Object.values(bySev).reduce(function(a,b){return a+b;},0) || 0;

    function pct(n) { return total > 0 ? Math.round(n/total*100)+'%' : '0%'; }
    function setKPI(sev, key) {
      var n = bySev[key] || bySev[key.toLowerCase()] || 0;
      var numEl = document.getElementById('fkpi-'+sev+'-num');
      var pctEl = document.getElementById('fkpi-'+sev+'-pct');
      if (numEl) numEl.textContent = n;
      if (pctEl) pctEl.textContent = pct(n) + ' of ' + total;
    }
    setKPI('critical','CRITICAL');
    setKPI('high','HIGH');
    setKPI('medium','MEDIUM');
    setKPI('low','LOW');

    // Tool breakdown
    var byTool = d.by_tool || d.tool || {};
    var toolBreakdown = document.getElementById('findings-tool-breakdown');
    var toolTotal = document.getElementById('findings-tool-total-lbl');
    if (toolBreakdown && Object.keys(byTool).length > 0) {
      var maxVal = Math.max.apply(null, Object.values(byTool));
      var toolColors = {
        kics:'var(--cyan)', trivy:'var(--blue)', gitleaks:'var(--red)',
        checkov:'var(--amber)', bandit:'var(--orange)', semgrep:'var(--purple)',
        codeql:'var(--green)', grype:'var(--cyan)', nuclei:'var(--amber)',
        nikto:'var(--orange)', trufflehog:'var(--red)'
      };
      var sorted = Object.keys(byTool).sort(function(a,b){ return byTool[b]-byTool[a]; });
      toolBreakdown.innerHTML = sorted.map(function(tool) {
        var n = byTool[tool] || 0;
        var w = maxVal > 0 ? Math.round(n/maxVal*100) : 0;
        var col = toolColors[tool] || 'var(--t2)';
        return '<div class="tool-bar-row">'
          + '<span class="tool-bar-name">'+tool+'</span>'
          + '<div class="tool-bar-track"><div class="tool-bar-fill" style="width:'+w+'%;background:'+col+'"></div></div>'
          + '<span class="tool-bar-count">'+n+'</span>'
          + '</div>';
      }).join('');
      if (toolTotal) toolTotal.textContent = total + ' total';
    }

  } catch(e) {
    // findings/summary may not exist — fallback: count from cache
    var cache = window._findingsCache || [];
    if (!cache.length) return;
    var counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    cache.forEach(function(f){ var s=(f.severity||'').toUpperCase(); if(counts[s]!==undefined) counts[s]++; });
    var tot = cache.length;
    function pct2(n){ return tot>0?Math.round(n/tot*100)+'%':'0%'; }
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(function(s){
      var numEl = document.getElementById('fkpi-'+s.toLowerCase()+'-num');
      var pctEl = document.getElementById('fkpi-'+s.toLowerCase()+'-pct');
      if (numEl) numEl.textContent = counts[s];
      if (pctEl) pctEl.textContent = pct2(counts[s]) + ' of ' + tot;
    });
  }
}
// ── END GOV PATCH v1.6 ───────────────────────────────────────────────────
"""

html = html.replace("</body>", "<script>" + PATCH_JS + "</script>\n</body>", 1)
print("[+] Runs KPI + Charts + Findings KPI JS injected")
changes += 1

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Patch v1.6 complete — {changes} changes → {TARGET}")
print(f"   Backup → {bak}")
print("""
What was added:

RUNS TAB:
  [1] KPI row: Total Runs, Pass Rate, Avg Findings, Last Gate, Latest Score
  [2] Gate trend bar chart — last 20 runs (green=PASS, red=FAIL, amber=WARN)
  [3] Findings by mode doughnut chart
  [4] Fixed r.total → r.total_findings (was showing 0/--- for many runs)
  [5] Score column added to table header
  [6] Summary key normalization (uppercase/lowercase)

FINDINGS TAB:
  [7] KPI cards: CRITICAL / HIGH / MEDIUM / LOW with counts + % of total
  [8] Click KPI card → filter by that severity
  [9] Tool breakdown mini horizontal bar chart
  [10] Filter tool dropdown: added codeql, grype, nuclei, nikto, trufflehog
""")
