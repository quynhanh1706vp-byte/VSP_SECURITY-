#!/usr/bin/env bash
# VSP Dashboard v2 — Chart.js D3-style charts
# Chay tu ~/Data/GOLANG_VSP
set -e
echo ">>> Installing Chart.js dashboard"
mkdir -p static
cat > 'static/index.html' << 'VSP_DASH_V2_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VSP Security Platform</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
  /* Nav */
  .nav { background: #1e293b; border-bottom: 1px solid #334155; padding: 0 24px;
         display: flex; align-items: center; gap: 32px; height: 56px; }
  .nav-brand { color: #38bdf8; font-weight: 700; font-size: 18px; letter-spacing: 1px; }
  .nav-tabs { display: flex; gap: 4px; }
  .tab { padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px;
         color: #94a3b8; border: none; background: none; transition: all .15s; }
  .tab:hover { color: #e2e8f0; background: #334155; }
  .tab.active { color: #38bdf8; background: #0f2744; }
  .nav-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
  .badge { padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 600; }
  .badge-green { background: #14532d; color: #4ade80; }
  .badge-red   { background: #7f1d1d; color: #fca5a5; }
  .badge-yellow{ background: #713f12; color: #fbbf24; }
  /* Layout */
  .main { padding: 24px; max-width: 1400px; margin: 0 auto; }
  /* Cards */
  .grid4 { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 24px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
  .card-title { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 8px; }
  .card-value { font-size: 32px; font-weight: 700; }
  .card-sub { font-size: 12px; color: #64748b; margin-top: 4px; }
  .c-crit { color: #f87171; } .c-high { color: #fb923c; }
  .c-med  { color: #fbbf24; } .c-low  { color: #4ade80; }
  .c-pass { color: #4ade80; } .c-warn { color: #fbbf24; } .c-fail { color: #f87171; }
  /* Table */
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; color: #64748b; border-bottom: 1px solid #334155;
       font-size: 11px; text-transform: uppercase; }
  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; }
  tr:hover td { background: #1e293b; }
  /* Buttons */
  .btn { padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer;
         font-size: 13px; font-weight: 500; transition: all .15s; }
  .btn-primary { background: #2563eb; color: #fff; }
  .btn-primary:hover { background: #1d4ed8; }
  .btn-sm { padding: 4px 10px; font-size: 12px; border-radius: 6px; }
  .btn-outline { background: none; border: 1px solid #334155; color: #94a3b8; }
  .btn-outline:hover { border-color: #64748b; color: #e2e8f0; }
  /* Login */
  .login-wrap { display: flex; align-items: center; justify-content: center;
                min-height: 100vh; background: #0f172a; }
  .login-card { background: #1e293b; border: 1px solid #334155; border-radius: 16px;
                padding: 40px; width: 360px; }
  .login-title { font-size: 22px; font-weight: 700; color: #38bdf8; margin-bottom: 24px; text-align: center; }
  .form-group { margin-bottom: 16px; }
  .form-label { font-size: 12px; color: #94a3b8; margin-bottom: 6px; display: block; }
  .form-input { width: 100%; padding: 10px 12px; background: #0f172a; border: 1px solid #334155;
                border-radius: 8px; color: #e2e8f0; font-size: 14px; outline: none; }
  .form-input:focus { border-color: #38bdf8; }
  .error-msg { color: #f87171; font-size: 13px; margin-top: 8px; text-align: center; }
  /* Section header */
  .section-head { display: flex; align-items: center; justify-content: space-between;
                  margin-bottom: 16px; }
  .section-title { font-size: 16px; font-weight: 600; color: #f1f5f9; }
  /* Status pill */
  .pill { padding: 2px 8px; border-radius: 99px; font-size: 11px; font-weight: 600; }
  .pill-queued  { background: #1e3a5f; color: #60a5fa; }
  .pill-running { background: #1c3a2a; color: #34d399; }
  .pill-done    { background: #14532d; color: #4ade80; }
  .pill-failed  { background: #7f1d1d; color: #fca5a5; }
  .pill-pass    { background: #14532d; color: #4ade80; }
  .pill-warn    { background: #713f12; color: #fbbf24; }
  .pill-fail    { background: #7f1d1d; color: #fca5a5; }
  /* Trigger form */
  .trigger-form { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
  .trigger-form select, .trigger-form input {
    padding: 8px 12px; background: #0f172a; border: 1px solid #334155;
    border-radius: 8px; color: #e2e8f0; font-size: 13px; outline: none; }
  .trigger-form select:focus, .trigger-form input:focus { border-color: #38bdf8; }
  /* Spinner */
  @keyframes spin { to { transform: rotate(360deg); } }
  .spin { animation: spin .8s linear infinite; display: inline-block; }
  /* Panel visibility */
  .panel { display: none; }
  .panel.active { display: block; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>

<!-- Login Screen -->
<div id="loginScreen" class="login-wrap">
  <div class="login-card">
    <div class="login-title">⬡ VSP Platform</div>
    <div class="form-group">
      <label class="form-label">Email</label>
      <input id="loginEmail" class="form-input" type="email" value="admin@vsp.local" placeholder="admin@vsp.local">
    </div>
    <div class="form-group">
      <label class="form-label">Password</label>
      <input id="loginPassword" class="form-input" type="password" value="admin123" placeholder="password">
    </div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" onclick="doLogin()">Sign In</button>
    <div id="loginError" class="error-msg"></div>
  </div>
</div>

<!-- Main App -->
<div id="appScreen" style="display:none">
  <nav class="nav">
    <span class="nav-brand">⬡ VSP</span>
    <div class="nav-tabs">
      <button class="tab active" onclick="showPanel('dashboard',this)">Dashboard</button>
      <button class="tab" onclick="showPanel('runs',this)">Runs</button>
      <button class="tab" onclick="showPanel('findings',this)">Findings</button>
      <button class="tab" onclick="showPanel('policy',this)">Policy</button>
      <button class="tab" onclick="showPanel('audit',this)">Audit</button>
      <button class="tab" onclick="showPanel('governance',this)">Governance</button>
      <button class="tab" onclick="showPanel('soc',this)">SOC</button>
      <button class="tab" onclick="showPanel('export',this)">Export</button>
    </div>
    <div class="nav-right">
      <span id="gateWidget" class="badge badge-green">PASS</span>
      <span id="userWidget" class="badge" style="background:#1e293b;color:#94a3b8">—</span>
      <button class="btn btn-sm btn-outline" onclick="doLogout()">Logout</button>
    </div>
  </nav>

  <div class="main">

    <!-- Dashboard -->
    <div id="panel-dashboard" class="panel active">
      <div class="grid4">
        <div class="card">
          <div class="card-title">Security Score</div>
          <div class="card-value c-pass" id="d-score">—</div>
          <div class="card-sub">out of 100</div>
        </div>
        <div class="card">
          <div class="card-title">Posture Grade</div>
          <div class="card-value c-pass" id="d-posture">—</div>
          <div class="card-sub">latest run</div>
        </div>
        <div class="card">
          <div class="card-title">Total Runs</div>
          <div class="card-value" id="d-runs">—</div>
          <div class="card-sub">all time</div>
        </div>
        <div class="card">
          <div class="card-title">Gate Decision</div>
          <div class="card-value" id="d-gate">—</div>
          <div class="card-sub">latest</div>
        </div>
      </div>
      <div class="grid4">
        <div class="card">
          <div class="card-title">Critical</div>
          <div class="card-value c-crit" id="d-critical">0</div>
        </div>
        <div class="card">
          <div class="card-title">High</div>
          <div class="card-value c-high" id="d-high">0</div>
        </div>
        <div class="card">
          <div class="card-title">Medium</div>
          <div class="card-value c-med" id="d-medium">0</div>
        </div>
        <div class="card">
          <div class="card-title">Low</div>
          <div class="card-value c-low" id="d-low">0</div>
        </div>
      </div>

      <!-- Premium Charts -->
      <div class="grid2" style="margin-bottom:20px">
        <div class="card">
          <div class="section-head">
            <span class="section-title">Findings — latest run</span>
            <span style="font-size:11px;color:#64748b" id="chart-run-label"></span>
          </div>
          <canvas id="chartSeverity" height="160"></canvas>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Posture trend — last 10 runs</span></div>
          <canvas id="chartTrend" height="160"></canvas>
        </div>
      </div>
      <div class="grid2" style="margin-bottom:20px">
        <div class="card">
          <div class="section-head"><span class="section-title">Findings by tool</span></div>
          <canvas id="chartTools" height="160"></canvas>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Gate decisions — history</span></div>
          <canvas id="chartGates" height="160"></canvas>
        </div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Recent Runs</span>
          <button class="btn btn-sm btn-primary" onclick="showPanel('runs',null);showTrigger()">+ New Scan</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>RID</th><th>Mode</th><th>Status</th><th>Gate</th><th>Findings</th><th>Created</th></tr></thead>
            <tbody id="d-runs-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Runs -->
    <div id="panel-runs" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-head">
          <span class="section-title">Trigger New Scan</span>
        </div>
        <div class="trigger-form">
          <div>
            <div class="form-label">Mode</div>
            <select id="scanMode">
              <option>SAST</option><option>SCA</option><option>SECRETS</option>
              <option>IAC</option><option>DAST</option><option>FULL</option>
            </select>
          </div>
          <div>
            <div class="form-label">Profile</div>
            <select id="scanProfile">
              <option>FAST</option><option>EXT</option><option>FULL</option>
            </select>
          </div>
          <div style="flex:1;min-width:200px">
            <div class="form-label">Source Path</div>
            <input id="scanSrc" type="text" placeholder="/path/to/code" style="width:100%">
          </div>
          <button class="btn btn-primary" onclick="triggerScan()">Run Scan</button>
        </div>
        <div id="triggerMsg" style="margin-top:10px;font-size:13px;color:#4ade80"></div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Run History</span>
          <button class="btn btn-sm btn-outline" onclick="loadRuns()">↻ Refresh</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>RID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th>
              <th>Findings</th><th>Tools</th><th>Created</th></tr></thead>
            <tbody id="runs-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Findings -->
    <div id="panel-findings" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <select id="filterSev" onchange="loadFindings()" style="padding:6px 10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:13px">
            <option value="">All severities</option>
            <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
          </select>
          <select id="filterTool" onchange="loadFindings()" style="padding:6px 10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:13px">
            <option value="">All tools</option>
            <option>bandit</option><option>semgrep</option><option>grype</option>
            <option>trivy</option><option>gitleaks</option><option>kics</option>
          </select>
          <input id="filterQ" type="text" placeholder="Search…" onkeyup="if(event.key==='Enter')loadFindings()"
            style="padding:6px 10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:13px;width:200px">
          <button class="btn btn-sm btn-primary" onclick="loadFindings()">Search</button>
          <span id="findings-count" style="color:#64748b;font-size:13px;margin-left:auto"></span>
        </div>
      </div>
      <div class="card">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Message</th><th>Path</th><th>Line</th><th>CWE</th></tr></thead>
            <tbody id="findings-table"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Policy -->
    <div id="panel-policy" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-head">
          <span class="section-title">Gate Evaluation</span>
          <button class="btn btn-primary btn-sm" onclick="runEval()">Evaluate Latest Run</button>
        </div>
        <div id="eval-result" style="margin-top:12px;font-size:14px"></div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Policy Rules</span>
          <button class="btn btn-sm btn-outline" onclick="loadRules()">↻ Refresh</button>
        </div>
        <div id="rules-list" style="color:#64748b;font-size:13px">Loading…</div>
      </div>
    </div>

    <!-- Audit -->
    <div id="panel-audit" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-head">
          <span class="section-title">Hash Chain Integrity</span>
          <button class="btn btn-sm btn-primary" onclick="verifyAudit()">Verify Chain</button>
        </div>
        <div id="verify-result" style="font-size:14px;color:#64748b">Click verify to check chain integrity.</div>
      </div>
      <div class="card">
        <div class="section-head">
          <span class="section-title">Audit Log</span>
          <button class="btn btn-sm btn-outline" onclick="loadAudit()">↻ Refresh</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Seq</th><th>Action</th><th>Resource</th><th>IP</th><th>Time</th><th>Hash</th></tr></thead>
            <tbody id="audit-table"></tbody>
          </table>
        </div>
      </div>
    </div>


    <!-- Governance Panel -->
    <div id="panel-governance" class="panel">
      <div class="grid4" style="grid-template-columns:repeat(2,1fr)">
        <div class="card">
          <div class="section-head"><span class="section-title">Risk Register</span><button class="btn btn-sm btn-outline" onclick="loadRiskRegister()">Refresh</button></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Level</th><th>Title</th><th>Status</th><th>Due</th></tr></thead>
            <tbody id="risk-table"><tr><td colspan="4" style="color:#64748b;padding:16px">Loading...</td></tr></tbody>
          </table></div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Traceability Matrix</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Severity</th><th>Rule</th><th>Control</th><th>Framework</th></tr></thead>
            <tbody id="trace-table"></tbody>
          </table></div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">RACI Governance</span></div>
          <div id="raci-list" style="font-size:13px">Loading...</div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Control Ownership</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Control</th><th>Owner</th><th>Status</th></tr></thead>
            <tbody id="ownership-table"></tbody>
          </table></div>
        </div>
      </div>
    </div>

    <!-- SOC Panel -->
    <div id="panel-soc" class="panel">
      <div class="grid4" style="grid-template-columns:repeat(2,1fr)">
        <div class="card">
          <div class="section-head"><span class="section-title">Framework Scorecard</span></div>
          <div id="scorecard-list">Loading...</div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Zero Trust — 7 Pillars</span></div>
          <div id="zerotrust-list">Loading...</div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">Security Roadmap</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Quarter</th><th>Title</th><th>Priority</th><th>Status</th></tr></thead>
            <tbody id="roadmap-table"></tbody>
          </table></div>
        </div>
        <div class="card">
          <div class="section-head"><span class="section-title">SOC Incidents</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>ID</th><th>Severity</th><th>Title</th></tr></thead>
            <tbody id="incidents-table"></tbody>
          </table></div>
        </div>
      </div>
    </div>

    <!-- Export Panel -->
    <div id="panel-export" class="panel">
      <div class="card" style="margin-bottom:16px">
        <div class="section-title" style="margin-bottom:12px">Export Latest Run</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-primary" onclick="exportFile('sarif')">Download SARIF 2.1.0</button>
          <button class="btn btn-primary" onclick="exportFile('csv')">Download CSV</button>
          <button class="btn btn-primary" onclick="exportFile('json')">Download JSON</button>
        </div>
        <div id="export-rid" style="margin-top:10px;font-size:12px;color:#64748b"></div>
      </div>
      <div class="grid4" style="grid-template-columns:repeat(2,1fr)">
        <div class="card">
          <div class="section-head">
            <span class="section-title">OSCAL Assessment Result</span>
            <button class="btn btn-sm btn-outline" onclick="downloadOSCAL('ar')">Download</button>
          </div>
          <pre id="oscal-ar-preview" style="font-size:11px;color:#94a3b8;overflow:auto;max-height:200px;white-space:pre-wrap"></pre>
        </div>
        <div class="card">
          <div class="section-head">
            <span class="section-title">OSCAL POA&amp;M</span>
            <button class="btn btn-sm btn-outline" onclick="downloadOSCAL('poam')">Download</button>
          </div>
          <pre id="oscal-poam-preview" style="font-size:11px;color:#94a3b8;overflow:auto;max-height:200px;white-space:pre-wrap"></pre>
        </div>
      </div>
    </div>

  </div><!-- main -->
</div><!-- appScreen -->

<script>
const API = '/api/v1'
let TOKEN = localStorage.getItem('vsp_token') || ''
let USER  = JSON.parse(localStorage.getItem('vsp_user') || '{}')

// ── Auth ────────────────────────────────────────────────────────────────────
async function doLogin() {
  const email    = document.getElementById('loginEmail').value
  const password = document.getElementById('loginPassword').value
  const err      = document.getElementById('loginError')
  try {
    const r = await api('POST', '/auth/login', {email, password}, true)
    TOKEN = r.token
    USER  = {email: r.email, role: r.role, tenant_id: r.tenant_id}
    localStorage.setItem('vsp_token', TOKEN)
    localStorage.setItem('vsp_user', JSON.stringify(USER))
    showApp()
  } catch(e) {
    err.textContent = 'Login failed: ' + (e.message || 'check credentials')
  }
}

function doLogout() {
  api('POST', '/auth/logout').catch(()=>{})
  localStorage.removeItem('vsp_token')
  localStorage.removeItem('vsp_user')
  TOKEN = ''
  document.getElementById('appScreen').style.display = 'none'
  document.getElementById('loginScreen').style.display = 'flex'
}

function showApp() {
  document.getElementById('loginScreen').style.display = 'none'
  document.getElementById('appScreen').style.display   = 'block'
  document.getElementById('userWidget').textContent = USER.email + ' [' + (USER.role||'') + ']'
  loadDashboard()
  loadDashboardCharts()
  startPolling()
}

// ── API helper ────────────────────────────────────────────────────────────────
async function api(method, path, body, noAuth) {
  const opts = { method, headers: {'Content-Type':'application/json'} }
  if (!noAuth && TOKEN) opts.headers['Authorization'] = 'Bearer ' + TOKEN
  if (body) opts.body = JSON.stringify(body)
  const r = await fetch(API + path, opts)
  if (r.status === 401) { doLogout(); throw new Error('session expired') }
  const data = await r.json()
  if (!r.ok) throw new Error(data.error || r.statusText)
  return data
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPanel(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'))
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
  document.getElementById('panel-' + name).classList.add('active')
  if (btn) btn.classList.add('active')
  else document.querySelectorAll('.tab').forEach(t => {
    if (t.textContent.toLowerCase() === name) t.classList.add('active')
  })
  if (name === 'runs')     loadRuns()
  if (name === 'findings') loadFindings()
  if (name === 'audit')      loadAudit()
  if (name === 'dashboard')  loadDashboardCharts()
  if (name === 'governance') { loadRiskRegister(); loadTraceability(); loadRACI(); loadOwnership() }
  if (name === 'soc')        { loadScorecard(); loadZeroTrust(); loadRoadmap(); loadIncidents() }
  if (name === 'export')     loadExport()
  if (name === 'policy')   loadRules()
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard()
  loadDashboardCharts() {
  try {
    const [summary, posture, runs] = await Promise.all([
      api('GET', '/vsp/findings/summary'),
      api('GET', '/vsp/posture/latest').catch(()=>null),
      api('GET', '/vsp/runs/index'),
    ])
    document.getElementById('d-critical').textContent = summary.critical
    document.getElementById('d-high').textContent     = summary.high
    document.getElementById('d-medium').textContent   = summary.medium
    document.getElementById('d-low').textContent      = summary.low
    if (posture) {
      const sc = document.getElementById('d-score')
      sc.textContent = posture.score
      sc.className   = 'card-value ' + (posture.score >= 80 ? 'c-pass' : posture.score >= 50 ? 'c-warn' : 'c-fail')
      document.getElementById('d-posture').textContent = posture.grade
      const gw = document.getElementById('d-gate')
      const rg = posture.grade
      gw.textContent = rg
      // nav badge
      const nb = document.getElementById('gateWidget')
    }
    const runList = runs.runs || []
    document.getElementById('d-runs').textContent = runList.length
    const tbody = document.getElementById('d-runs-table')
    tbody.innerHTML = runList.slice(0,5).map(r => `
      <tr>
        <td style="font-family:monospace;font-size:12px">${r.rid}</td>
        <td>${r.mode}</td>
        <td>${statusPill(r.status)}</td>
        <td>${r.gate ? gatePill(r.gate) : '—'}</td>
        <td>${r.total}</td>
        <td style="color:#64748b">${fmtDate(r.created_at)}</td>
      </tr>`).join('')
  } catch(e) { console.error('dashboard', e) }
}

// ── Runs ──────────────────────────────────────────────────────────────────────
async function loadRuns() {
  try {
    const data = await api('GET', '/vsp/runs?limit=50')
    const runs = data.runs || []
    document.getElementById('runs-table').innerHTML = runs.map(r => `
      <tr>
        <td style="font-family:monospace;font-size:12px">${r.rid}</td>
        <td>${r.mode}</td><td>${r.profile}</td>
        <td>${statusPill(r.status)}</td>
        <td>${r.gate ? gatePill(r.gate) : '—'}</td>
        <td>${r.total_findings}</td>
        <td>${r.tools_done}/${r.tools_total}</td>
        <td style="color:#64748b">${fmtDate(r.created_at)}</td>
      </tr>`).join('')
  } catch(e) { console.error('runs', e) }
}

async function triggerScan() {
  const mode    = document.getElementById('scanMode').value
  const profile = document.getElementById('scanProfile').value
  const src     = document.getElementById('scanSrc').value
  const msg     = document.getElementById('triggerMsg')
  if (!src) { msg.style.color='#f87171'; msg.textContent='Source path required'; return }
  try {
    msg.style.color='#94a3b8'; msg.textContent='⏳ Triggering...'
    const r = await api('POST', '/vsp/run', {mode, profile, src})
    msg.style.color='#4ade80'
    msg.textContent='✓ ' + r.rid + ' — ' + r.message
    setTimeout(loadRuns, 500)
    setTimeout(loadDashboard, 1000)
  } catch(e) {
    msg.style.color='#f87171'; msg.textContent='Error: ' + e.message
  }
}

function showTrigger() {
  document.getElementById('scanSrc').focus()
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings() {
  const sev  = document.getElementById('filterSev').value
  const tool = document.getElementById('filterTool').value
  const q    = document.getElementById('filterQ').value
  let path   = '/vsp/findings?limit=100'
  if (sev)  path += '&severity=' + sev
  if (tool) path += '&tool=' + tool
  if (q)    path += '&q=' + encodeURIComponent(q)
  try {
    const data = await api('GET', path)
    const findings = data.findings || []
    document.getElementById('findings-count').textContent = data.total + ' findings'
    document.getElementById('findings-table').innerHTML = findings.map(f => `
      <tr>
        <td>${sevPill(f.severity)}</td>
        <td style="color:#94a3b8">${f.tool}</td>
        <td style="font-family:monospace;font-size:11px;color:#60a5fa">${f.rule_id||'—'}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${esc(f.message)}">${esc(f.message)||'—'}</td>
        <td style="font-family:monospace;font-size:11px;color:#94a3b8">${esc(f.path)||'—'}</td>
        <td style="color:#64748b">${f.line||'—'}</td>
        <td style="font-size:11px;color:#818cf8">${f.cwe||'—'}</td>
      </tr>`).join('')
  } catch(e) { console.error('findings', e) }
}

// ── Policy ────────────────────────────────────────────────────────────────────
async function runEval() {
  try {
    const r = await api('POST', '/policy/evaluate', {repo: 'current'})
    const color = r.decision==='PASS' ? '#4ade80' : r.decision==='WARN' ? '#fbbf24' : '#f87171'
    document.getElementById('eval-result').innerHTML =
      `<span style="color:${color};font-size:20px;font-weight:700">${r.decision}</span>
       &nbsp; score: <b>${r.score}</b> &nbsp; posture: <b>${r.posture}</b>
       &nbsp; <span style="color:#64748b">${r.reason}</span>`
  } catch(e) {
    document.getElementById('eval-result').textContent = 'Error: ' + e.message
  }
}

async function loadRules() {
  try {
    const data = await api('GET', '/policy/rules')
    const rules = data.rules || []
    if (!rules.length) {
      document.getElementById('rules-list').innerHTML =
        '<span style="color:#64748b">No custom rules — using default policy (block critical + secrets).</span>'
      return
    }
    document.getElementById('rules-list').innerHTML = rules.map(r =>
      `<div style="padding:12px;border:1px solid #334155;border-radius:8px;margin-bottom:8px">
        <b>${r.name}</b> &nbsp;
        <span class="pill pill-pass">${r.fail_on}</span> &nbsp;
        max_high: ${r.max_high === -1 ? '∞' : r.max_high} &nbsp;
        min_score: ${r.min_score} &nbsp;
        <span style="color:#64748b">pattern: ${r.repo_pattern}</span>
       </div>`).join('')
  } catch(e) { console.error('rules', e) }
}

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit() {
  try {
    const data = await api('GET', '/audit/log?limit=50')
    const entries = data.entries || []
    document.getElementById('audit-table').innerHTML = entries.map(e =>
      `<tr>
        <td style="color:#64748b">${e.seq}</td>
        <td style="color:#60a5fa">${e.action}</td>
        <td style="font-family:monospace;font-size:12px">${e.resource||'—'}</td>
        <td style="color:#64748b;font-size:12px">${e.ip||'—'}</td>
        <td style="color:#64748b">${fmtDate(e.created_at)}</td>
        <td style="font-family:monospace;font-size:10px;color:#334155">${(e.hash||'').slice(0,16)}…</td>
       </tr>`).join('')
  } catch(e) { console.error('audit', e) }
}

async function verifyAudit() {
  const el = document.getElementById('verify-result')
  el.textContent = '⏳ Verifying...'
  try {
    const r = await api('POST', '/audit/verify')
    el.innerHTML = r.ok
      ? `<span style="color:#4ade80">✓ Chain intact</span> — ${r.checked} entries verified`
      : `<span style="color:#f87171">✗ Chain broken</span> at seq ${r.broken_at_seq}: ${r.error}`
  } catch(e) { el.textContent = 'Error: ' + e.message }
}

// ── Polling ────────────────────────────────────────────────────────────────────
function startPolling() {
  setInterval(() => {
    const active = document.querySelector('.panel.active')?.id
    if (active === 'panel-dashboard') loadDashboard()
  loadDashboardCharts()
    if (active === 'panel-runs')      loadRuns()
  }, 6000)
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function statusPill(s) {
  const m = {QUEUED:'queued',RUNNING:'running',DONE:'done',FAILED:'failed',CANCELLED:'queued'}
  return `<span class="pill pill-${m[s]||'queued'}">${s}</span>`
}
function gatePill(g) {
  const m = {PASS:'pass',WARN:'warn',FAIL:'fail'}
  return `<span class="pill pill-${m[g]||'queued'}">${g}</span>`
}
function sevPill(s) {
  const m = {CRITICAL:'c-crit',HIGH:'c-high',MEDIUM:'c-med',LOW:'c-low'}
  return `<span style="font-weight:600" class="${m[s]||''}">${s}</span>`
}
function fmtDate(d) {
  if (!d) return '—'
  const dt = new Date(d)
  return dt.toLocaleDateString() + ' ' + dt.toTimeString().slice(0,8)
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}


async function loadRiskRegister() {
  try {
    const data = await api('GET', '/governance/risk-register')
    const risks = data.risks || []
    const colors = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80'}
    document.getElementById('risk-table').innerHTML = risks.length
      ? risks.map(r => `<tr>
          <td><span style="font-weight:600;color:${colors[r.level]||'#94a3b8'}">${r.level}</span></td>
          <td style="font-size:12px">${esc(r.title)}</td>
          <td><span class="pill ${r.status==='open'?'pill-failed':'pill-done'}">${r.status}</span></td>
          <td style="color:#64748b;font-size:11px">${r.due_date?new Date(r.due_date).toLocaleDateString():'-'}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" style="color:#64748b;padding:16px;text-align:center">No risks found — run a scan first</td></tr>'
  } catch(e) { console.error('risks', e) }
}

async function loadTraceability() {
  try {
    const data = await api('GET', '/governance/traceability')
    const rows = data.rows || []
    document.getElementById('trace-table').innerHTML = rows.length
      ? rows.map(r => `<tr>
          <td>${sevPill(r.severity)}</td>
          <td style="font-family:monospace;font-size:11px">${esc(r.rule_id)}</td>
          <td style="font-family:monospace;font-size:11px;color:#818cf8">${r.control}</td>
          <td style="color:#64748b;font-size:11px">${r.framework}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" style="color:#64748b;padding:16px;text-align:center">No findings to trace</td></tr>'
  } catch(e) { console.error('trace', e) }
}

async function loadRACI() {
  try {
    const data = await api('GET', '/governance/raci')
    const raci = data.raci || []
    document.getElementById('raci-list').innerHTML = raci.map(r =>
      `<div style="padding:8px 0;border-bottom:1px solid #1e293b;font-size:12px">
        <b style="color:#e2e8f0">${esc(r.activity)}</b><br>
        <span style="color:#60a5fa">R: ${r.responsible}</span> &nbsp;
        <span style="color:#4ade80">A: ${r.accountable}</span> &nbsp;
        <span style="color:#fbbf24">C: ${r.consulted}</span>
       </div>`).join('')
  } catch(e) { console.error('raci', e) }
}

async function loadOwnership() {
  try {
    const data = await api('GET', '/governance/ownership')
    const owners = data.owners || []
    document.getElementById('ownership-table').innerHTML = owners.map(o => `
      <tr>
        <td style="font-family:monospace;font-size:12px;color:#818cf8">${o.control}</td>
        <td style="font-size:12px">${o.owner}</td>
        <td><span class="pill ${o.status==='implemented'?'pill-done':o.status==='partial'?'pill-queued':'pill-failed'}">${o.status}</span></td>
      </tr>`).join('')
  } catch(e) { console.error('ownership', e) }
}

async function loadScorecard() {
  try {
    const data = await api('GET', '/soc/framework-scorecard')
    const fws = data.frameworks || []
    document.getElementById('scorecard-list').innerHTML = fws.map(f => {
      const color = f.score >= 80 ? '#4ade80' : f.score >= 60 ? '#fbbf24' : '#f87171'
      return `<div style="margin-bottom:14px">
        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px">
          <span style="font-size:13px;color:#e2e8f0">${f.framework}</span>
          <span style="font-size:20px;font-weight:700;color:${color}">${f.score}</span>
        </div>
        <div style="background:#0f172a;border-radius:4px;height:6px">
          <div style="width:${f.score}%;background:${color};height:6px;border-radius:4px;transition:width .5s"></div>
        </div>
      </div>`}).join('')
  } catch(e) { console.error('scorecard', e) }
}

async function loadZeroTrust() {
  try {
    const data = await api('GET', '/soc/zero-trust')
    const pillars = data.pillars || []
    document.getElementById('zerotrust-list').innerHTML = pillars.map(p => {
      const color = p.score >= 80 ? '#4ade80' : p.score >= 60 ? '#fbbf24' : '#f87171'
      return `<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:baseline">
          <span style="font-size:12px;color:#e2e8f0">${p.pillar}</span>
          <span style="font-size:14px;font-weight:600;color:${color}">${p.score}
            <span style="font-size:10px;color:#64748b">${p.level}</span></span>
        </div>
        <div style="background:#0f172a;border-radius:3px;height:4px;margin-top:3px">
          <div style="width:${p.score}%;background:${color};height:4px;border-radius:3px;transition:width .5s"></div>
        </div>
        ${p.open_findings>0?`<div style="font-size:10px;color:#f87171;margin-top:2px">${p.open_findings} open findings</div>`:''}
      </div>`}).join('')
  } catch(e) { console.error('zerotrust', e) }
}

async function loadRoadmap() {
  try {
    const data = await api('GET', '/soc/roadmap')
    const items = data.roadmap || []
    const colors = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#94a3b8'}
    document.getElementById('roadmap-table').innerHTML = items.map(r => `
      <tr>
        <td style="color:#64748b;font-size:11px;white-space:nowrap">${r.quarter}</td>
        <td style="font-size:12px">${esc(r.title)}</td>
        <td><span style="font-size:11px;font-weight:600;color:${colors[r.priority]||'#94a3b8'}">${r.priority}</span></td>
        <td><span class="pill ${r.status==='done'?'pill-done':r.status==='in-progress'?'pill-running':r.status==='overdue'?'pill-failed':'pill-queued'}">${r.status}</span></td>
      </tr>`).join('')
  } catch(e) { console.error('roadmap', e) }
}

async function loadIncidents() {
  try {
    const data = await api('GET', '/soc/incidents')
    const inc = data.incidents || []
    document.getElementById('incidents-table').innerHTML = inc.length
      ? inc.map(i => `<tr>
          <td style="font-family:monospace;font-size:11px;color:#94a3b8">${i.id}</td>
          <td>${sevPill(i.severity)}</td>
          <td style="font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.title)}</td>
        </tr>`).join('')
      : '<tr><td colspan="3" style="color:#64748b;padding:16px;text-align:center">No active incidents</td></tr>'
  } catch(e) { console.error('incidents', e) }
}

let currentRID = ''
async function loadExport() {
  try {
    const r = await api('GET', '/vsp/run/latest')
    currentRID = r.rid
    document.getElementById('export-rid').textContent = 'Latest run: ' + r.rid + ' (' + r.status + ')'
    const ar = await api('GET', '/compliance/oscal/ar')
    document.getElementById('oscal-ar-preview').textContent = JSON.stringify(ar, null, 2).slice(0,600) + '\n...'
    const poam = await api('GET', '/compliance/oscal/poam')
    document.getElementById('oscal-poam-preview').textContent = JSON.stringify(poam, null, 2).slice(0,600) + '\n...'
  } catch(e) { console.error('export', e) }
}

function exportFile(fmt) {
  if (!currentRID) { alert('No run selected'); return }
  const a = document.createElement('a')
  a.href = API + '/export/' + fmt + '/' + currentRID
  a.download = 'vsp-' + currentRID + '.' + fmt
  a.click()
}

function downloadOSCAL(type) {
  const a = document.createElement('a')
  a.href = API + '/compliance/oscal/' + type + '?format=download'
  a.download = 'oscal-' + type + '.json'
  a.click()
}


// ── Charts ─────────────────────────────────────────────────────────────────

const CHART_COLORS = {
  CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24',
  LOW: '#4ade80', INFO: '#94a3b8'
}
const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 10 } } },
  scales: {
    x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' } },
    y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' } }
  }
}

let charts = {}
function destroyChart(id) { if (charts[id]) { charts[id].destroy(); delete charts[id] } }

async function loadDashboardCharts() {
  try {
    // 1. Severity chart — latest run findings
    const summary = await api('GET', '/vsp/findings/summary')
    const rid = (await api('GET', '/vsp/run/latest')).rid
    document.getElementById('chart-run-label').textContent = rid ? rid.slice(-8) : ''

    destroyChart('sev')
    const ctxSev = document.getElementById('chartSeverity').getContext('2d')
    charts['sev'] = new Chart(ctxSev, {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          label: 'Findings',
          data: [summary.critical, summary.high, summary.medium, summary.low, summary.info || 0],
          backgroundColor: [CHART_COLORS.CRITICAL, CHART_COLORS.HIGH, CHART_COLORS.MEDIUM, CHART_COLORS.LOW, CHART_COLORS.INFO],
          borderRadius: 4,
          borderSkipped: false,
        }]
      },
      options: {
        ...CHART_DEFAULTS,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } },
          y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' }, beginAtZero: true }
        }
      }
    })

    // 2. Trend chart — posture score over last 10 runs
    const runsData = await api('GET', '/vsp/runs/index')
    const runs = (runsData.runs || []).filter(r => r.status === 'DONE').slice(0, 10).reverse()
    const postureScore = { 'A':100,'B':85,'C':70,'D':50,'F':20,'':0 }
    const gateColor = r => r.gate === 'PASS' ? '#4ade80' : r.gate === 'FAIL' ? '#f87171' : '#fbbf24'

    destroyChart('trend')
    const ctxTrend = document.getElementById('chartTrend').getContext('2d')
    charts['trend'] = new Chart(ctxTrend, {
      type: 'line',
      data: {
        labels: runs.map(r => r.rid.slice(-8)),
        datasets: [{
          label: 'Security score',
          data: runs.map(r => postureScore[r.posture] || 0),
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56,189,248,0.08)',
          pointBackgroundColor: runs.map(r => gateColor(r)),
          pointRadius: 5,
          tension: 0.3,
          fill: true,
        }]
      },
      options: {
        ...CHART_DEFAULTS,
        scales: {
          x: { ticks: { color: '#64748b', font: { size: 9 }, maxRotation: 45 }, grid: { display: false } },
          y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' }, min: 0, max: 100 }
        }
      }
    })

    // 3. Tools chart — findings by tool (all findings)
    const findingsAll = await api('GET', '/vsp/findings?limit=1000')
    const byTool = {}
    ;(findingsAll.findings || []).forEach(f => {
      if (!byTool[f.tool]) byTool[f.tool] = 0
      byTool[f.tool]++
    })
    const toolLabels = Object.keys(byTool).sort((a,b) => byTool[b]-byTool[a])
    const toolColors = ['#818cf8','#34d399','#fb923c','#f472b6','#38bdf8','#a78bfa','#fbbf24','#6ee7b7','#f87171','#94a3b8']

    destroyChart('tools')
    const ctxTools = document.getElementById('chartTools').getContext('2d')
    charts['tools'] = new Chart(ctxTools, {
      type: 'doughnut',
      data: {
        labels: toolLabels,
        datasets: [{
          data: toolLabels.map(t => byTool[t]),
          backgroundColor: toolColors.slice(0, toolLabels.length),
          borderWidth: 0,
          hoverOffset: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 10, padding: 8 } }
        }
      }
    })

    // 4. Gate decisions donut
    const allRuns = (runsData.runs || []).filter(r => r.status === 'DONE')
    const gates = { PASS: 0, WARN: 0, FAIL: 0 }
    allRuns.forEach(r => { if (gates[r.gate] !== undefined) gates[r.gate]++ })

    destroyChart('gates')
    const ctxGates = document.getElementById('chartGates').getContext('2d')
    charts['gates'] = new Chart(ctxGates, {
      type: 'doughnut',
      data: {
        labels: ['Pass', 'Warn', 'Fail'],
        datasets: [{
          data: [gates.PASS, gates.WARN, gates.FAIL],
          backgroundColor: ['#4ade80', '#fbbf24', '#f87171'],
          borderWidth: 0,
          hoverOffset: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 10, padding: 10 } }
        }
      }
    })
  } catch(e) { console.error('charts', e) }
}


// ── Boot ──────────────────────────────────────────────────────────────────────
if (TOKEN) {
  showApp()
} else {
  document.getElementById('loginScreen').style.display = 'flex'
}
</script>
</body>
</html>
VSP_DASH_V2_HTML

sudo systemctl restart vsp-go-shell 2>/dev/null || pkill -x soc-shell 2>/dev/null; sleep 1; ./soc-shell &
sleep 2
echo "Dashboard upgraded: http://localhost:8922"
echo "Features: Severity bar chart, Posture trend line, Tool doughnut, Gate decisions"
