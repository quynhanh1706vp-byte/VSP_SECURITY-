#!/usr/bin/env bash
# VSP — Premium UI upgrade (Terminal Noir design)
set -e
echo ">>> Premium UI — Terminal Noir"
mkdir -p static

cat > 'static/index.html' << 'VSP_PREMIUM_UI'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VSP — Security Platform</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --black:   #060810;
  --navy:    #080d1a;
  --surface: #0c1220;
  --card:    #101828;
  --border:  #1a2540;
  --border2: #243055;
  --text1:   #e8eaf0;
  --text2:   #8892a4;
  --text3:   #3d4a60;
  --amber:   #f0a500;
  --amber2:  #ffc840;
  --amber-d: #2a1e00;
  --cyan:    #00d4ff;
  --cyan-d:  #00182a;
  --green:   #00e676;
  --green-d: #001a0d;
  --red:     #ff3d57;
  --red-d:   #1a000a;
  --purple:  #b388ff;
  --mono:    'JetBrains Mono', monospace;
  --display: 'Syne', sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--mono);
  background: var(--black);
  color: var(--text1);
  min-height: 100vh;
  font-size: 13px;
  line-height: 1.6;
}

/* Scanline overlay */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,.03) 2px,
    rgba(0,0,0,.03) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* ── LOGIN ─────────────────────────────────────────────────────── */
.login-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--black);
  position: relative;
  overflow: hidden;
}
.login-wrap::before {
  content: 'SECURE ACCESS TERMINAL';
  position: absolute;
  top: 40px;
  left: 50%;
  transform: translateX(-50%);
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: .3em;
  color: var(--text3);
}
.login-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(var(--border) 1px, transparent 1px),
    linear-gradient(90deg, var(--border) 1px, transparent 1px);
  background-size: 48px 48px;
  opacity: .3;
}
.login-card {
  position: relative;
  z-index: 1;
  background: var(--surface);
  border: 1px solid var(--border2);
  width: 400px;
  padding: 40px;
}
.login-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--amber), transparent);
}
.login-logo {
  font-family: var(--display);
  font-size: 28px;
  font-weight: 800;
  color: var(--amber);
  letter-spacing: -.02em;
  margin-bottom: 6px;
}
.login-sub {
  font-size: 10px;
  letter-spacing: .25em;
  color: var(--text3);
  text-transform: uppercase;
  margin-bottom: 32px;
}
.field { margin-bottom: 20px; }
.field label {
  display: block;
  font-size: 10px;
  letter-spacing: .15em;
  color: var(--text3);
  text-transform: uppercase;
  margin-bottom: 6px;
}
.field input {
  width: 100%;
  padding: 10px 14px;
  background: var(--black);
  border: 1px solid var(--border2);
  color: var(--text1);
  font-family: var(--mono);
  font-size: 13px;
  outline: none;
  transition: border-color .2s;
}
.field input:focus { border-color: var(--amber); }
.btn-login {
  width: 100%;
  padding: 12px;
  background: var(--amber);
  color: var(--black);
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: .15em;
  text-transform: uppercase;
  border: none;
  cursor: pointer;
  transition: background .2s;
  margin-top: 8px;
}
.btn-login:hover { background: var(--amber2); }
.login-err { color: var(--red); font-size: 11px; margin-top: 10px; text-align: center; }

/* ── NAV ───────────────────────────────────────────────────────── */
.nav {
  background: var(--navy);
  border-bottom: 1px solid var(--border);
  height: 52px;
  display: flex;
  align-items: center;
  padding: 0 24px;
  gap: 0;
  position: sticky;
  top: 0;
  z-index: 100;
}
.nav-logo {
  font-family: var(--display);
  font-size: 18px;
  font-weight: 800;
  color: var(--amber);
  letter-spacing: -.02em;
  margin-right: 32px;
  white-space: nowrap;
}
.nav-tabs { display: flex; gap: 0; flex: 1; overflow-x: auto; scrollbar-width: none; }
.nav-tabs::-webkit-scrollbar { display: none; }
.tab {
  padding: 0 16px;
  height: 52px;
  display: flex;
  align-items: center;
  font-size: 11px;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: var(--text3);
  cursor: pointer;
  border: none;
  background: none;
  border-bottom: 2px solid transparent;
  transition: all .15s;
  white-space: nowrap;
  font-family: var(--mono);
}
.tab:hover { color: var(--text2); }
.tab.active { color: var(--amber); border-bottom-color: var(--amber); }

.nav-right {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-left: 16px;
  flex-shrink: 0;
}
.gate-badge {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .12em;
  padding: 4px 10px;
  border-radius: 2px;
}
.gate-pass { background: var(--green-d); color: var(--green); border: 1px solid var(--green); }
.gate-fail { background: var(--red-d); color: var(--red); border: 1px solid var(--red); }
.gate-warn { background: var(--amber-d); color: var(--amber); border: 1px solid var(--amber); }
.user-chip {
  font-size: 11px;
  color: var(--text2);
  padding: 4px 10px;
  border: 1px solid var(--border2);
  background: var(--surface);
}
.btn-sm {
  padding: 4px 12px;
  font-size: 10px;
  letter-spacing: .1em;
  text-transform: uppercase;
  border: 1px solid var(--border2);
  background: none;
  color: var(--text2);
  cursor: pointer;
  font-family: var(--mono);
  transition: all .15s;
}
.btn-sm:hover { border-color: var(--amber); color: var(--amber); }
.btn-primary {
  background: var(--amber);
  color: var(--black);
  border-color: var(--amber);
}
.btn-primary:hover { background: var(--amber2); border-color: var(--amber2); color: var(--black); }

/* Bell */
.bell-btn {
  position: relative;
  background: none;
  border: none;
  cursor: pointer;
  color: var(--text3);
  font-size: 16px;
  padding: 4px 8px;
  transition: color .15s;
  font-family: var(--mono);
}
.bell-btn:hover { color: var(--amber); }
.bell-badge {
  position: absolute;
  top: -2px; right: -2px;
  background: var(--red);
  color: #fff;
  font-size: 8px;
  font-weight: 700;
  padding: 0 4px;
  min-width: 14px;
  text-align: center;
  display: none;
  line-height: 14px;
}

/* ── LAYOUT ────────────────────────────────────────────────────── */
.main { padding: 24px; max-width: 1440px; margin: 0 auto; }
.panel { display: none; }
.panel.active { display: block; }

/* ── GRID ──────────────────────────────────────────────────────── */
.g4 { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin-bottom: 16px; }
.g2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
.g3 { display: grid; grid-template-columns: repeat(3,1fr); gap: 16px; margin-bottom: 16px; }

/* ── CARDS ─────────────────────────────────────────────────────── */
.card {
  background: var(--card);
  border: 1px solid var(--border);
  padding: 20px;
  position: relative;
}
.card::before {
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 2px; height: 100%;
  background: transparent;
  transition: background .2s;
}
.card:hover::before { background: var(--border2); }

/* KPI cards */
.kpi-card {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
}
.kpi-card::after {
  content: '';
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, var(--accent, var(--border)), transparent);
}
.kpi-label {
  font-size: 9px;
  letter-spacing: .2em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 10px;
  font-weight: 500;
}
.kpi-value {
  font-family: var(--display);
  font-size: 36px;
  font-weight: 800;
  line-height: 1;
  margin-bottom: 4px;
}
.kpi-sub { font-size: 10px; color: var(--text3); }
.kpi-crit { --accent: var(--red); }
.kpi-high { --accent: #ff8c00; }
.kpi-med  { --accent: var(--amber); }
.kpi-low  { --accent: var(--green); }
.kpi-pass { --accent: var(--cyan); }

/* Colors */
.c-amber  { color: var(--amber); }
.c-cyan   { color: var(--cyan); }
.c-green  { color: var(--green); }
.c-red    { color: var(--red); }
.c-purple { color: var(--purple); }

/* ── CARD HEADER ───────────────────────────────────────────────── */
.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.card-title {
  font-size: 10px;
  letter-spacing: .2em;
  text-transform: uppercase;
  color: var(--text2);
  font-weight: 500;
}

/* ── TABLE ─────────────────────────────────────────────────────── */
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th {
  text-align: left;
  padding: 8px 12px;
  font-size: 9px;
  letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--text3);
  border-bottom: 1px solid var(--border);
  font-weight: 500;
  white-space: nowrap;
}
td {
  padding: 9px 12px;
  border-bottom: 1px solid rgba(26,37,64,.5);
  font-size: 12px;
  vertical-align: middle;
}
tr:hover td { background: rgba(240,165,0,.03); }
tr:last-child td { border-bottom: none; }

/* ── PILLS ─────────────────────────────────────────────────────── */
.pill {
  display: inline-block;
  padding: 2px 8px;
  font-size: 9px;
  letter-spacing: .1em;
  text-transform: uppercase;
  font-weight: 600;
  border-radius: 1px;
}
.pill-pass    { background: var(--green-d); color: var(--green); }
.pill-fail    { background: var(--red-d);   color: var(--red); }
.pill-warn    { background: var(--amber-d); color: var(--amber); }
.pill-done    { background: var(--cyan-d);  color: var(--cyan); }
.pill-running { background: rgba(179,136,255,.1); color: var(--purple); }
.pill-queued  { background: var(--surface); color: var(--text3); border: 1px solid var(--border); }

/* ── CHART WRAPPER ─────────────────────────────────────────────── */
.chart-wrap { position: relative; height: 220px; width: 100%; }

/* ── SCAN FORM ─────────────────────────────────────────────────── */
.scan-form { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; }
.scan-form select, .scan-form input {
  padding: 8px 12px;
  background: var(--black);
  border: 1px solid var(--border2);
  color: var(--text1);
  font-family: var(--mono);
  font-size: 12px;
  outline: none;
  transition: border-color .2s;
}
.scan-form select:focus, .scan-form input:focus { border-color: var(--amber); }
.scan-form label { font-size: 9px; letter-spacing: .15em; color: var(--text3); text-transform: uppercase; display: block; margin-bottom: 4px; }
.scan-form .btn-sm { padding: 8px 20px; font-size: 11px; }

/* ── NOTIFICATION PANEL ────────────────────────────────────────── */
#notif-panel {
  display: none;
  position: fixed;
  top: 56px; right: 16px;
  width: 340px;
  max-height: 460px;
  background: var(--surface);
  border: 1px solid var(--border2);
  z-index: 200;
  flex-direction: column;
}
.notif-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.notif-head span { font-size: 10px; letter-spacing: .15em; text-transform: uppercase; color: var(--text2); }
.notif-list { overflow-y: auto; flex: 1; }
.notif-item {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background .15s;
  display: flex;
  gap: 10px;
  align-items: flex-start;
}
.notif-item:hover { background: rgba(240,165,0,.04); }
.notif-unread { border-left: 2px solid var(--amber); }
.notif-icon { font-size: 14px; flex-shrink: 0; margin-top: 1px; }
.notif-msg { font-size: 11px; color: var(--text1); font-weight: 500; }
.notif-detail { font-size: 10px; color: var(--text3); margin-top: 2px; }
.notif-time { font-size: 9px; color: var(--text3); flex-shrink: 0; }
.notif-empty { padding: 24px; text-align: center; font-size: 11px; color: var(--text3); letter-spacing: .1em; }

/* ── REMEDIATION MODAL ─────────────────────────────────────────── */
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.8);
  z-index: 300;
  align-items: center;
  justify-content: center;
}
.modal-box {
  background: var(--surface);
  border: 1px solid var(--border2);
  width: 540px;
  max-height: 80vh;
  overflow-y: auto;
  position: relative;
  padding: 28px;
}
.modal-box::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: var(--amber);
}
.modal-title { font-family: var(--display); font-size: 16px; font-weight: 700; color: var(--text1); margin-bottom: 16px; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
.form-group { margin-bottom: 12px; }
.form-label { font-size: 9px; letter-spacing: .15em; text-transform: uppercase; color: var(--text3); display: block; margin-bottom: 5px; }
.form-ctrl {
  width: 100%;
  padding: 8px 12px;
  background: var(--black);
  border: 1px solid var(--border2);
  color: var(--text1);
  font-family: var(--mono);
  font-size: 12px;
  outline: none;
}
.form-ctrl:focus { border-color: var(--amber); }
textarea.form-ctrl { resize: vertical; min-height: 60px; }

/* ── COMPLIANCE BARS ───────────────────────────────────────────── */
.compliance-bar-bg { background: var(--border); height: 4px; border-radius: 0; margin-top: 6px; }
.compliance-bar-fill { height: 4px; transition: width .6s ease; }

/* ── SBOM CARD ─────────────────────────────────────────────────── */
.sbom-feature {
  display: grid;
  grid-template-columns: repeat(3,1fr);
  gap: 8px;
  margin-top: 12px;
}
.sbom-feature-item {
  padding: 10px;
  border: 1px solid var(--border);
  font-size: 10px;
  color: var(--text2);
}
.sbom-feature-item::before { content: "→ "; color: var(--amber); }

/* ── SPINNER ───────────────────────────────────────────────────── */
@keyframes spin { to { transform: rotate(360deg); } }
.spin { display: inline-block; animation: spin .6s linear infinite; }

/* ── TOAST ─────────────────────────────────────────────────────── */
#toast-container {
  position: fixed;
  bottom: 24px; right: 24px;
  z-index: 400;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.toast {
  padding: 12px 20px;
  background: var(--surface);
  border: 1px solid var(--border2);
  border-left: 3px solid var(--amber);
  font-size: 12px;
  max-width: 300px;
  animation: slideIn .2s ease;
}
.toast-success { border-left-color: var(--green); }
.toast-error   { border-left-color: var(--red); }
@keyframes slideIn {
  from { transform: translateX(100%); opacity: 0; }
  to   { transform: translateX(0); opacity: 1; }
}

/* ── POSTURE DISPLAY ───────────────────────────────────────────── */
.posture-A { color: var(--cyan); }
.posture-B { color: var(--green); }
.posture-C { color: var(--amber2); }
.posture-D { color: var(--amber); }
.posture-F { color: var(--red); }

/* ── CODE ──────────────────────────────────────────────────────── */
code { font-family: var(--mono); color: var(--cyan); font-size: 11px; }
pre  { font-family: var(--mono); font-size: 11px; color: var(--text2); line-height: 1.7;
       overflow: auto; max-height: 200px; }

/* Scrollbar */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--black); }
::-webkit-scrollbar-thumb { background: var(--border2); }
</style>
</head>
<body>

<div id="toast-container"></div>

<!-- ── LOGIN ────────────────────────────────────────────────────── -->
<div id="loginScreen" class="login-wrap" style="display:none">
  <div class="login-grid"></div>
  <div class="login-card">
    <div class="login-logo">VSP</div>
    <div class="login-sub">Security Platform v0.4.1 · Enterprise</div>
    <div class="field">
      <label>Email address</label>
      <input id="loginEmail" type="email" value="admin@vsp.local">
    </div>
    <div class="field">
      <label>Password</label>
      <input id="loginPassword" type="password" value="admin123">
    </div>
    <button class="btn-login" onclick="doLogin()">Authenticate →</button>
    <div id="loginError" class="login-err"></div>
    <div id="sso-buttons" style="display:none;margin-top:20px">
      <div style="text-align:center;font-size:10px;letter-spacing:.15em;color:var(--text3);margin-bottom:12px">— OR CONTINUE WITH —</div>
      <div id="sso-provider-list"></div>
    </div>
  </div>
</div>

<!-- ── APP ──────────────────────────────────────────────────────── -->
<div id="appScreen" style="display:none">
  <nav class="nav">
    <div class="nav-logo">VSP</div>
    <div class="nav-tabs">
      <button class="tab active" onclick="showPanel('dashboard',this)">Dashboard</button>
      <button class="tab" onclick="showPanel('runs',this)">Runs</button>
      <button class="tab" onclick="showPanel('findings',this)">Findings</button>
      <button class="tab" onclick="showPanel('policy',this)">Policy</button>
      <button class="tab" onclick="showPanel('audit',this)">Audit</button>
      <button class="tab" onclick="showPanel('governance',this)">Governance</button>
      <button class="tab" onclick="showPanel('soc',this)">SOC</button>
      <button class="tab" onclick="showPanel('export',this)">Export</button>
      <button class="tab" onclick="showPanel('remediation',this)">Remediation</button>
      <button class="tab" onclick="showPanel('sbom',this)">SBOM</button>
      <button class="tab" onclick="showPanel('compliance2',this)">FedRAMP</button>
    </div>
    <div class="nav-right">
      <button class="bell-btn" onclick="toggleNotifPanel()" id="notif-bell">
        ◉ <span class="bell-badge" id="notif-count">0</span>
      </button>
      <span class="gate-badge gate-pass" id="gateWidget">PASS</span>
      <span class="user-chip" id="userWidget">—</span>
      <button class="btn-sm" onclick="doLogout()">Exit</button>
    </div>
  </nav>

  <!-- NOTIFICATION PANEL -->
  <div id="notif-panel">
    <div class="notif-head">
      <span>Notifications</span>
      <div style="display:flex;gap:8px">
        <button class="btn-sm" style="padding:2px 8px;font-size:9px" onclick="clearNotifs()">Clear</button>
        <button class="btn-sm" style="padding:2px 8px;font-size:9px" onclick="toggleNotifPanel()">✕</button>
      </div>
    </div>
    <div class="notif-list" id="notif-list"></div>
    <div class="notif-empty" id="notif-empty">NO NOTIFICATIONS</div>
  </div>

  <div class="main">

  <!-- ── DASHBOARD ──────────────────────────────────────────────── -->
  <div id="panel-dashboard" class="panel active">
    <!-- KPI row 1 -->
    <div class="g4" style="margin-bottom:12px">
      <div class="kpi-card kpi-pass" style="--accent:var(--cyan)">
        <div class="kpi-label">Security Score</div>
        <div class="kpi-value c-cyan" id="d-score">—</div>
        <div class="kpi-sub">out of 100</div>
      </div>
      <div class="kpi-card" style="--accent:var(--amber)">
        <div class="kpi-label">Posture Grade</div>
        <div class="kpi-value c-amber" id="d-posture">—</div>
        <div class="kpi-sub">latest run</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Runs</div>
        <div class="kpi-value" id="d-runs">—</div>
        <div class="kpi-sub">all time</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Gate Decision</div>
        <div class="kpi-value" id="d-gate">—</div>
        <div class="kpi-sub">latest</div>
      </div>
    </div>
    <!-- KPI row 2 — findings -->
    <div class="g4" style="margin-bottom:20px">
      <div class="kpi-card kpi-crit">
        <div class="kpi-label">Critical</div>
        <div class="kpi-value c-red" id="d-critical">—</div>
      </div>
      <div class="kpi-card kpi-high">
        <div class="kpi-label">High</div>
        <div class="kpi-value" style="color:#ff8c00" id="d-high">—</div>
      </div>
      <div class="kpi-card kpi-med">
        <div class="kpi-label">Medium</div>
        <div class="kpi-value c-amber" id="d-medium">—</div>
      </div>
      <div class="kpi-card kpi-low">
        <div class="kpi-label">Low</div>
        <div class="kpi-value c-green" id="d-low">—</div>
      </div>
    </div>
    <!-- Charts -->
    <div class="g2">
      <div class="card">
        <div class="card-head">
          <span class="card-title">Findings — latest run</span>
          <code id="chart-run-label" style="font-size:10px"></code>
        </div>
        <div class="chart-wrap"><canvas id="chartSeverity"></canvas></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Posture trend — last 10 scans</span></div>
        <div class="chart-wrap"><canvas id="chartTrend"></canvas></div>
      </div>
    </div>
    <div class="g2" style="margin-bottom:20px">
      <div class="card">
        <div class="card-head"><span class="card-title">Findings by tool</span></div>
        <div class="chart-wrap"><canvas id="chartTools"></canvas></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Gate decisions</span></div>
        <div class="chart-wrap"><canvas id="chartGates"></canvas></div>
      </div>
    </div>
    <!-- Recent runs -->
    <div class="card">
      <div class="card-head">
        <span class="card-title">Recent runs</span>
        <button class="btn-sm btn-primary" onclick="showPanel('runs',null);showTrigger()">+ New Scan</button>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Run ID</th><th>Mode</th><th>Status</th><th>Gate</th><th>Findings</th><th>Created</th></tr></thead>
          <tbody id="d-runs-table"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── RUNS ───────────────────────────────────────────────────── -->
  <div id="panel-runs" class="panel">
    <div class="card" style="margin-bottom:16px">
      <div class="card-head"><span class="card-title">Trigger new scan</span></div>
      <div class="scan-form">
        <div><label>Mode</label>
          <select id="scanMode"><option>SAST</option><option>SCA</option><option>SECRETS</option><option>IAC</option><option>DAST</option><option>FULL</option></select>
        </div>
        <div><label>Profile</label>
          <select id="scanProfile"><option>FAST</option><option>EXT</option><option>FULL</option></select>
        </div>
        <div style="flex:1;min-width:240px"><label>Source Path</label>
          <input id="scanSrc" type="text" placeholder="/path/to/code" style="width:100%">
        </div>
        <button class="btn-sm btn-primary" onclick="triggerScan()">Execute →</button>
      </div>
      <div id="triggerMsg" style="margin-top:10px;font-size:11px"></div>
    </div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">Run history</span>
        <button class="btn-sm" onclick="loadRuns()">↻ Refresh</button>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Run ID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th><th>Findings</th><th>Tools</th><th>Created</th></tr></thead>
          <tbody id="runs-table"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── FINDINGS ───────────────────────────────────────────────── -->
  <div id="panel-findings" class="panel">
    <div class="card" style="margin-bottom:16px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <select id="filterSev" onchange="loadFindings()" style="padding:7px 12px;background:var(--black);border:1px solid var(--border2);color:var(--text1);font-family:var(--mono);font-size:12px">
          <option value="">All severities</option>
          <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
        </select>
        <select id="filterTool" onchange="loadFindings()" style="padding:7px 12px;background:var(--black);border:1px solid var(--border2);color:var(--text1);font-family:var(--mono);font-size:12px">
          <option value="">All tools</option>
          <option>bandit</option><option>semgrep</option><option>grype</option><option>trivy</option><option>gitleaks</option><option>kics</option><option>checkov</option><option>nikto</option><option>nuclei</option><option>codeql</option>
        </select>
        <input id="filterQ" type="text" placeholder="Search findings..." onkeyup="if(event.key==='Enter')loadFindings()" style="padding:7px 12px;background:var(--black);border:1px solid var(--border2);color:var(--text1);font-family:var(--mono);font-size:12px;width:220px">
        <button class="btn-sm btn-primary" onclick="loadFindings()">Search</button>
        <span id="findings-count" style="color:var(--text3);font-size:11px;margin-left:auto;letter-spacing:.05em"></span>
      </div>
    </div>
    <div class="card">
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Message</th><th>Path</th><th>Line</th><th>CWE</th></tr></thead>
          <tbody id="findings-table"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── POLICY ─────────────────────────────────────────────────── -->
  <div id="panel-policy" class="panel">
    <div class="card" style="margin-bottom:16px">
      <div class="card-head">
        <span class="card-title">Gate evaluation</span>
        <button class="btn-sm btn-primary" onclick="runEval()">Evaluate →</button>
      </div>
      <div id="eval-result" style="font-size:13px;margin-top:4px"></div>
    </div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">Policy rules</span>
        <button class="btn-sm" onclick="loadRules()">↻ Refresh</button>
      </div>
      <div id="rules-list" style="font-size:12px;color:var(--text2)">Loading...</div>
    </div>
  </div>

  <!-- ── AUDIT ──────────────────────────────────────────────────── -->
  <div id="panel-audit" class="panel">
    <div class="card" style="margin-bottom:16px">
      <div class="card-head">
        <span class="card-title">Hash chain integrity</span>
        <button class="btn-sm btn-primary" onclick="verifyAudit()">Verify chain →</button>
      </div>
      <div id="verify-result" style="font-size:12px;color:var(--text2)">Click verify to check chain integrity.</div>
    </div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">Audit log</span>
        <button class="btn-sm" onclick="loadAudit()">↻ Refresh</button>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Seq</th><th>Action</th><th>Resource</th><th>IP</th><th>Time</th><th>Hash</th></tr></thead>
          <tbody id="audit-table"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── GOVERNANCE ─────────────────────────────────────────────── -->
  <div id="panel-governance" class="panel">
    <div class="g2">
      <div class="card">
        <div class="card-head"><span class="card-title">Risk register</span><button class="btn-sm" onclick="loadRiskRegister()">↻</button></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Level</th><th>Title</th><th>Status</th><th>Due</th></tr></thead>
          <tbody id="risk-table"></tbody>
        </table></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Traceability matrix</span></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Severity</th><th>Rule</th><th>Control</th><th>Framework</th></tr></thead>
          <tbody id="trace-table"></tbody>
        </table></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">RACI governance</span></div>
        <div id="raci-list" style="font-size:12px"></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Control ownership</span></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Control</th><th>Owner</th><th>Status</th></tr></thead>
          <tbody id="ownership-table"></tbody>
        </table></div>
      </div>
    </div>
  </div>

  <!-- ── SOC ────────────────────────────────────────────────────── -->
  <div id="panel-soc" class="panel">
    <div class="g2">
      <div class="card">
        <div class="card-head"><span class="card-title">Framework scorecard</span></div>
        <div id="scorecard-list"></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Zero trust — 7 pillars</span></div>
        <div id="zerotrust-list"></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Security roadmap</span></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Quarter</th><th>Title</th><th>Priority</th><th>Status</th></tr></thead>
          <tbody id="roadmap-table"></tbody>
        </table></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">SOC incidents</span></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>ID</th><th>Severity</th><th>Title</th></tr></thead>
          <tbody id="incidents-table"></tbody>
        </table></div>
      </div>
    </div>
  </div>

  <!-- ── EXPORT ─────────────────────────────────────────────────── -->
  <div id="panel-export" class="panel">
    <div class="card" style="margin-bottom:16px">
      <div class="card-head"><span class="card-title">Export latest run</span></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        <button class="btn-sm btn-primary" onclick="exportFile('sarif')">↓ SARIF 2.1.0</button>
        <button class="btn-sm btn-primary" onclick="exportFile('csv')">↓ CSV</button>
        <button class="btn-sm btn-primary" onclick="exportFile('json')">↓ JSON</button>
      </div>
      <div id="export-rid" style="font-size:10px;color:var(--text3);letter-spacing:.05em"></div>
    </div>
    <div class="g2">
      <div class="card">
        <div class="card-head">
          <span class="card-title">OSCAL — Assessment result</span>
          <button class="btn-sm" onclick="downloadOSCAL('ar')">↓ Download</button>
        </div>
        <pre id="oscal-ar-preview"></pre>
      </div>
      <div class="card">
        <div class="card-head">
          <span class="card-title">OSCAL — POA&M</span>
          <button class="btn-sm" onclick="downloadOSCAL('poam')">↓ Download</button>
        </div>
        <pre id="oscal-poam-preview"></pre>
      </div>
    </div>
  </div>

  <!-- ── REMEDIATION ────────────────────────────────────────────── -->
  <div id="panel-remediation" class="panel">
    <div class="g4" style="grid-template-columns:repeat(6,1fr);margin-bottom:16px">
      <div class="kpi-card" style="padding:14px">
        <div class="kpi-label">Open</div>
        <div class="kpi-value c-red" id="rem-open" style="font-size:28px">—</div>
      </div>
      <div class="kpi-card" style="padding:14px">
        <div class="kpi-label">In progress</div>
        <div class="kpi-value c-amber" id="rem-inprog" style="font-size:28px">—</div>
      </div>
      <div class="kpi-card" style="padding:14px">
        <div class="kpi-label">Resolved</div>
        <div class="kpi-value c-green" id="rem-resolved" style="font-size:28px">—</div>
      </div>
      <div class="kpi-card" style="padding:14px">
        <div class="kpi-label">Accepted</div>
        <div class="kpi-value" id="rem-accepted" style="font-size:28px;color:var(--text2)">—</div>
      </div>
      <div class="kpi-card" style="padding:14px">
        <div class="kpi-label">False +ve</div>
        <div class="kpi-value c-purple" id="rem-fp" style="font-size:28px">—</div>
      </div>
      <div class="kpi-card" style="padding:14px">
        <div class="kpi-label">Suppressed</div>
        <div class="kpi-value" id="rem-sup" style="font-size:28px;color:var(--text3)">—</div>
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:14px;align-items:center">
      <select id="rem-filter-status" onchange="loadRemediation()" style="padding:7px 12px;background:var(--black);border:1px solid var(--border2);color:var(--text1);font-family:var(--mono);font-size:11px">
        <option value="">All statuses</option>
        <option value="open">Open</option>
        <option value="in_progress">In progress</option>
        <option value="resolved">Resolved</option>
        <option value="accepted">Accepted</option>
        <option value="false_positive">False positive</option>
        <option value="suppressed">Suppressed</option>
      </select>
      <span id="rem-count" style="font-size:10px;color:var(--text3);letter-spacing:.1em"></span>
    </div>
    <div class="card">
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Finding</th><th>Assignee</th><th>Priority</th><th>Status</th><th></th></tr></thead>
          <tbody id="rem-tbody"></tbody>
        </table>
      </div>
    </div>
    <!-- Modal -->
    <div class="modal-overlay" id="rem-modal">
      <div class="modal-box">
        <div class="modal-title" id="rem-modal-title">Update finding</div>
        <div id="rem-modal-finding" style="font-size:11px;color:var(--text2);margin-bottom:16px;padding:10px;border:1px solid var(--border);background:var(--black)"></div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Status</label>
            <select id="rem-status" class="form-ctrl">
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="resolved">Resolved</option>
              <option value="accepted">Risk accepted</option>
              <option value="false_positive">False positive</option>
              <option value="suppressed">Suppressed</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Priority</label>
            <select id="rem-priority" class="form-ctrl">
              <option value="P1">P1 — Critical</option>
              <option value="P2">P2 — High</option>
              <option value="P3" selected>P3 — Medium</option>
              <option value="P4">P4 — Low</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Assignee</label>
          <input id="rem-assignee" class="form-ctrl" placeholder="email or name">
        </div>
        <div class="form-group">
          <label class="form-label">Ticket URL</label>
          <input id="rem-ticket" class="form-ctrl" placeholder="https://jira.example.com/VSP-001">
        </div>
        <div class="form-group">
          <label class="form-label">Notes</label>
          <textarea id="rem-notes" class="form-ctrl" rows="3"></textarea>
        </div>
        <div style="margin-bottom:16px">
          <div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--text3);margin-bottom:8px">Comments</div>
          <div id="rem-comments" style="max-height:130px;overflow-y:auto;margin-bottom:8px;border:1px solid var(--border);padding:8px"></div>
          <div style="display:flex;gap:8px">
            <input id="rem-comment-input" class="form-ctrl" style="flex:1" placeholder="Add comment...">
            <button class="btn-sm btn-primary" onclick="submitComment()">Post</button>
          </div>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button class="btn-sm" onclick="closeRemModal()">Cancel</button>
          <button class="btn-sm btn-primary" onclick="saveRemediation()">Save changes →</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ── SBOM ───────────────────────────────────────────────────── -->
  <div id="panel-sbom" class="panel">
    <div style="margin-bottom:20px">
      <div style="font-family:var(--display);font-size:22px;font-weight:800;color:var(--text1);margin-bottom:4px">Software Bill of Materials</div>
      <div style="font-size:10px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase">CycloneDX 1.5 · per scan run · machine-readable</div>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div class="card-head"><span class="card-title">Available SBOMs</span></div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Run ID</th><th>Mode</th><th>Gate</th><th>Findings</th><th>Date</th><th>Download</th></tr></thead>
          <tbody id="sbom-tbody"></tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><span class="card-title">CycloneDX 1.5 includes</span></div>
      <div class="sbom-feature">
        <div class="sbom-feature-item">BOM format + spec version</div>
        <div class="sbom-feature-item">All vulnerability IDs</div>
        <div class="sbom-feature-item">Severity ratings</div>
        <div class="sbom-feature-item">Tool attribution</div>
        <div class="sbom-feature-item">Fix signal URLs</div>
        <div class="sbom-feature-item">Scan metadata</div>
      </div>
    </div>
  </div>

  <!-- ── FEDRAMP / CMMC ─────────────────────────────────────────── -->
  <div id="panel-compliance2" class="panel">
    <div style="display:flex;gap:10px;margin-bottom:20px">
      <button class="btn-sm btn-primary" onclick="loadFedRAMP()" id="btn-fedramp">FedRAMP Moderate</button>
      <button class="btn-sm" onclick="loadCMMC()" id="btn-cmmc">CMMC Level 2</button>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:12px">
        <span id="compliance2-title" style="font-family:var(--display);font-size:18px;font-weight:700">FedRAMP Moderate</span>
        <span id="compliance2-coverage" style="font-family:var(--display);font-size:32px;font-weight:800;color:var(--cyan)">—%</span>
      </div>
      <div class="compliance-bar-bg">
        <div class="compliance-bar-fill" id="compliance2-bar" style="background:var(--cyan);width:0%"></div>
      </div>
      <div style="display:flex;justify-content:space-between;margin-top:8px">
        <span id="compliance2-assessed" style="font-size:10px;color:var(--text3)">0 assessed</span>
        <span id="compliance2-total" style="font-size:10px;color:var(--text3)">0 total</span>
      </div>
    </div>
    <div class="card">
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>ID</th><th>Family / Domain</th><th>Control / Practice</th><th>Tools</th><th>Status</th></tr></thead>
          <tbody id="compliance2-tbody"></tbody>
        </table>
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
  loadSSOProviders()
  handleSSOCallback()
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
  if (name === 'remediation') loadRemediation()
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



// ── Remediation workflow ────────────────────────────────────────────────────

let remCurrentFindingId = ''
let remCurrentRemId = ''
let remAllFindings = []

async function loadRemediation() {
  try {
    // Load stats
    const stats = await api('GET', '/remediation/stats')
    document.getElementById('rem-open').textContent     = stats.open || 0
    document.getElementById('rem-inprog').textContent   = stats.in_progress || 0
    document.getElementById('rem-resolved').textContent = stats.resolved || 0
    document.getElementById('rem-accepted').textContent = stats.accepted || 0
    document.getElementById('rem-fp').textContent       = stats.false_positive || 0
    document.getElementById('rem-sup').textContent      = stats.suppressed || 0

    // Load findings from latest run
    const status = document.getElementById('rem-filter-status').value
    const findingsData = await api('GET', '/vsp/findings?limit=200')
    remAllFindings = findingsData.findings || []

    // Load remediation records
    const remUrl = '/remediation' + (status ? '?status=' + status : '')
    const remData = await api('GET', remUrl)
    const remByFinding = {}
    for (const r of (remData.remediations || [])) {
      remByFinding[r.finding_id] = r
    }

    const priorityColor = {P1:'#f87171',P2:'#fb923c',P3:'#fbbf24',P4:'#4ade80'}
    const statusBadge = {
      open:           '<span class="pill pill-failed">open</span>',
      in_progress:    '<span class="pill pill-running">in progress</span>',
      resolved:       '<span class="pill pill-done">resolved</span>',
      accepted:       '<span class="pill" style="background:#1e293b;color:#94a3b8">accepted</span>',
      false_positive: '<span class="pill" style="background:#312e81;color:#a5b4fc">false +ve</span>',
      suppressed:     '<span class="pill" style="background:#1e293b;color:#64748b">suppressed</span>',
    }

    let findings = remAllFindings
    if (status) findings = findings.filter(f => {
      const r = remByFinding[f.id]
      const fStatus = r ? r.status : 'open'
      return fStatus === status
    })

    document.getElementById('rem-count').textContent = findings.length + ' findings'
    document.getElementById('rem-tbody').innerHTML = findings.map(f => {
      const rem = remByFinding[f.id]
      const fStatus = rem ? rem.status : 'open'
      const assignee = rem ? (rem.assignee || '—') : '—'
      const priority = rem ? rem.priority : '—'
      const pColor = priorityColor[priority] || '#94a3b8'
      return `<tr>
        <td>${sevPill(f.severity)}</td>
        <td style="color:#94a3b8;font-size:11px">${esc(f.tool)}</td>
        <td style="font-family:monospace;font-size:11px;color:#818cf8">${esc(f.rule_id)}</td>
        <td style="font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.message)}">${esc(f.message)}</td>
        <td style="font-size:12px;color:#94a3b8">${esc(assignee)}</td>
        <td><span style="font-size:11px;font-weight:600;color:${pColor}">${priority}</span></td>
        <td>${statusBadge[fStatus] || statusBadge.open}</td>
        <td><button class="btn btn-sm btn-outline" onclick="openRemModal('${f.id}','${esc(f.message).slice(0,50)}','${f.severity}')">Edit</button></td>
      </tr>`
    }).join('')
  } catch(e) { console.error('remediation', e) }
}

function openRemModal(findingId, title, severity) {
  remCurrentFindingId = findingId
  document.getElementById('rem-modal-title').textContent = 'Remediation — ' + severity
  document.getElementById('rem-modal-finding').textContent = title
  document.getElementById('rem-modal').style.display = 'flex'
  document.getElementById('rem-comments').innerHTML = '<div style="color:#64748b;font-size:12px">Loading...</div>'

  api('GET', '/remediation/finding/' + findingId).then(data => {
    const rem = data.remediation || {}
    remCurrentRemId = rem.id || ''
    document.getElementById('rem-status').value   = rem.status || 'open'
    document.getElementById('rem-priority').value = rem.priority || 'P3'
    document.getElementById('rem-assignee').value = rem.assignee || ''
    document.getElementById('rem-ticket').value   = rem.ticket_url || ''
    document.getElementById('rem-notes').value    = rem.notes || ''

    const comments = data.comments || []
    document.getElementById('rem-comments').innerHTML = comments.length
      ? comments.map(c => `
          <div style="padding:8px;border-bottom:1px solid #1e293b;font-size:12px">
            <span style="color:#38bdf8;font-weight:500">${esc(c.author || 'user')}</span>
            <span style="color:#64748b;font-size:10px;margin-left:8px">${new Date(c.created_at).toLocaleString()}</span>
            <div style="color:#e2e8f0;margin-top:4px">${esc(c.body)}</div>
          </div>`).join('')
      : '<div style="color:#64748b;font-size:12px;padding:8px">No comments yet</div>'
  }).catch(() => {
    document.getElementById('rem-status').value = 'open'
    document.getElementById('rem-priority').value = 'P3'
    document.getElementById('rem-assignee').value = ''
    document.getElementById('rem-ticket').value = ''
    document.getElementById('rem-notes').value = ''
    document.getElementById('rem-comments').innerHTML = '<div style="color:#64748b;font-size:12px;padding:8px">No comments yet</div>'
  })
}

function closeRemModal() {
  document.getElementById('rem-modal').style.display = 'none'
}

async function saveRemediation() {
  try {
    await api('POST', '/remediation/finding/' + remCurrentFindingId, {
      status:     document.getElementById('rem-status').value,
      priority:   document.getElementById('rem-priority').value,
      assignee:   document.getElementById('rem-assignee').value,
      ticket_url: document.getElementById('rem-ticket').value,
      notes:      document.getElementById('rem-notes').value,
    })
    closeRemModal()
    loadRemediation()
  } catch(e) { console.error('save rem', e) }
}

async function submitComment() {
  const body = document.getElementById('rem-comment-input').value.trim()
  if (!body || !remCurrentRemId) return
  try {
    await api('POST', '/remediation/' + remCurrentRemId + '/comments', { body })
    document.getElementById('rem-comment-input').value = ''
    openRemModal(remCurrentFindingId, '', '')
  } catch(e) { console.error('comment', e) }
}


async function // already called below {
  try {
    const data = await fetch('/auth/sso/providers').then(r=>r.json())
    if (data.sso_enabled && data.providers && data.providers.length > 0) {
      document.getElementById('sso-buttons').style.display = 'block'
      const icons = {google:'G', github:'GH', azure:'MS', okta:'OK'}
      document.getElementById('sso-provider-list').innerHTML = data.providers.map(p => `
        <a href="${p.login_url}" style="display:flex;align-items:center;justify-content:center;
           gap:10px;padding:10px;border:1px solid #334155;border-radius:8px;color:#e2e8f0;
           text-decoration:none;font-size:13px;margin-bottom:8px;transition:background .15s"
           onmouseover="this.style.background='#334155'" onmouseout="this.style.background='none'">
          <span style="font-weight:700;color:#38bdf8">${icons[p.name]||p.name.toUpperCase()}</span>
          Sign in with ${p.name.charAt(0).toUpperCase()+p.name.slice(1)}
        </a>`).join('')
    }
  } catch(e) {}
}

// Handle SSO redirect callback — token in URL fragment
function handleSSOCallback() {
  const hash = window.location.hash
  if (hash.startsWith('#sso_token=')) {
    const token = hash.slice('#sso_token='.length)
    localStorage.setItem('vsp_token', token)
    TOKEN = token
    window.location.hash = ''
    initApp()
  }
}


// ── Boot ──────────────────────────────────────────────────────────────────────
if (TOKEN) {
  showApp()
} else {
  document.getElementById('loginScreen').style.display = 'flex'
  loadSSOProviders()
  handleSSOCallback()
}


// ── OVERRIDES for new UI ─────────────────────────────────────────

// Toast notification
function showToast(msg, type) {
  const t = document.createElement('div')
  t.className = 'toast toast-' + (type||'info')
  t.textContent = msg
  document.getElementById('toast-container').appendChild(t)
  setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity .3s'; setTimeout(()=>t.remove(),300) }, 3000)
}

// Notification system
const notifications = []
let notifOpen = false

function addNotification(msg, type, detail) {
  const icons = {success:'✓', error:'✗', warn:'!', info:'◉', scan:'◎'}
  const n = { id:Date.now(), type, msg, detail:detail||'', time:new Date().toLocaleTimeString(), icon:icons[type]||'◉', read:false }
  notifications.unshift(n)
  if (notifications.length > 50) notifications.pop()
  renderNotifications()
  const bell = document.getElementById('notif-bell')
  if (bell) { bell.style.color='var(--amber)'; setTimeout(()=>bell.style.color='',1000) }
}

function renderNotifications() {
  const unread = notifications.filter(n=>!n.read).length
  const cnt = document.getElementById('notif-count')
  if (cnt) { cnt.textContent = unread > 9 ? '9+' : unread; cnt.style.display = unread > 0 ? 'block' : 'none' }
  const list = document.getElementById('notif-list')
  const empty = document.getElementById('notif-empty')
  if (!list) return
  if (!notifications.length) { list.innerHTML=''; if(empty)empty.style.display='block'; return }
  if (empty) empty.style.display = 'none'
  list.innerHTML = notifications.map(n => `
    <div class="notif-item ${n.read?'':'notif-unread'}" onclick="markRead(${n.id})">
      <span class="notif-icon" style="color:${n.type==='error'?'var(--red)':n.type==='success'?'var(--green)':'var(--amber)'}">${n.icon}</span>
      <div style="flex:1;min-width:0">
        <div class="notif-msg">${n.msg}</div>
        ${n.detail?`<div class="notif-detail">${n.detail}</div>`:''}
      </div>
      <span class="notif-time">${n.time}</span>
    </div>`).join('')
}

function markRead(id) { const n=notifications.find(x=>x.id===id); if(n){n.read=true;renderNotifications()} }
function clearNotifs() { notifications.length=0; renderNotifications(); if(notifOpen)toggleNotifPanel() }
function toggleNotifPanel() {
  const p = document.getElementById('notif-panel')
  notifOpen = !notifOpen
  p.style.display = notifOpen ? 'flex' : 'none'
  if (notifOpen) { notifications.forEach(n=>n.read=true); renderNotifications() }
}
document.addEventListener('click', e => {
  if (notifOpen && !e.target.closest('#notif-panel') && !e.target.closest('#notif-bell')) toggleNotifPanel()
})

// SSE
let sseConn = null
function connectSSE() {
  if (!TOKEN) return
  if (sseConn) sseConn.close()
  sseConn = new EventSource('/api/v1/events')
  sseConn.onmessage = function(e) {
    try {
      const msg = JSON.parse(e.data)
      if (msg.type === 'scan_complete') {
        addNotification('Scan complete — ' + msg.mode, msg.gate==='PASS'?'success':'error', msg.findings + ' findings · ' + msg.gate + ' · ' + (msg.rid||'').slice(-8))
        showToast('Scan complete: ' + msg.gate, msg.gate==='PASS'?'success':'error')
        loadDashboard(); loadDashboardCharts()
      } else if (msg.type === 'scan_started') {
        addNotification('Scan started — ' + msg.mode, 'scan', 'Run ' + (msg.rid||'').slice(-8))
      }
    } catch(e) {}
  }
  sseConn.onerror = () => setTimeout(connectSSE, 5000)
}

// Override showApp to connect SSE + add welcome notif
const _origShowApp = showApp
window.showApp = function() {
  _origShowApp()
  connectSSE()
  setTimeout(() => addNotification('VSP Platform ready', 'info', 'SSE real-time active · v0.4.1'), 600)
}

// Override statusPill for new style
window.statusPill = function(s) {
  const m = {QUEUED:'queued',RUNNING:'running',DONE:'done',FAILED:'fail',CANCELLED:'queued'}
  return `<span class="pill pill-${m[s]||'queued'}">${s}</span>`
}
window.gatePill = function(g) {
  const m = {PASS:'pass',WARN:'warn',FAIL:'fail'}
  return `<span class="pill pill-${m[g]||'queued'}">${g}</span>`
}
window.sevPill = function(s) {
  const c = {CRITICAL:'var(--red)',HIGH:'#ff8c00',MEDIUM:'var(--amber)',LOW:'var(--green)',INFO:'var(--text3)'}
  return `<span style="color:${c[s]||'var(--text2)'};font-weight:600;font-size:11px;letter-spacing:.05em">${s}</span>`
}

// SBOM functions
async function loadSBOM() {
  try {
    const data = await api('GET', '/vsp/runs/index')
    const runs = (data.runs||[]).filter(r=>r.status==='DONE').slice(0,20)
    document.getElementById('sbom-tbody').innerHTML = runs.map(r => `<tr>
      <td><code>${r.rid.slice(-16)}</code></td>
      <td><span class="pill pill-queued">${r.mode}</span></td>
      <td>${r.gate?gatePill(r.gate):'—'}</td>
      <td style="color:${(r.total||0)>0?'var(--red)':'var(--green)'}">${r.total||0}</td>
      <td style="color:var(--text3)">${new Date(r.created_at).toLocaleDateString()}</td>
      <td><a href="#" onclick="downloadSBOM(event,'${r.rid}')" style="color:var(--amber);font-size:11px;letter-spacing:.05em;text-decoration:none;border:1px solid var(--amber);padding:2px 8px">↓ CDX</a></td>
    </tr>`).join('')
  } catch(e) { console.error('sbom',e) }
}

function downloadSBOM(e, rid) {
  e.preventDefault()
  fetch('/api/v1/sbom/'+rid,{headers:{'Authorization':'Bearer '+TOKEN}}).then(r=>r.blob()).then(blob=>{
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='sbom-'+rid.slice(-8)+'.cdx.json'; a.click()
  })
}

// FedRAMP / CMMC
async function loadFedRAMP() {
  document.getElementById('btn-fedramp').className='btn-sm btn-primary'
  document.getElementById('btn-cmmc').className='btn-sm'
  try {
    const d = await api('GET','/compliance/fedramp')
    renderCompliance2(d,'FedRAMP Moderate',d.controls,'id','family','title')
  } catch(e) {}
}
async function loadCMMC() {
  document.getElementById('btn-fedramp').className='btn-sm'
  document.getElementById('btn-cmmc').className='btn-sm btn-primary'
  try {
    const d = await api('GET','/compliance/cmmc')
    renderCompliance2(d,'CMMC Level 2',d.practices,'id','domain','practice')
  } catch(e) {}
}
function renderCompliance2(data,title,items,idKey,famKey,titleKey) {
  document.getElementById('compliance2-title').textContent=title
  const pct=data.coverage_pct||0
  document.getElementById('compliance2-coverage').textContent=pct+'%'
  document.getElementById('compliance2-bar').style.width=pct+'%'
  document.getElementById('compliance2-bar').style.background=pct>=80?'var(--cyan)':pct>=50?'var(--amber)':'var(--red)'
  document.getElementById('compliance2-assessed').textContent=(data.assessed||0)+' assessed'
  document.getElementById('compliance2-total').textContent=(data.total_controls||data.total_practices||0)+' total'
  document.getElementById('compliance2-tbody').innerHTML=(items||[]).map(c=>`<tr>
    <td><code>${c[idKey]}</code></td>
    <td style="color:var(--text2);font-size:11px">${c[famKey]}</td>
    <td style="font-size:12px">${c[titleKey]}</td>
    <td style="font-size:10px;color:var(--text3)">${c.tool||'—'}</td>
    <td><span class="pill ${c.status==='assessed'?'pill-done':'pill-queued'}">${c.status}</span></td>
  </tr>`).join('')
}

// Charts override with new color scheme
const CHART_COLORS = { CRITICAL:'#ff3d57', HIGH:'#ff8c00', MEDIUM:'#f0a500', LOW:'#00e676', INFO:'#3d4a60' }
const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { labels: { color:'#8892a4', font:{size:10,family:"'JetBrains Mono',monospace"}, boxWidth:8 } } },
  scales: {
    x: { ticks:{color:'#3d4a60',font:{size:9}}, grid:{color:'rgba(26,37,64,.5)'} },
    y: { ticks:{color:'#3d4a60',font:{size:9}}, grid:{color:'rgba(26,37,64,.5)'} }
  }
}

</script>
</body>
</html>
VSP_PREMIUM_UI

sudo systemctl restart vsp-go-shell 2>/dev/null; sleep 2
echo "Premium UI deployed: http://localhost:8922"
echo "Design: Terminal Noir — JetBrains Mono + Syne"
echo "Features: Amber accent, monospace typography, sharp geometry"
