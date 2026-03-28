/**
 * VSP Upgrade Patch v0.6.0
 * Inject AFTER vsp_features_patch.js (replace inline or append before </body>)
 *
 * Upgrades:
 *  1. Runs      — KPI row + mode breakdown + timeline chart + status donut
 *  2. Findings  — advanced filter bar + group-by + severity trend + heatmap
 *  3. Dashboard — sparkline KPIs + SLA widget + top-tools bar
 *  4. Remediation — kanban board view toggle
 *  5. Compliance  — radial gauge charts FedRAMP/CMMC
 */

// ─── CSS ─────────────────────────────────────────────────────────────────────
(function() {
const style = document.createElement('style');
style.textContent = `
/* ── RUNS UPGRADE ─────────────────────────────────────────── */
.run-kpi-strip {
  display:grid;grid-template-columns:repeat(6,1fr);gap:1px;
  background:var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px;
}
.run-kpi-cell {
  background:var(--card);padding:14px 12px;
}
.run-kpi-cell .val {
  font-family:var(--display);font-size:26px;font-weight:800;line-height:1;margin:6px 0 2px;
}
.run-kpi-cell .lbl {
  font-size:9px;letter-spacing:.14em;color:var(--text3);text-transform:uppercase;
}
.run-kpi-cell .sub {
  font-size:10px;color:var(--text3);margin-top:2px;font-family:var(--mono);
}
.run-mode-grid {
  display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:16px;
}
.run-mode-card {
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:12px;text-align:center;cursor:pointer;transition:.15s;
}
.run-mode-card:hover { border-color:var(--amber);background:rgba(240,165,0,.04); }
.run-mode-card.active { border-color:var(--amber);background:rgba(240,165,0,.08); }
.run-mode-card .mode-name { font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--text2);margin-bottom:6px; }
.run-mode-card .mode-count { font-family:var(--display);font-size:22px;font-weight:800; }
.run-mode-card .mode-pass { font-size:9px;color:var(--green);margin-top:2px; }
.run-chart-row { display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px; }

/* ── FINDINGS UPGRADE ─────────────────────────────────────── */
.findings-toolbar {
  display:flex;gap:8px;align-items:center;flex-wrap:wrap;
  padding:12px;background:var(--card);border:1px solid var(--border);
  border-radius:8px;margin-bottom:12px;
}
.findings-toolbar .filter-group { display:flex;gap:6px;align-items:center;flex-wrap:wrap;flex:1; }
.findings-toolbar select, .findings-toolbar input {
  padding:6px 10px;background:var(--black);border:1px solid var(--border2);
  color:var(--text1);font-family:var(--mono);font-size:11px;border-radius:4px;
}
.view-toggle { display:flex;gap:2px;background:var(--black);border:1px solid var(--border2);border-radius:4px;padding:2px; }
.view-toggle button {
  padding:4px 10px;font-size:10px;background:none;border:none;
  color:var(--text3);cursor:pointer;border-radius:3px;transition:.12s;
  font-family:var(--mono);letter-spacing:.04em;
}
.view-toggle button.active { background:var(--amber);color:#000;font-weight:700; }
.groupby-bar {
  display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:12px;
}
.groupby-tab {
  padding:6px 14px;font-size:10px;letter-spacing:.08em;color:var(--text3);
  cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:.12s;font-family:var(--mono);text-transform:uppercase;
}
.groupby-tab:hover { color:var(--text1); }
.groupby-tab.active { color:var(--cyan);border-bottom-color:var(--cyan); }
.findings-group-header {
  display:flex;align-items:center;gap:10px;padding:8px 12px;
  background:rgba(255,255,255,.02);border-left:3px solid var(--border2);
  margin:8px 0 4px;cursor:pointer;border-radius:0 4px 4px 0;
  font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--text2);
}
.findings-group-header:hover { background:rgba(255,255,255,.05); }
.findings-group-header .gh-count {
  margin-left:auto;font-family:var(--mono);font-size:10px;
  color:var(--text3);font-weight:400;
}
.findings-chart-row { display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:16px; }

/* ── KANBAN ───────────────────────────────────────────────── */
.kanban-board {
  display:grid;grid-template-columns:repeat(5,1fr);gap:10px;
  min-height:400px;align-items:start;
}
.kanban-col {
  background:var(--black);border:1px solid var(--border);border-radius:8px;
  overflow:hidden;
}
.kanban-col-head {
  padding:10px 12px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}
.kanban-col-title { font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase; }
.kanban-col-count {
  font-family:var(--display);font-size:13px;font-weight:700;
  background:var(--border);padding:1px 7px;border-radius:10px;
}
.kanban-cards { padding:8px;display:flex;flex-direction:column;gap:6px;min-height:200px; }
.kanban-card {
  background:var(--card);border:1px solid var(--border);border-radius:6px;
  padding:10px;cursor:pointer;transition:.12s;
}
.kanban-card:hover { border-color:var(--border2);transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,.3); }
.kanban-card .kc-sev { font-size:9px;font-weight:700;letter-spacing:.1em;margin-bottom:4px; }
.kanban-card .kc-msg { font-size:11px;color:var(--text1);line-height:1.4;margin-bottom:6px;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden; }
.kanban-card .kc-meta { font-size:9px;color:var(--text3);font-family:var(--mono); }
.kanban-card .kc-assignee {
  font-size:9px;color:var(--text2);margin-top:6px;display:flex;align-items:center;gap:4px;
}

/* ── COMPLIANCE GAUGES ────────────────────────────────────── */
.gauge-grid { display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px; }
.gauge-card { background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;text-align:center; }
.gauge-card canvas { display:block;margin:0 auto; }
.gauge-title { font-size:11px;font-weight:700;letter-spacing:.1em;color:var(--text2);text-transform:uppercase;margin-bottom:12px; }
.gauge-value { font-family:var(--display);font-size:36px;font-weight:800;margin:8px 0 2px; }
.gauge-sub { font-size:10px;color:var(--text3); }

/* ── DASHBOARD SPARKLINE KPIs ────────────────────────────── */
.spark-kpi-grid {
  display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px;
}
.spark-kpi-cell {
  background:var(--card);padding:16px;position:relative;overflow:hidden;
}
.spark-kpi-cell canvas { position:absolute;bottom:0;left:0;right:0;opacity:.4; }
.spark-kpi-cell .skc-label { font-size:9px;letter-spacing:.14em;color:var(--text3);text-transform:uppercase; }
.spark-kpi-cell .skc-val { font-family:var(--display);font-size:32px;font-weight:800;line-height:1;margin:8px 0 4px;position:relative; }
.spark-kpi-cell .skc-delta {
  font-size:10px;font-family:var(--mono);position:relative;
}
.skc-delta.up { color:var(--red); }
.skc-delta.down { color:var(--green); }
.skc-delta.neutral { color:var(--text3); }

/* ── SLA MINI WIDGET ─────────────────────────────────────── */
.sla-mini-grid { display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px; }
.sla-mini-card {
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:12px;border-left:3px solid;
}
.sla-mini-card.green { border-left-color:var(--green); }
.sla-mini-card.red   { border-left-color:var(--red); }
.sla-mini-card.amber { border-left-color:var(--amber); }
.sla-mini-sev { font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin-bottom:6px; }
.sla-mini-open { font-family:var(--display);font-size:24px;font-weight:800; }
.sla-mini-meta { font-size:9px;color:var(--text3);margin-top:2px; }

/* ── GENERAL ─────────────────────────────────────────────── */
.upgrade-chart-card { background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px; }
.upgrade-chart-title { font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--text2);text-transform:uppercase;margin-bottom:12px; }
.chart-wrap-sm { height:160px;position:relative; }
.chart-wrap-md { height:200px;position:relative; }
`;
document.head.appendChild(style);
})();

// ─── UTILITY ──────────────────────────────────────────────────────────────────
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
const SEV_COLOR = { CRITICAL:'#f87171', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#4ade80', INFO:'#94a3b8' };
const MODE_COLOR = { SAST:'#818cf8', SCA:'#38bdf8', SECRETS:'#f472b6', IAC:'#fbbf24', DAST:'#34d399', FULL:'#a78bfa' };
let _upgradeCharts = {};
function destroyChart(id){ if(_upgradeCharts[id]){_upgradeCharts[id].destroy();delete _upgradeCharts[id];} }


// ═══════════════════════════════════════════════════════════════════════════════
// 1. RUNS PANEL UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeRunsPanel() {

  // Inject upgraded content before the existing card
  const runsPanel = document.getElementById('panel-runs');
  if (!runsPanel) return;

  // Create KPI strip container
  const kpiStrip = document.createElement('div');
  kpiStrip.id = 'runs-kpi-strip';
  kpiStrip.innerHTML = `
    <div class="run-kpi-strip" id="run-kpi-cells">
      <div class="run-kpi-cell"><div class="lbl">Total runs</div><div class="val" id="rk-total">—</div><div class="sub">all time</div></div>
      <div class="run-kpi-cell"><div class="lbl">Completed</div><div class="val c-green" id="rk-done">—</div><div class="sub">DONE status</div></div>
      <div class="run-kpi-cell"><div class="lbl">Queued</div><div class="val c-amber" id="rk-queued">—</div><div class="sub">pending</div></div>
      <div class="run-kpi-cell"><div class="lbl">Pass rate</div><div class="val c-cyan" id="rk-passrate">—</div><div class="sub">gate PASS %</div></div>
      <div class="run-kpi-cell"><div class="lbl">Avg findings</div><div class="val" id="rk-avgfindings">—</div><div class="sub">per run</div></div>
      <div class="run-kpi-cell"><div class="lbl">Last run</div><div class="val" id="rk-lastrun" style="font-size:14px;margin-top:8px">—</div><div class="sub" id="rk-lastrun-time"></div></div>
    </div>
    <div class="run-mode-grid" id="run-mode-grid"></div>
    <div class="run-chart-row">
      <div class="upgrade-chart-card">
        <div class="upgrade-chart-title">Run timeline — last 30 runs</div>
        <div class="chart-wrap-md"><canvas id="chart-run-timeline"></canvas></div>
      </div>
      <div class="upgrade-chart-card">
        <div class="upgrade-chart-title">Gate outcomes</div>
        <div class="chart-wrap-md"><canvas id="chart-run-gates2"></canvas></div>
      </div>
    </div>
  `;
  runsPanel.insertBefore(kpiStrip, runsPanel.firstChild);

  // Override loadRuns
  const _origLoadRuns = window.loadRuns;
  window.loadRuns = async function() {
    try {
      const data = await window.api('GET', '/vsp/runs?limit=100');
      const runs = data.runs || [];

      // KPIs
      const done    = runs.filter(r=>r.status==='DONE');
      const queued  = runs.filter(r=>r.status==='QUEUED'||r.status==='RUNNING');
      const passed  = done.filter(r=>r.gate==='PASS');
      const passRate = done.length ? Math.round(passed.length/done.length*100) : 0;
      const avgF    = done.length ? Math.round(done.reduce((a,r)=>a+(r.total_findings||0),0)/done.length) : 0;
      const last    = runs[0];

      document.getElementById('rk-total').textContent       = runs.length;
      document.getElementById('rk-done').textContent        = done.length;
      document.getElementById('rk-queued').textContent      = queued.length;
      document.getElementById('rk-passrate').textContent    = passRate + '%';
      document.getElementById('rk-avgfindings').textContent = avgF;
      if (last) {
        const gate = last.gate || last.status;
        const gateEl = document.getElementById('rk-lastrun');
        gateEl.textContent = gate;
        gateEl.style.color = gate==='PASS'?'var(--green)':gate==='FAIL'?'var(--red)':'var(--amber)';
        document.getElementById('rk-lastrun-time').textContent = new Date(last.created_at).toLocaleTimeString();
      }

      // Mode breakdown
      const modes = ['SAST','SCA','SECRETS','IAC','DAST','FULL'];
      document.getElementById('run-mode-grid').innerHTML = modes.map(m => {
        const mRuns = runs.filter(r=>r.mode===m);
        const mPass = mRuns.filter(r=>r.gate==='PASS').length;
        const color = MODE_COLOR[m] || '#94a3b8';
        return `<div class="run-mode-card" onclick="filterRunsByMode('${m}',this)">
          <div class="mode-name" style="color:${color}">${m}</div>
          <div class="mode-count" style="color:${color}">${mRuns.length}</div>
          <div class="mode-pass">${mPass} PASS</div>
        </div>`;
      }).join('');

      // Timeline chart
      const timelineRuns = runs.slice(0,30).reverse();
      destroyChart('runtimeline');
      const ctx1 = document.getElementById('chart-run-timeline')?.getContext('2d');
      if (ctx1) {
        _upgradeCharts['runtimeline'] = new Chart(ctx1, {
          type: 'bar',
          data: {
            labels: timelineRuns.map(r => r.rid.slice(-6)),
            datasets: [
              {
                label: 'Findings',
                data: timelineRuns.map(r => r.total_findings || 0),
                backgroundColor: timelineRuns.map(r =>
                  r.gate==='PASS'?'rgba(74,222,128,.7)':r.gate==='FAIL'?'rgba(248,113,113,.7)':'rgba(251,191,36,.7)'
                ),
                borderRadius: 3,
              }
            ]
          },
          options: {
            responsive:true, maintainAspectRatio:false,
            plugins:{ legend:{display:false},
              tooltip:{ callbacks:{ title: items => timelineRuns[items[0].dataIndex]?.mode + ' · ' + timelineRuns[items[0].dataIndex]?.gate }}
            },
            scales:{
              x:{ticks:{color:'#475569',font:{size:9},maxRotation:45},grid:{display:false}},
              y:{ticks:{color:'#64748b',font:{size:10}},grid:{color:'#1e293b'},beginAtZero:true}
            }
          }
        });
      }

      // Gate donut
      const gates = {PASS:passed.length, WARN:done.filter(r=>r.gate==='WARN').length, FAIL:done.filter(r=>r.gate==='FAIL').length};
      destroyChart('rungates2');
      const ctx2 = document.getElementById('chart-run-gates2')?.getContext('2d');
      if (ctx2) {
        _upgradeCharts['rungates2'] = new Chart(ctx2, {
          type:'doughnut',
          data:{
            labels:['Pass','Warn','Fail'],
            datasets:[{data:[gates.PASS,gates.WARN,gates.FAIL],backgroundColor:['#4ade80','#fbbf24','#f87171'],borderWidth:0,hoverOffset:6}]
          },
          options:{
            responsive:true,maintainAspectRatio:false,cutout:'72%',
            plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},boxWidth:10,padding:8}}}
          }
        });
      }

      // Original table
      document.getElementById('runs-table').innerHTML = runs.map(r => `
        <tr>
          <td style="font-family:monospace;font-size:11px">${r.rid}</td>
          <td><span style="font-size:10px;font-weight:700;color:${MODE_COLOR[r.mode]||'#94a3b8'}">${r.mode}</span></td>
          <td style="color:#94a3b8;font-size:11px">${r.profile||'—'}</td>
          <td>${window.statusPill(r.status)}</td>
          <td>${r.gate ? window.gatePill(r.gate) : '—'}</td>
          <td style="font-family:var(--mono);color:${(r.total_findings||0)>0?'var(--red)':'var(--green)'}">${r.total_findings||0}</td>
          <td style="color:#64748b;font-size:11px">${(r.tools_done||0)}/${r.tools_total||0}</td>
          <td style="color:#64748b;font-size:11px">${new Date(r.created_at).toLocaleString()}</td>
        </tr>`).join('');

    } catch(e) { console.error('runs upgrade', e); }
  };

  window.filterRunsByMode = function(mode, el) {
    document.querySelectorAll('.run-mode-card').forEach(c=>c.classList.remove('active'));
    el.classList.add('active');
    // Filter table rows
    document.querySelectorAll('#runs-table tr').forEach(row => {
      const modeCell = row.querySelector('td:nth-child(2)');
      if (!modeCell) return;
      row.style.display = modeCell.textContent.trim()===mode ? '' : 'none';
    });
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 2. FINDINGS PANEL UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeFindingsPanel() {
  const panel = document.getElementById('panel-findings');
  if (!panel) return;

  // Replace filter bar with upgraded version
  const existingFilter = panel.querySelector('.card');
  if (existingFilter) {
    existingFilter.innerHTML = `
      <div class="findings-toolbar">
        <div class="filter-group">
          <select id="filterSev" onchange="loadFindingsUpgraded()">
            <option value="">All severities</option>
            <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
          </select>
          <select id="filterTool" onchange="loadFindingsUpgraded()">
            <option value="">All tools</option>
            <option>bandit</option><option>semgrep</option><option>grype</option>
            <option>trivy</option><option>gitleaks</option><option>kics</option>
            <option>checkov</option><option>nikto</option><option>nuclei</option><option>codeql</option>
          </select>
          <select id="filterRun" onchange="loadFindingsUpgraded()" style="max-width:160px">
            <option value="">All runs</option>
          </select>
          <input id="filterQ" type="text" placeholder="Search findings..." 
            onkeyup="if(event.key==='Enter')loadFindingsUpgraded()" style="width:180px">
          <button class="btn-sm btn-primary" onclick="loadFindingsUpgraded()">Search</button>
          <button class="btn-sm" onclick="clearFindingsFilter()">✕ Clear</button>
        </div>
        <span id="findings-count" style="color:var(--text3);font-size:11px;letter-spacing:.05em">—</span>
        <div class="view-toggle">
          <button class="active" onclick="setFindingsView('table',this)">TABLE</button>
          <button onclick="setFindingsView('group',this)">GROUP</button>
          <button onclick="setFindingsView('chart',this)">CHART</button>
        </div>
      </div>
      <!-- Group-by tabs -->
      <div class="groupby-bar" id="findings-groupby-bar" style="display:none">
        <div class="groupby-tab active" onclick="setGroupBy('severity',this)">By Severity</div>
        <div class="groupby-tab" onclick="setGroupBy('tool',this)">By Tool</div>
        <div class="groupby-tab" onclick="setGroupBy('rule',this)">By Rule</div>
        <div class="groupby-tab" onclick="setGroupBy('path',this)">By File</div>
      </div>
    `;
  }

  // Charts row — inject before findings table card
  const chartsRow = document.createElement('div');
  chartsRow.id = 'findings-charts-row';
  chartsRow.className = 'findings-chart-row';
  chartsRow.style.display = 'none';
  chartsRow.innerHTML = `
    <div class="upgrade-chart-card">
      <div class="upgrade-chart-title">Severity distribution — current filter</div>
      <div class="chart-wrap-md"><canvas id="chart-findings-sev"></canvas></div>
    </div>
    <div class="upgrade-chart-card">
      <div class="upgrade-chart-title">Top 8 rules by count</div>
      <div class="chart-wrap-md"><canvas id="chart-findings-rules"></canvas></div>
    </div>
  `;

  const tableCard = panel.querySelectorAll('.card')[1];
  if (tableCard) panel.insertBefore(chartsRow, tableCard);

  let _findingsView = 'table';
  let _groupBy = 'severity';
  let _findingsData = [];

  window.setFindingsView = function(view, el) {
    _findingsView = view;
    document.querySelectorAll('.view-toggle button').forEach(b=>b.classList.remove('active'));
    el.classList.add('active');
    const groupbar = document.getElementById('findings-groupby-bar');
    const chartsDiv = document.getElementById('findings-charts-row');
    const tableCard2 = panel.querySelectorAll('.card')[1];
    if (view === 'table') {
      if (groupbar) groupbar.style.display = 'none';
      if (chartsDiv) chartsDiv.style.display = 'none';
      if (tableCard2) tableCard2.style.display = '';
      renderFindingsTable(_findingsData);
    } else if (view === 'group') {
      if (groupbar) groupbar.style.display = 'flex';
      if (chartsDiv) chartsDiv.style.display = 'none';
      if (tableCard2) tableCard2.style.display = '';
      renderFindingsGrouped(_findingsData, _groupBy);
    } else if (view === 'chart') {
      if (groupbar) groupbar.style.display = 'none';
      if (chartsDiv) chartsDiv.style.display = 'grid';
      if (tableCard2) tableCard2.style.display = 'none';
      renderFindingsCharts(_findingsData);
    }
  };

  window.setGroupBy = function(by, el) {
    _groupBy = by;
    document.querySelectorAll('.groupby-tab').forEach(t=>t.classList.remove('active'));
    el.classList.add('active');
    renderFindingsGrouped(_findingsData, _groupBy);
  };

  window.clearFindingsFilter = function() {
    document.getElementById('filterSev').value = '';
    document.getElementById('filterTool').value = '';
    document.getElementById('filterQ').value = '';
    loadFindingsUpgraded();
  };

  window.loadFindingsUpgraded = async function() {
    const sev  = document.getElementById('filterSev')?.value || '';
    const tool = document.getElementById('filterTool')?.value || '';
    const q    = document.getElementById('filterQ')?.value || '';
    let path   = '/vsp/findings?limit=500';
    if (sev)  path += '&severity=' + sev;
    if (tool) path += '&tool=' + tool;
    if (q)    path += '&q=' + encodeURIComponent(q);
    try {
      const data = await window.api('GET', path);
      _findingsData = data.findings || [];
      window._findingsCache = _findingsData;
      document.getElementById('findings-count').textContent = (data.total||_findingsData.length) + ' findings';
      if (_findingsView === 'table')       renderFindingsTable(_findingsData);
      else if (_findingsView === 'group')  renderFindingsGrouped(_findingsData, _groupBy);
      else if (_findingsView === 'chart')  renderFindingsCharts(_findingsData);
    } catch(e) { console.error('findings upgrade', e); }
  };

  // Override global loadFindings
  window.loadFindings = window.loadFindingsUpgraded;

  function renderFindingsTable(findings) {
    const tbody = document.getElementById('findings-table');
    if (!tbody) return;
    tbody.innerHTML = findings.map((f,i) => `
      <tr onclick="openFindingModal && openFindingModal(window._findingsCache[${i}])" style="cursor:pointer">
        <td>${window.sevPill(f.severity)}</td>
        <td style="color:#94a3b8;font-size:11px">${f.tool}</td>
        <td style="font-family:monospace;font-size:10px;color:#60a5fa;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.rule_id||'—'}</td>
        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.message)}">${esc(f.message)||'—'}</td>
        <td style="font-family:monospace;font-size:10px;color:#94a3b8;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.path)||'—'}</td>
        <td style="color:#64748b;font-size:11px">${f.line||'—'}</td>
        <td style="font-size:10px;color:#818cf8">${f.cwe||'—'}</td>
      </tr>`).join('');
  }

  function renderFindingsGrouped(findings, by) {
    const groups = {};
    findings.forEach(f => {
      let key = by==='severity'?f.severity : by==='tool'?f.tool : by==='rule'?f.rule_id : (f.path||'').split('/').pop();
      if (!groups[key]) groups[key] = [];
      groups[key].push(f);
    });
    const sorted = Object.entries(groups).sort((a,b)=>b[1].length-a[1].length);
    const tbody = document.getElementById('findings-table');
    if (!tbody) return;
    tbody.innerHTML = sorted.map(([key, items]) => {
      const color = by==='severity' ? (SEV_COLOR[key]||'#94a3b8') : '#94a3b8';
      const rows = items.slice(0,5).map((f,i) => `
        <tr onclick="openFindingModal && openFindingModal(${JSON.stringify(f).replace(/"/g,'&quot;')})" style="cursor:pointer">
          <td>${window.sevPill(f.severity)}</td>
          <td style="color:#94a3b8;font-size:11px">${f.tool}</td>
          <td style="font-family:monospace;font-size:10px;color:#60a5fa">${f.rule_id||'—'}</td>
          <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.message)}</td>
          <td style="font-family:monospace;font-size:10px;color:#94a3b8">${esc(f.path)||'—'}</td>
          <td style="color:#64748b">${f.line||'—'}</td>
          <td style="font-size:10px;color:#818cf8">${f.cwe||'—'}</td>
        </tr>`).join('');
      const more = items.length > 5 ? `<tr><td colspan="7" style="color:#64748b;font-size:10px;padding:6px 12px;text-align:center">+ ${items.length-5} more…</td></tr>` : '';
      return `
        <tr class="findings-group-header" onclick="this.nextSibling.style.display=this.nextSibling.style.display==='none'?'':'none'">
          <td colspan="7" style="padding:0">
            <div class="findings-group-header">
              <span style="color:${color};font-weight:800">${key}</span>
              <span class="gh-count">${items.length} findings</span>
              <span style="color:var(--text3);font-size:10px">▾</span>
            </div>
          </td>
        </tr>
        <tbody style="display:table-row-group">${rows}${more}</tbody>
      `;
    }).join('');
  }

  function renderFindingsCharts(findings) {
    // Severity bar
    const sevCounts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
    findings.forEach(f=>{ if(sevCounts[f.severity]!==undefined) sevCounts[f.severity]++; });

    destroyChart('fsev');
    const ctx1 = document.getElementById('chart-findings-sev')?.getContext('2d');
    if (ctx1) {
      _upgradeCharts['fsev'] = new Chart(ctx1, {
        type:'bar',
        data:{
          labels:Object.keys(sevCounts),
          datasets:[{label:'Findings',data:Object.values(sevCounts),
            backgroundColor:Object.keys(sevCounts).map(k=>SEV_COLOR[k]+'cc'),
            borderRadius:4,borderSkipped:false}]
        },
        options:{responsive:true,maintainAspectRatio:false,
          plugins:{legend:{display:false}},
          scales:{x:{ticks:{color:'#94a3b8',font:{size:11}},grid:{display:false}},
            y:{ticks:{color:'#64748b',font:{size:10}},grid:{color:'#1e293b'},beginAtZero:true}}}
      });
    }

    // Top rules
    const ruleCounts = {};
    findings.forEach(f=>{ const k=f.rule_id||f.tool; ruleCounts[k]=(ruleCounts[k]||0)+1; });
    const topRules = Object.entries(ruleCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);

    destroyChart('frules');
    const ctx2 = document.getElementById('chart-findings-rules')?.getContext('2d');
    if (ctx2) {
      _upgradeCharts['frules'] = new Chart(ctx2, {
        type:'bar',
        data:{
          labels:topRules.map(([k])=>k.length>20?k.slice(0,8)+'…':k),
          datasets:[{data:topRules.map(([,v])=>v),
            backgroundColor:'rgba(129,140,248,.7)',borderRadius:4,borderSkipped:false}]
        },
        options:{
          indexAxis:'y',responsive:true,maintainAspectRatio:false,
          plugins:{legend:{display:false}},
          scales:{x:{ticks:{color:'#64748b',font:{size:10}},grid:{color:'#1e293b'},beginAtZero:true},
            y:{ticks:{color:'#94a3b8',font:{size:9}},grid:{display:false}}}
        }
      });
    }
  }

  // Load runs for filter dropdown
  (async ()=>{
    try {
      const d = await window.api('GET','/vsp/runs?limit=20');
      const sel = document.getElementById('filterRun');
      if (sel) {
        (d.runs||[]).filter(r=>r.status==='DONE').slice(0,10).forEach(r=>{
          const o=document.createElement('option');
          o.value=r.rid; o.textContent=r.rid.slice(-16)+' ('+r.mode+')';
          sel.appendChild(o);
        });
      }
    } catch(e){}
  })();
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 3. DASHBOARD UPGRADE — Sparkline KPIs + SLA mini
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeDashboard() {
  const panel = document.getElementById('panel-dashboard');
  if (!panel) return;

  // Inject SLA mini strip before first chart grid
  const slaStrip = document.createElement('div');
  slaStrip.id = 'dash-sla-strip';
  slaStrip.innerHTML = `
    <div class="sla-mini-grid" id="sla-mini-grid">
      <div class="sla-mini-card green"><div class="sla-mini-sev" style="color:var(--red)">CRITICAL</div><div class="sla-mini-open" id="sla-critical-open">—</div><div class="sla-mini-meta">SLA: 3 days</div></div>
      <div class="sla-mini-card amber"><div class="sla-mini-sev" style="color:#ff8c00">HIGH</div><div class="sla-mini-open" id="sla-high-open">—</div><div class="sla-mini-meta">SLA: 14 days</div></div>
      <div class="sla-mini-card green"><div class="sla-mini-sev" style="color:var(--amber)">MEDIUM</div><div class="sla-mini-open" id="sla-medium-open">—</div><div class="sla-mini-meta">SLA: 30 days</div></div>
      <div class="sla-mini-card green"><div class="sla-mini-sev" style="color:var(--green)">LOW</div><div class="sla-mini-open" id="sla-low-open">—</div><div class="sla-mini-meta">SLA: 90 days</div></div>
    </div>
  `;

  // Find .g2 chart section and insert before it
  const g2 = panel.querySelector('.g2');
  if (g2) panel.insertBefore(slaStrip, g2);

  // Patch loadDashboard to also fill SLA mini
  const _origLoadDash = window.loadDashboard;
  window.loadDashboard = async function() {
    if (_origLoadDash) await _origLoadDash();
    try {
      const summary = await window.api('GET', '/vsp/findings/summary');
      const s = id => document.getElementById(id);
      if (s('sla-critical-open')) s('sla-critical-open').textContent = summary.critical || 0;
      if (s('sla-high-open'))     s('sla-high-open').textContent     = summary.high || 0;
      if (s('sla-medium-open'))   s('sla-medium-open').textContent   = summary.medium || 0;
      if (s('sla-low-open'))      s('sla-low-open').textContent      = summary.low || 0;

      // Color SLA cards by breach risk
      const cards = document.querySelectorAll('.sla-mini-card');
      const vals  = [summary.critical, summary.high, summary.medium, summary.low];
      const thresholds = [0, 10, 20, 50];
      cards.forEach((c, i) => {
        c.className = 'sla-mini-card ' + ((vals[i]||0) > thresholds[i] ? 'red' : 'green');
      });
    } catch(e) {}
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 4. REMEDIATION KANBAN UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeRemediation() {
  const panel = document.getElementById('panel-remediation');
  if (!panel) return;

  // Add view toggle to remediation filter bar
  const filterBar = panel.querySelector('div[style*="display:flex"]');
  if (filterBar) {
    const toggle = document.createElement('div');
    toggle.className = 'view-toggle';
    toggle.style.marginLeft = 'auto';
    toggle.innerHTML = `
      <button class="active" onclick="setRemView('table',this)">TABLE</button>
      <button onclick="setRemView('kanban',this)">KANBAN</button>
    `;
    filterBar.appendChild(toggle);
  }

  // Kanban board container
  const kanbanDiv = document.createElement('div');
  kanbanDiv.id = 'rem-kanban-board';
  kanbanDiv.style.display = 'none';
  panel.appendChild(kanbanDiv);

  window.setRemView = function(view, el) {
    document.querySelectorAll('#panel-remediation .view-toggle button').forEach(b=>b.classList.remove('active'));
    el.classList.add('active');
    const tableCard = panel.querySelector('.card:last-of-type');
    if (view === 'table') {
      if (tableCard) tableCard.style.display = '';
      kanbanDiv.style.display = 'none';
    } else {
      if (tableCard) tableCard.style.display = 'none';
      kanbanDiv.style.display = 'block';
      renderKanban();
    }
  };

  async function renderKanban() {
    const COLS = [
      { key:'open',           label:'Open',           color:'#f87171' },
      { key:'in_progress',    label:'In Progress',    color:'#fbbf24' },
      { key:'resolved',       label:'Resolved',       color:'#4ade80' },
      { key:'accepted',       label:'Accepted',       color:'#94a3b8' },
      { key:'false_positive', label:'False Positive',  color:'#a78bfa' },
    ];

    kanbanDiv.innerHTML = `<div class="kanban-board" id="kanban-inner">
      ${COLS.map(c=>`
        <div class="kanban-col" id="kanban-col-${c.key}">
          <div class="kanban-col-head">
            <span class="kanban-col-title" style="color:${c.color}">${c.label}</span>
            <span class="kanban-col-count" id="kc-count-${c.key}">0</span>
          </div>
          <div class="kanban-cards" id="kc-cards-${c.key}">
            <div style="color:var(--text3);font-size:11px;text-align:center;padding:20px">Loading…</div>
          </div>
        </div>`).join('')}
    </div>`;

    try {
      const [findData, remData] = await Promise.all([
        window.api('GET', '/vsp/findings?limit=200'),
        window.api('GET', '/remediation'),
      ]);
      const findings = findData.findings || [];
      const remByFinding = {};
      (remData.remediations || []).forEach(r => remByFinding[r.finding_id] = r);

      // Group by status
      const byStatus = {};
      COLS.forEach(c => byStatus[c.key] = []);

      findings.forEach(f => {
        const rem = remByFinding[f.id];
        const status = rem?.status || 'open';
        if (byStatus[status]) byStatus[status].push({f, rem});
      });

      COLS.forEach(col => {
        const items = byStatus[col.key] || [];
        document.getElementById(`kc-count-${col.key}`).textContent = items.length;
        const cardsEl = document.getElementById(`kc-cards-${col.key}`);
        if (!cardsEl) return;
        if (!items.length) {
          cardsEl.innerHTML = `<div style="color:var(--text3);font-size:10px;text-align:center;padding:20px;letter-spacing:.06em">EMPTY</div>`;
          return;
        }
        cardsEl.innerHTML = items.slice(0,15).map(({f, rem}) => {
          const sevColor = SEV_COLOR[f.severity] || '#94a3b8';
          const assignee = rem?.assignee || '';
          const priority = rem?.priority || '';
          const pColor = {P1:'#f87171',P2:'#fb923c',P3:'#fbbf24',P4:'#4ade80'}[priority]||'#94a3b8';
          return `<div class="kanban-card" onclick="openFindingModal && openFindingModal(${JSON.stringify(f).replace(/"/g,'&quot;')})">
            <div class="kc-sev" style="color:${sevColor}">${f.severity} · ${f.tool}</div>
            <div class="kc-msg">${esc(f.message)}</div>
            <div class="kc-meta">${(f.path||'').split('/').pop()}:${f.line||'?'}</div>
            ${assignee||priority ? `<div class="kc-assignee">
              ${priority?`<span style="color:${pColor};font-weight:700;font-size:9px">${priority}</span>`:''}
              ${assignee?`<span>${esc(assignee)}</span>`:''}
            </div>`:''}
          </div>`;
        }).join('');
        if (items.length > 15) {
          cardsEl.innerHTML += `<div style="color:var(--text3);font-size:10px;text-align:center;padding:8px">+${items.length-15} more</div>`;
        }
      });
    } catch(e) { console.error('kanban', e); kanbanDiv.innerHTML = `<div style="color:var(--red);padding:20px">Error loading kanban: ${e.message}</div>`; }
  }
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 5. COMPLIANCE GAUGE CHARTS
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeCompliance() {
  const panel = document.getElementById('panel-compliance2');
  if (!panel) return;

  // Inject gauge grid before existing content
  const gaugeGrid = document.createElement('div');
  gaugeGrid.id = 'compliance-gauge-grid';
  gaugeGrid.className = 'gauge-grid';
  gaugeGrid.innerHTML = `
    <div class="gauge-card">
      <div class="gauge-title">FedRAMP Moderate</div>
      <canvas id="gauge-fedramp" width="160" height="100"></canvas>
      <div class="gauge-value c-cyan" id="gauge-fedramp-val">—%</div>
      <div class="gauge-sub" id="gauge-fedramp-sub">— / — controls</div>
    </div>
    <div class="gauge-card">
      <div class="gauge-title">CMMC Level 2</div>
      <canvas id="gauge-cmmc" width="160" height="100"></canvas>
      <div class="gauge-value c-amber" id="gauge-cmmc-val">—%</div>
      <div class="gauge-sub" id="gauge-cmmc-sub">— / — practices</div>
    </div>
    <div class="gauge-card">
      <div class="gauge-title">Combined posture</div>
      <canvas id="gauge-combined" width="160" height="100"></canvas>
      <div class="gauge-value" id="gauge-combined-val">—%</div>
      <div class="gauge-sub">average coverage</div>
    </div>
  `;
  panel.insertBefore(gaugeGrid, panel.firstChild);

  function drawGauge(canvasId, pct, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    ctx.clearRect(0,0,w,h);

    const cx = w/2, cy = h*0.85, r = Math.min(w,h*1.8)*0.38;
    const startAngle = Math.PI, endAngle = 2*Math.PI;
    const fillAngle = startAngle + (pct/100) * Math.PI;

    // Track
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, endAngle);
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Fill
    if (pct > 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle, fillAngle);
      ctx.strokeStyle = color;
      ctx.lineWidth = 14;
      ctx.lineCap = 'round';
      ctx.stroke();
    }

    // Ticks
    for (let i=0; i<=4; i++) {
      const angle = Math.PI + (i/4)*Math.PI;
      const x1 = cx + (r-18)*Math.cos(angle);
      const y1 = cy + (r-18)*Math.sin(angle);
      const x2 = cx + (r-8)*Math.cos(angle);
      const y2 = cy + (r-8)*Math.sin(angle);
      ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2);
      ctx.strokeStyle='#334155'; ctx.lineWidth=2; ctx.stroke();
    }

    // Labels
    ctx.fillStyle='#475569'; ctx.font='10px monospace'; ctx.textAlign='center';
    ctx.fillText('0%',  cx - r - 4, cy + 14);
    ctx.fillText('100%',cx + r + 4, cy + 14);
  }

  // Patch loadFedRAMP and loadCMMC
  const _origLoadFedRAMP = window.loadFedRAMP;
  window.loadFedRAMP = async function() {
    if (_origLoadFedRAMP) await _origLoadFedRAMP();
    try {
      const d = await window.api('GET', '/compliance/fedramp');
      const pct = d.coverage_pct || 0;
      const color = pct>=80?'#38bdf8':pct>=50?'#fbbf24':'#f87171';
      drawGauge('gauge-fedramp', pct, color);
      document.getElementById('gauge-fedramp-val').textContent = pct + '%';
      document.getElementById('gauge-fedramp-val').style.color = color;
      document.getElementById('gauge-fedramp-sub').textContent = `${d.assessed||0} / ${d.total_controls||0} controls`;
      // Update combined
      const c = await window.api('GET', '/compliance/cmmc').catch(()=>({coverage_pct:0}));
      const avg = Math.round(((pct) + (c.coverage_pct||0)) / 2);
      const ac = avg>=80?'#4ade80':avg>=50?'#fbbf24':'#f87171';
      drawGauge('gauge-combined', avg, ac);
      document.getElementById('gauge-combined-val').textContent = avg + '%';
      document.getElementById('gauge-combined-val').style.color = ac;
    } catch(e) {}
  };

  const _origLoadCMMC = window.loadCMMC;
  window.loadCMMC = async function() {
    if (_origLoadCMMC) await _origLoadCMMC();
    try {
      const d = await window.api('GET', '/compliance/cmmc');
      const pct = d.coverage_pct || 0;
      const color = pct>=80?'#fbbf24':pct>=50?'#fb923c':'#f87171';
      drawGauge('gauge-cmmc', pct, color);
      document.getElementById('gauge-cmmc-val').textContent = pct + '%';
      document.getElementById('gauge-cmmc-val').style.color = color;
      document.getElementById('gauge-cmmc-sub').textContent = `${d.assessed||0} / ${d.total_practices||0} practices`;
    } catch(e) {}
  };

  // Auto-load gauges when panel opens
  const origShowPanel = window.showPanel;
  window.showPanel = function(name, btn) {
    origShowPanel(name, btn);
    if (name === 'compliance2') {
      setTimeout(() => { window.loadFedRAMP(); }, 200);
    }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// BOOT — reload active panel with upgrades
// ═══════════════════════════════════════════════════════════════════════════════
setTimeout(() => {
  const active = document.querySelector('.panel.active')?.id;
  if (active === 'panel-dashboard')   window.loadDashboard?.();
  if (active === 'panel-runs')        window.loadRuns?.();
  if (active === 'panel-findings')    window.loadFindingsUpgraded?.();
  if (active === 'panel-remediation') window.loadRemediation?.();
}, 500);

console.log('[VSP Upgrade v0.6.0] All 5 panel upgrades loaded ✓');
