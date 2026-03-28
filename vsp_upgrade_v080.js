/**
 * VSP Upgrade Patch v0.8.0
 * New upgrades:
 *  1. Governance — radar chart + risk heatmap + RACI visual
 *  2. SOC — incident timeline + framework radar
 *  3. Findings — pagination (50/page) + export CSV button
 *  4. Dashboard — real-time last-scan ticker + score trend sparkline
 *  5. General — keyboard shortcuts + quick search (/)
 */

(function vsp080(){

// ─── CSS ─────────────────────────────────────────────────────────────────────
const s = document.createElement('style');
s.textContent = `
/* ── GOVERNANCE ──────────────────────────────────────── */
.gov-grid { display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px; }
.gov-radar-card { background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px; }
.risk-heatmap { display:grid;grid-template-columns:repeat(5,1fr);gap:4px;margin-top:8px; }
.risk-cell {
  aspect-ratio:1;border-radius:4px;display:flex;align-items:center;
  justify-content:center;font-size:9px;font-weight:700;letter-spacing:.06em;
  cursor:pointer;transition:.15s;
}
.risk-cell:hover { transform:scale(1.05); }
.risk-label-row { display:flex;justify-content:space-between;font-size:9px;color:var(--text3);margin-top:4px; }
.raci-table { width:100%;border-collapse:collapse;font-size:11px; }
.raci-table th { padding:6px 10px;background:var(--black);color:var(--text3);font-size:9px;letter-spacing:.1em;text-transform:uppercase;text-align:left;border-bottom:1px solid var(--border); }
.raci-table td { padding:8px 10px;border-bottom:1px solid var(--border);color:var(--text2); }
.raci-badge { display:inline-block;width:22px;height:22px;border-radius:50%;font-size:10px;font-weight:800;display:inline-flex;align-items:center;justify-content:center; }
.raci-R { background:rgba(248,113,113,.2);color:#f87171; }
.raci-A { background:rgba(251,191,36,.2);color:#fbbf24; }
.raci-C { background:rgba(56,189,248,.2);color:#38bdf8; }
.raci-I { background:rgba(148,163,184,.15);color:#94a3b8; }

/* ── SOC UPGRADE ─────────────────────────────────────── */
.soc-timeline { position:relative;padding-left:24px;margin-top:8px; }
.soc-timeline::before { content:'';position:absolute;left:7px;top:0;bottom:0;width:2px;background:var(--border); }
.soc-tl-item { position:relative;margin-bottom:16px; }
.soc-tl-dot {
  position:absolute;left:-20px;top:3px;width:10px;height:10px;
  border-radius:50%;border:2px solid var(--card);flex-shrink:0;
}
.soc-tl-content { background:var(--black);border:1px solid var(--border);border-radius:6px;padding:10px 12px; }
.soc-tl-title { font-size:12px;font-weight:600;color:var(--text1);margin-bottom:3px; }
.soc-tl-meta { font-size:10px;color:var(--text3);font-family:var(--mono); }
.soc-pillars-grid { display:grid;grid-template-columns:repeat(7,1fr);gap:6px;margin-top:8px; }
.soc-pillar-cell {
  background:var(--black);border:1px solid var(--border);border-radius:6px;
  padding:10px 6px;text-align:center;
}
.soc-pillar-score { font-family:var(--display);font-size:20px;font-weight:800;line-height:1; }
.soc-pillar-name { font-size:8px;letter-spacing:.06em;color:var(--text3);margin-top:4px;text-transform:uppercase; }

/* ── FINDINGS PAGINATION ─────────────────────────────── */
.findings-pagination {
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 0;margin-top:8px;
}
.pagination-info { font-size:11px;color:var(--text3);font-family:var(--mono); }
.pagination-btns { display:flex;gap:4px; }
.page-btn {
  padding:4px 10px;font-size:10px;background:var(--black);border:1px solid var(--border2);
  color:var(--text2);cursor:pointer;border-radius:3px;font-family:var(--mono);transition:.12s;
}
.page-btn:hover { border-color:var(--amber);color:var(--amber); }
.page-btn.active { background:var(--amber);color:#000;border-color:var(--amber);font-weight:700; }
.page-btn:disabled { opacity:.3;cursor:not-allowed; }

/* ── QUICK SEARCH ────────────────────────────────────── */
#quick-search-overlay {
  display:none;position:fixed;inset:0;z-index:9999;
  background:rgba(0,0,0,.8);backdrop-filter:blur(6px);
  align-items:flex-start;justify-content:center;padding-top:15vh;
}
#quick-search-overlay.open { display:flex; }
#quick-search-box {
  background:var(--card);border:1px solid var(--border2);
  border-radius:12px;width:min(600px,90%);
  box-shadow:0 32px 80px rgba(0,0,0,.6);overflow:hidden;
}
#quick-search-input {
  width:100%;padding:16px 20px;background:none;border:none;
  color:var(--text1);font-size:16px;font-family:var(--mono);outline:none;
  border-bottom:1px solid var(--border);
}
#quick-search-results { max-height:360px;overflow-y:auto; }
.qs-result {
  display:flex;align-items:center;gap:12px;padding:10px 20px;
  cursor:pointer;transition:.1s;border-bottom:1px solid var(--border);
}
.qs-result:hover, .qs-result.selected { background:rgba(240,165,0,.08); }
.qs-result-icon { font-size:14px;width:20px;text-align:center;flex-shrink:0; }
.qs-result-main { flex:1;min-width:0; }
.qs-result-title { font-size:12px;color:var(--text1);font-weight:600; }
.qs-result-sub { font-size:10px;color:var(--text3); }
.qs-result-badge { font-size:9px;color:var(--text3);letter-spacing:.08em;white-space:nowrap; }
.qs-section-header { padding:6px 20px;font-size:9px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;background:rgba(0,0,0,.2); }
#quick-search-hint { padding:8px 20px;font-size:10px;color:var(--text3);font-family:var(--mono); }

/* ── DASHBOARD TICKER ────────────────────────────────── */
#dash-ticker {
  display:flex;align-items:center;gap:12px;
  padding:8px 16px;background:rgba(240,165,0,.06);
  border:1px solid rgba(240,165,0,.15);border-radius:6px;
  margin-bottom:14px;font-size:11px;font-family:var(--mono);
  overflow:hidden;
}
.ticker-dot { width:6px;height:6px;border-radius:50%;background:var(--green);animation:ssePulse 2s infinite;flex-shrink:0; }
.ticker-label { color:var(--text3);flex-shrink:0; }
.ticker-content { color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
.ticker-time { color:var(--text3);flex-shrink:0;margin-left:auto; }
`;
document.head.appendChild(s);

const e7 = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const SEV_C = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80',INFO:'#94a3b8'};


// ═══════════════════════════════════════════════════════════════════════════════
// 1. GOVERNANCE UPGRADE — radar + heatmap + RACI visual
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeGovernance(){
  const panel = document.getElementById('panel-governance');
  if (!panel) return;

  // Add radar chart card at top
  const radarCard = document.createElement('div');
  radarCard.className = 'gov-grid';
  radarCard.style.marginBottom = '16px';
  radarCard.innerHTML = `
    <div class="gov-radar-card">
      <div style="font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--text2);text-transform:uppercase;margin-bottom:12px">Risk framework radar</div>
      <canvas id="gov-radar-chart" height="240"></canvas>
    </div>
    <div class="gov-radar-card">
      <div style="font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--text2);text-transform:uppercase;margin-bottom:8px">Risk heatmap — severity × tool</div>
      <div id="gov-heatmap"></div>
    </div>
  `;
  panel.insertBefore(radarCard, panel.firstChild);

  // Patch loadRiskRegister
  const _orig = window.loadRiskRegister;
  window.loadRiskRegister = async function() {
    if (_orig) await _orig();
    try {
      // Draw radar chart
      const [scorecard, zerotrust] = await Promise.all([
        window.api('GET', '/soc/framework-scorecard').catch(()=>({frameworks:[]})),
        window.api('GET', '/soc/zero-trust').catch(()=>({pillars:[]})),
      ]);

      const fws = scorecard.frameworks || [];
      const labels = fws.map(f=>f.framework||'').concat(['Zero Trust']);
      const scores = fws.map(f=>f.score||0).concat([
        Math.round((zerotrust.pillars||[]).reduce((a,p)=>a+(p.score||0),0) / Math.max((zerotrust.pillars||[]).length,1))
      ]);

      const ctx = document.getElementById('gov-radar-chart')?.getContext('2d');
      if (ctx && labels.length > 0) {
        if (window._govRadarChart) window._govRadarChart.destroy();
        window._govRadarChart = new Chart(ctx, {
          type: 'radar',
          data: {
            labels,
            datasets: [{
              label: 'Score',
              data: scores,
              borderColor: '#38bdf8',
              backgroundColor: 'rgba(56,189,248,0.12)',
              pointBackgroundColor: '#38bdf8',
              pointRadius: 4,
              borderWidth: 2,
            }]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
              r: {
                min: 0, max: 100,
                ticks: { color:'#475569', font:{size:9}, stepSize:25 },
                grid: { color:'#1e293b' },
                pointLabels: { color:'#94a3b8', font:{size:10} },
                angleLines: { color:'#1e293b' },
              }
            },
            plugins: { legend:{display:false} }
          }
        });
      }

      // Risk heatmap — tool vs severity
      const findings = await window.api('GET', '/vsp/findings?limit=500').catch(()=>({findings:[]}));
      const tools = ['kics','bandit','semgrep','grype','trivy','gitleaks','checkov'];
      const sevs  = ['CRITICAL','HIGH','MEDIUM','LOW'];
      const matrix = {};
      (findings.findings||[]).forEach(f => {
        const k = f.tool+'|'+f.severity;
        matrix[k] = (matrix[k]||0)+1;
      });
      const maxVal = Math.max(...Object.values(matrix), 1);

      const heatEl = document.getElementById('gov-heatmap');
      if (heatEl) {
        heatEl.innerHTML = `
          <div style="display:grid;grid-template-columns:60px repeat(${sevs.length},1fr);gap:3px;font-size:9px">
            <div></div>
            ${sevs.map(s=>`<div style="text-align:center;color:${SEV_C[s]};font-weight:700;padding:2px">${s.slice(0,4)}</div>`).join('')}
            ${tools.map(t=>`
              <div style="color:var(--text3);font-family:var(--mono);padding:3px 0;display:flex;align-items:center">${t}</div>
              ${sevs.map(sev=>{
                const v = matrix[t+'|'+sev]||0;
                const intensity = v/maxVal;
                const bg = v===0?'#0f172a':sev==='CRITICAL'?`rgba(248,113,113,${0.15+intensity*0.8})`:
                  sev==='HIGH'?`rgba(251,146,60,${0.15+intensity*0.8})`:
                  sev==='MEDIUM'?`rgba(251,191,36,${0.15+intensity*0.8})`:`rgba(74,222,128,${0.15+intensity*0.8})`;
                return `<div style="background:${bg};border-radius:3px;padding:5px;text-align:center;font-family:var(--mono);font-size:10px;color:${v>0?'white':'#334155'};font-weight:${v>0?'700':'400'}">${v||''}</div>`;
              }).join('')}`).join('')}
          </div>`;
      }
    } catch(e) { console.error('gov upgrade', e); }
  };

  // Better RACI table
  const _origRACI = window.loadRACI;
  window.loadRACI = async function() {
    try {
      const data = await window.api('GET', '/governance/raci');
      const raci = data.raci || [];
      const raciEl = document.getElementById('raci-list');
      if (!raciEl || !raci.length) { if(_origRACI) _origRACI(); return; }
      raciEl.innerHTML = `
        <table class="raci-table">
          <thead><tr><th>Activity</th><th>R</th><th>A</th><th>C</th><th>I</th></tr></thead>
          <tbody>
            ${raci.map(r=>`<tr>
              <td style="font-size:12px;color:var(--text1)">${e7(r.activity)}</td>
              <td><span class="raci-badge raci-R" title="${r.responsible}">${(r.responsible||'?')[0].toUpperCase()}</span></td>
              <td><span class="raci-badge raci-A" title="${r.accountable}">${(r.accountable||'?')[0].toUpperCase()}</span></td>
              <td><span class="raci-badge raci-C" title="${r.consulted}">${(r.consulted||'?')[0].toUpperCase()}</span></td>
              <td><span class="raci-badge raci-I">—</span></td>
            </tr>`).join('')}
          </tbody>
        </table>`;
    } catch(err) { if(_origRACI) _origRACI(); }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 2. SOC PANEL UPGRADE — pillar grid + incident timeline
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeSOC(){
  const panel = document.getElementById('panel-soc');
  if (!panel) return;

  // Add pillar grid + timeline at top
  const topGrid = document.createElement('div');
  topGrid.style.marginBottom = '16px';
  topGrid.innerHTML = `
    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><span class="card-title">Zero Trust — pillar scores</span></div>
      <div class="soc-pillars-grid" id="soc-pillars-grid">
        ${['User','Device','Network','App','Data','Visibility','Automation'].map(p=>`
          <div class="soc-pillar-cell">
            <div class="soc-pillar-score" id="soc-p-${p.toLowerCase().replace(/[^a-z]/g,'')}">—</div>
            <div class="soc-pillar-name">${p}</div>
          </div>`).join('')}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      <div class="card">
        <div class="card-head"><span class="card-title">Framework radar</span></div>
        <div style="height:220px;position:relative"><canvas id="soc-radar-chart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Incident timeline</span></div>
        <div class="soc-timeline" id="soc-incident-timeline">
          <div style="color:var(--text3);font-size:11px">Loading…</div>
        </div>
      </div>
    </div>
  `;
  panel.insertBefore(topGrid, panel.firstChild);

  // Patch loadScorecard
  const _origScore = window.loadScorecard;
  window.loadScorecard = async function() {
    if (_origScore) await _origScore();
    try {
      const [sc, zt] = await Promise.all([
        window.api('GET','/soc/framework-scorecard').catch(()=>({frameworks:[]})),
        window.api('GET','/soc/zero-trust').catch(()=>({pillars:[]})),
      ]);

      // Pillar scores
      const pillarMap = {'user':'User','device':'Device','network':'Network',
        'applicationworkload':'App','data':'Data','visibilityanalytics':'Visibility',
        'automationorchestration':'Automation'};
      (zt.pillars||[]).forEach(p => {
        const key = (p.pillar||'').toLowerCase().replace(/[^a-z]/g,'');
        const el = document.getElementById('soc-p-'+key) ||
          document.getElementById('soc-p-'+key.slice(0,6));
        if (el) {
          el.textContent = p.score||0;
          el.style.color = (p.score||0)>=80?'var(--green)':(p.score||0)>=60?'var(--amber)':'var(--red)';
        }
      });

      // Radar
      const fws = sc.frameworks||[];
      const ctx = document.getElementById('soc-radar-chart')?.getContext('2d');
      if (ctx && fws.length) {
        if (window._socRadarChart) window._socRadarChart.destroy();
        window._socRadarChart = new Chart(ctx, {
          type:'radar',
          data:{
            labels: fws.map(f=>f.framework),
            datasets:[{
              label:'Score',data:fws.map(f=>f.score||0),
              borderColor:'#a78bfa',backgroundColor:'rgba(167,139,250,.1)',
              pointBackgroundColor:'#a78bfa',pointRadius:4,borderWidth:2
            }]
          },
          options:{
            responsive:true,maintainAspectRatio:false,
            scales:{r:{min:0,max:100,ticks:{color:'#475569',font:{size:9},stepSize:25},
              grid:{color:'#1e293b'},pointLabels:{color:'#94a3b8',font:{size:9}},
              angleLines:{color:'#1e293b'}}},
            plugins:{legend:{display:false}}
          }
        });
      }
    } catch(e){ console.error('soc upgrade',e); }
  };

  // Patch loadIncidents to add timeline
  const _origInc = window.loadIncidents;
  window.loadIncidents = async function() {
    if (_origInc) await _origInc();
    try {
      const data = await window.api('GET','/soc/incidents');
      const inc = data.incidents||[];
      const tlEl = document.getElementById('soc-incident-timeline');
      if (!tlEl) return;
      if (!inc.length) {
        tlEl.innerHTML = '<div style="color:var(--green);font-size:12px;padding:8px 0">✓ No active incidents</div>';
        return;
      }
      tlEl.innerHTML = inc.slice(0,6).map(i=>{
        const color = SEV_C[i.severity]||'#94a3b8';
        return `<div class="soc-tl-item">
          <div class="soc-tl-dot" style="background:${color}"></div>
          <div class="soc-tl-content">
            <div class="soc-tl-title">${e7(i.title||i.id)}</div>
            <div class="soc-tl-meta">
              <span style="color:${color};font-weight:700">${i.severity}</span>
              <span style="margin-left:8px">${i.id}</span>
            </div>
          </div>
        </div>`;
      }).join('');
    } catch(e){ console.error('soc tl',e); }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 3. FINDINGS PAGINATION
// ═══════════════════════════════════════════════════════════════════════════════
(function addFindingsPagination(){
  const panel = document.getElementById('panel-findings');
  if (!panel) return;

  let _page = 0;
  const PAGE_SIZE = 50;
  let _allFindings = [];

  // Inject pagination bar after table card
  const paginationBar = document.createElement('div');
  paginationBar.className = 'findings-pagination';
  paginationBar.id = 'findings-pagination';
  paginationBar.innerHTML = `
    <span class="pagination-info" id="page-info">—</span>
    <div style="display:flex;align-items:center;gap:8px">
      <button class="btn-sm" onclick="exportFindingsCSV()">↓ CSV</button>
      <div class="pagination-btns" id="page-btns"></div>
    </div>
  `;
  const tableCard = panel.querySelector('#findings-table')?.closest('.card');
  if (tableCard) tableCard.after(paginationBar);

  // Override loadFindingsUpgraded to store all and paginate
  const _origLoad = window.loadFindingsUpgraded || window.loadFindings;
  window.loadFindingsUpgraded = async function() {
    const sev  = document.getElementById('filterSev')?.value||'';
    const tool = document.getElementById('filterTool')?.value||'';
    const q    = document.getElementById('filterQ')?.value||'';
    let path   = '/vsp/findings?limit=1000';
    if (sev)  path += '&severity='+sev;
    if (tool) path += '&tool='+tool;
    if (q)    path += '&q='+encodeURIComponent(q);
    try {
      const data = await window.api('GET', path);
      _allFindings = data.findings||[];
      window._findingsCache = _allFindings;
      _page = 0;
      document.getElementById('findings-count').textContent = (data.total||_allFindings.length)+' findings';
      renderPage();
    } catch(e){ console.error('findings paged',e); }
  };
  window.loadFindings = window.loadFindingsUpgraded;

  function renderPage() {
    const start = _page * PAGE_SIZE;
    const slice = _allFindings.slice(start, start + PAGE_SIZE);
    const tbody = document.getElementById('findings-table');
    if (tbody) {
      tbody.innerHTML = slice.map((f,i)=>`
        <tr onclick="openFindingModal&&openFindingModal(window._findingsCache[${start+i}])" style="cursor:pointer">
          <td>${window.sevPill(f.severity)}</td>
          <td style="color:#94a3b8;font-size:11px">${f.tool}</td>
          <td style="font-family:monospace;font-size:10px;color:#60a5fa;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.rule_id||'—'}</td>
          <td style="max-width:270px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e7(f.message)}">${e7(f.message)||'—'}</td>
          <td style="font-family:monospace;font-size:10px;color:#94a3b8;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e7(f.path)||'—'}</td>
          <td style="color:#64748b;font-size:11px">${f.line||'—'}</td>
          <td style="font-size:10px;color:#818cf8">${f.cwe||'—'}</td>
        </tr>`).join('');
    }

    // Pagination controls
    const totalPages = Math.ceil(_allFindings.length / PAGE_SIZE);
    const infoEl = document.getElementById('page-info');
    const btnsEl = document.getElementById('page-btns');
    if (infoEl) infoEl.textContent = `${start+1}–${Math.min(start+PAGE_SIZE,_allFindings.length)} of ${_allFindings.length}`;
    if (btnsEl) {
      const pages = [];
      if (_page > 0) pages.push(`<button class="page-btn" onclick="gotoFindingsPage(${_page-1})">‹ Prev</button>`);
      const startP = Math.max(0, _page-2), endP = Math.min(totalPages-1, _page+2);
      for (let p=startP; p<=endP; p++) {
        pages.push(`<button class="page-btn${p===_page?' active':''}" onclick="gotoFindingsPage(${p})">${p+1}</button>`);
      }
      if (_page < totalPages-1) pages.push(`<button class="page-btn" onclick="gotoFindingsPage(${_page+1})">Next ›</button>`);
      btnsEl.innerHTML = pages.join('');
    }
  }

  window.gotoFindingsPage = function(p) {
    _page = p;
    renderPage();
    document.getElementById('panel-findings')?.scrollIntoView({behavior:'smooth',block:'start'});
  };

  window.exportFindingsCSV = function() {
    if (!_allFindings.length) { showToast('No findings to export', 'info'); return; }
    const headers = ['severity','tool','rule_id','message','path','line','cwe'];
    const rows = _allFindings.map(f => headers.map(h => {
      const v = String(f[h]||'').replace(/"/g,'""');
      return `"${v}"`;
    }).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vsp-findings-'+new Date().toISOString().slice(0,10)+'.csv';
    a.click();
    showToast('Exported '+_allFindings.length+' findings', 'success');
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 4. DASHBOARD TICKER
// ═══════════════════════════════════════════════════════════════════════════════
(function addDashboardTicker(){
  const panel = document.getElementById('panel-dashboard');
  if (!panel) return;

  const ticker = document.createElement('div');
  ticker.id = 'dash-ticker';
  ticker.innerHTML = `
    <div class="ticker-dot"></div>
    <span class="ticker-label">LATEST:</span>
    <span class="ticker-content" id="ticker-content">Loading last scan…</span>
    <span class="ticker-time" id="ticker-time"></span>
  `;
  panel.insertBefore(ticker, panel.firstChild);

  async function updateTicker() {
    try {
      const r = await window.api('GET','/vsp/run/latest');
      const content = `${r.rid?.slice(-16)||'—'} · ${r.mode||'?'} · ${r.status||'?'}${r.gate?' · '+r.gate:''}${(r.total_findings||0)>0?' · '+r.total_findings+' findings':''}`;
      const el = document.getElementById('ticker-content');
      const tel = document.getElementById('ticker-time');
      if (el) el.textContent = content;
      if (tel) tel.textContent = r.created_at ? new Date(r.created_at).toLocaleTimeString() : '';
    } catch(e){}
  }
  updateTicker();
  setInterval(updateTicker, 20000);

  // Patch loadDashboard to update ticker
  const _orig = window.loadDashboard;
  window.loadDashboard = async function() {
    if (_orig) await _orig();
    updateTicker();
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 5. QUICK SEARCH (press / to open)
// ═══════════════════════════════════════════════════════════════════════════════
(function initQuickSearch(){
  const overlay = document.createElement('div');
  overlay.id = 'quick-search-overlay';
  overlay.innerHTML = `
    <div id="quick-search-box">
      <input id="quick-search-input" placeholder="Search panels, findings, runs… (↑↓ navigate, Enter select, Esc close)" autocomplete="off">
      <div id="quick-search-results"></div>
      <div id="quick-search-hint">Press / to open · Esc to close · ↑↓ navigate</div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e=>{ if(e.target===overlay) closeQS(); });

  const PANELS = [
    {name:'Dashboard',    icon:'◈', panel:'dashboard'},
    {name:'Runs',         icon:'▷', panel:'runs'},
    {name:'Findings',     icon:'◎', panel:'findings'},
    {name:'Remediation',  icon:'◐', panel:'remediation'},
    {name:'Policy',       icon:'◫', panel:'policy'},
    {name:'Audit',        icon:'◷', panel:'audit'},
    {name:'SOC',          icon:'◉', panel:'soc'},
    {name:'Governance',   icon:'◧', panel:'governance'},
    {name:'FedRAMP/CMMC', icon:'◆', panel:'compliance2'},
    {name:'SBOM',         icon:'◌', panel:'sbom'},
    {name:'SLA Tracker',  icon:'◷', panel:'sla'},
    {name:'Export',       icon:'↓', panel:'export'},
    {name:'Executive',    icon:'★', panel:'executive'},
    {name:'Users',        icon:'◈', panel:'users'},
  ];

  let _qsSelected = 0;
  let _qsResults = [];

  function openQS() {
    overlay.classList.add('open');
    document.getElementById('quick-search-input').value = '';
    document.getElementById('quick-search-input').focus();
    renderQSResults('');
  }
  function closeQS() {
    overlay.classList.remove('open');
  }

  function renderQSResults(q) {
    const results = document.getElementById('quick-search-results');
    if (!results) return;

    _qsResults = [];
    let html = '';

    if (!q) {
      // Show all panels
      html += `<div class="qs-section-header">Panels</div>`;
      PANELS.forEach(p => {
        _qsResults.push({type:'panel', data:p});
        html += `<div class="qs-result${_qsResults.length===1?' selected':''}" onclick="selectQSResult(${_qsResults.length-1})">
          <span class="qs-result-icon" style="color:var(--amber)">${p.icon}</span>
          <div class="qs-result-main"><div class="qs-result-title">${p.name}</div></div>
          <span class="qs-result-badge">PANEL</span>
        </div>`;
      });
    } else {
      // Filter panels
      const matchPanels = PANELS.filter(p=>p.name.toLowerCase().includes(q.toLowerCase()));
      if (matchPanels.length) {
        html += `<div class="qs-section-header">Panels</div>`;
        matchPanels.forEach(p=>{
          _qsResults.push({type:'panel',data:p});
          html += `<div class="qs-result" onclick="selectQSResult(${_qsResults.length-1})">
            <span class="qs-result-icon" style="color:var(--amber)">${p.icon}</span>
            <div class="qs-result-main"><div class="qs-result-title">${p.name}</div></div>
            <span class="qs-result-badge">PANEL</span>
          </div>`;
        });
      }

      // Search findings cache
      const cache = window._findingsCache || [];
      const matchF = cache.filter(f=>
        (f.message||'').toLowerCase().includes(q.toLowerCase()) ||
        (f.rule_id||'').toLowerCase().includes(q.toLowerCase()) ||
        (f.path||'').toLowerCase().includes(q.toLowerCase())
      ).slice(0,5);
      if (matchF.length) {
        html += `<div class="qs-section-header">Findings</div>`;
        matchF.forEach(f=>{
          _qsResults.push({type:'finding',data:f});
          html += `<div class="qs-result" onclick="selectQSResult(${_qsResults.length-1})">
            <span class="qs-result-icon" style="color:${SEV_C[f.severity]||'#94a3b8'}">◎</span>
            <div class="qs-result-main">
              <div class="qs-result-title" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e7(f.message)}</div>
              <div style="font-size:9px;color:var(--text3)">${f.tool} · ${f.severity} · ${(f.path||'').split('/').pop()}</div>
            </div>
            <span class="qs-result-badge" style="color:${SEV_C[f.severity]}">${f.severity}</span>
          </div>`;
        });
      }

      if (!_qsResults.length) {
        html = `<div style="padding:20px;text-align:center;color:var(--text3);font-size:12px">No results for "${e7(q)}"</div>`;
      }
    }

    results.innerHTML = html;
    _qsSelected = 0;
    updateQSSelection();
  }

  function updateQSSelection() {
    document.querySelectorAll('.qs-result').forEach((el,i)=>{
      el.classList.toggle('selected', i===_qsSelected);
    });
  }

  window.selectQSResult = function(idx) {
    const r = _qsResults[idx];
    if (!r) return;
    closeQS();
    if (r.type==='panel') {
      const btn = document.querySelector(`.stab[onclick*="${r.data.panel}"]`);
      if (typeof showPanel==='function') showPanel(r.data.panel, btn);
    } else if (r.type==='finding') {
      if (typeof showPanel==='function') {
        const btn = document.querySelector(`.stab[onclick*="findings"]`);
        showPanel('findings', btn);
      }
      setTimeout(()=>{ if(typeof openFindingModal==='function') openFindingModal(r.data); }, 300);
    }
  };

  const input = document.getElementById('quick-search-input');
  if (input) {
    input.addEventListener('input', e=>{ renderQSResults(e.target.value); _qsSelected=0; });
    input.addEventListener('keydown', e=>{
      if (e.key==='ArrowDown')  { _qsSelected=Math.min(_qsSelected+1,_qsResults.length-1); updateQSSelection(); e.preventDefault(); }
      if (e.key==='ArrowUp')    { _qsSelected=Math.max(_qsSelected-1,0); updateQSSelection(); e.preventDefault(); }
      if (e.key==='Enter')      { selectQSResult(_qsSelected); }
      if (e.key==='Escape')     { closeQS(); }
    });
  }

  // Global keyboard shortcut
  document.addEventListener('keydown', e=>{
    if (e.key==='/' && e.target.tagName!=='INPUT' && e.target.tagName!=='TEXTAREA' && e.target.tagName!=='SELECT') {
      e.preventDefault();
      openQS();
    }
    if (e.key==='Escape' && overlay.classList.contains('open')) closeQS();
  });

  // Add hint to sidebar bottom
  const userWidget = document.getElementById('userWidget');
  if (userWidget) {
    const hint = document.createElement('div');
    hint.style.cssText = 'padding:4px 10px;font-size:9px;color:var(--text3);font-family:var(--mono);letter-spacing:.06em;cursor:pointer;';
    hint.textContent = '/ Quick search';
    hint.onclick = openQS;
    userWidget.after(hint);
  }
})();


// ═══════════════════════════════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════════════════════════════
// Patch showPanel for new panels
const _sp80 = window.showPanel;
window.showPanel = function(name, btn) {
  _sp80?.(name, btn);
  if (name==='governance') setTimeout(()=>{ window.loadRiskRegister?.(); window.loadRACI?.(); }, 100);
  if (name==='soc')        setTimeout(()=>{ window.loadScorecard?.(); window.loadIncidents?.(); }, 100);
};

console.log('[VSP Upgrade v0.8.0] Governance+SOC+Pagination+Ticker+QuickSearch loaded ✓');

})(); // end vsp080
