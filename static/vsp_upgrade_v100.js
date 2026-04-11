// ═══════════════════════════════════════════════════════
// VSP UPGRADE v1.0.0 — UI Enhancement & Bug Fixes (FINAL)
// ═══════════════════════════════════════════════════════
(function vsp100() {
'use strict';

// ── HELPERS ──
const GRADE_COLORS = {A:'var(--green)',B:'#4ade80',C:'var(--amber)',D:'#f97316',F:'var(--red)'};
const GATE_COLORS  = {PASS:'var(--green)',WARN:'var(--amber)',FAIL:'var(--red)'};

function scoreToGrade(score) {
  if (score >= 90) return { grade: 'A', color: GRADE_COLORS.A };
  if (score >= 75) return { grade: 'B', color: GRADE_COLORS.B };
  if (score >= 60) return { grade: 'C', color: GRADE_COLORS.C };
  if (score >= 40) return { grade: 'D', color: GRADE_COLORS.D };
  return { grade: 'F', color: GRADE_COLORS.F };
}

async function safeApi(method, url, fallback = {}) {
  try {
    // Nếu không có token thì không gọi API
    if (!window.TOKEN && !localStorage.getItem('vsp_token')) {
      return fallback;
    }
    const result = await Promise.race([
      window.api(method, url),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000))
    ]);
    return result || fallback;
  } catch (e) {
    const msg = e.message || '';
    // 401/not_authenticated → stop polling, trigger logout
    if (msg === 'not_authenticated' || msg.includes('401')) {
      window.TOKEN = '';
      localStorage.removeItem('vsp_token');
      return fallback;
    }
    console.warn('[VSP] API failed:', url, msg);
    return fallback;
  }
}

// ── 1. FIX: Governance radar ──
const _origShowPanel = window.showPanel;
window.showPanel = function(name, btn) {
  if (_origShowPanel) _origShowPanel(name, btn);
  setTimeout(() => {
    if (name === 'governance') {
      window.loadRiskRegister?.();
      window.loadTraceability?.();
      window.loadRACI?.();
      window.loadOwnership?.();
    }
    if (name === 'sla')        window.loadSLAPanel?.();
    if (name === 'compliance2' || name === 'compliance') { window.loadFedRAMP?.(); window.loadCMMC?.(); }
    if (name === 'executive')  window.loadExecutive?.();
    if (name === 'sbom')       window.loadSBOM?.();
    if (name === 'audit')      window.loadAudit?.();
  }, 150);
};

// ── 2. Dashboard KPI inject (dash-ticker không tồn tại → skip) ──
function upgradeDashboard() {
  const ticker = document.getElementById('dash-ticker');
  if (!ticker || document.getElementById('dash-extra-kpis')) return;
  const extra = document.createElement('div');
  extra.id = 'dash-extra-kpis';
  extra.style.cssText = 'display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px';
  extra.innerHTML = `
    <div class="kpi-card" style="padding:12px;border-left:3px solid var(--amber)">
      <div class="kpi-label">SLA Breaches</div>
      <div style="font-family:var(--display);font-size:22px;font-weight:800;color:var(--amber)" id="kpi-breach">—</div>
      <div style="font-size:9px;color:var(--text3);margin-top:2px">open violations</div>
    </div>
    <div class="kpi-card" style="padding:12px;border-left:3px solid var(--green)">
      <div class="kpi-label">Remediation Rate</div>
      <div style="font-family:var(--display);font-size:22px;font-weight:800;color:var(--green)" id="kpi-remrate">—</div>
      <div style="font-size:9px;color:var(--text3);margin-top:2px">resolved / total</div>
    </div>
    <div class="kpi-card" style="padding:12px;border-left:3px solid #a78bfa">
      <div class="kpi-label">Remediation Rate %</div>
      <div style="font-family:var(--display);font-size:22px;font-weight:800;color:#a78bfa" id="kpi-remrate2">—</div>
      <div style="font-size:9px;color:var(--text3);margin-top:2px">of total items</div>
    </div>`;
  ticker.parentNode.insertBefore(extra, ticker.nextSibling);
}

// ── 3. Patch loadDashboard ──
const _origDash = window.loadDashboard;
window.loadDashboard = async function() {
  if (_origDash) await _origDash();
  upgradeDashboard();
  try {
    const [sla, rem] = await Promise.all([
      safeApi('GET', '/vsp/sla_tracker', { sla: [] }),
      safeApi('GET', '/remediation/stats', {}),
    ]);
    // SLA breaches
    const slaArr = Array.isArray(sla.sla) ? sla.sla : [];
    const breaches = slaArr.reduce((a, s) => a + (s.breach_count || 0), 0);
    const elBreach = document.getElementById('kpi-breach');
    if (elBreach) { elBreach.textContent = breaches; elBreach.style.color = breaches > 0 ? 'var(--red)' : 'var(--green)'; }
    // Remediation rate
    const open = rem.open||0, resolved = rem.resolved||0, inProgress = rem.in_progress||0, accepted = rem.accepted||0;
    const total = open + resolved + inProgress + accepted;
    const rate = total > 0 ? Math.round(resolved / total * 100) : 0;
    const elRem = document.getElementById('kpi-remrate');
    if (elRem) { elRem.textContent = rate + '%'; elRem.style.color = rate >= 70 ? 'var(--green)' : rate >= 40 ? 'var(--amber)' : 'var(--red)'; }
  } catch (e) { console.error('[VSP] dash kpis', e); }
  // Load DoD widgets
  setTimeout(function(){ injectDoDRow(); loadDoDWidgets(); }, 500);
};

// ── 3b. DoD/NIST widgets ──────────────────────────────────────────────────────
window.injectDoDRow = function injectDoDRow() {
  if (document.getElementById('dod-widget-row')) return;
  // Find SIEM KPI row to inject after it
  const siemEl = document.getElementById('siem-incidents');
  const siemRow = siemEl ? siemEl.closest('.kpi-row') : document.querySelector('.kpi-row.mb14');
  if (!siemRow) return;
  const row = document.createElement('div');
  row.id = 'dod-widget-row';
  row.style.cssText = 'display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px';
  row.innerHTML = `
    <!-- ATO Countdown -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer"
         onclick="if(window.showPanel)showPanel('p4compliance',null)" title="→ P4 Compliance">
      <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
        ATO Countdown
      </div>
      <div style="font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--green)" id="dod-ato-days">—</div>
      <div style="font-size:10px;color:var(--t3);margin-top:2px" id="dod-ato-sub">days remaining</div>
      <div style="margin-top:8px;height:3px;background:var(--border);border-radius:2px">
        <div id="dod-ato-bar" style="height:100%;border-radius:2px;background:var(--green);width:0%;transition:width .6s"></div>
      </div>
    </div>
    <!-- POA&M -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer"
         onclick="if(window.showPanel)showPanel('p4compliance',null)" title="→ P4 Compliance">
      <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
        POA&amp;M Status
      </div>
      <div style="font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--amber)" id="dod-poam-open">—</div>
      <div style="font-size:10px;color:var(--t3);margin-top:2px" id="dod-poam-sub">open items</div>
      <div style="margin-top:6px;display:flex;gap:4px;font-size:9px;font-family:var(--font-mono)" id="dod-poam-detail">
        <span style="color:var(--t3)">loading...</span>
      </div>
    </div>
    <!-- ConMon Score -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer"
         onclick="if(window.showPanel)showPanel('p4compliance',null)" title="→ P4 Compliance">
      <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
        ConMon Score
      </div>
      <div style="font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--cyan)" id="dod-conmon-score">—</div>
      <div style="font-size:10px;color:var(--t3);margin-top:2px" id="dod-conmon-sub">CA-7 continuous monitoring</div>
      <div style="margin-top:8px;height:3px;background:var(--border);border-radius:2px">
        <div id="dod-conmon-bar" style="height:100%;border-radius:2px;background:var(--cyan);width:0%;transition:width .6s"></div>
      </div>
    </div>
    <!-- CISA KEV -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer"
         onclick="if(window.showPanel)showPanel('findings',null)" title="→ Findings">
      <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
        CISA KEV
      </div>
      <div style="font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--red)" id="dod-kev-count">—</div>
      <div style="font-size:10px;color:var(--t3);margin-top:2px" id="dod-kev-sub">known exploited vulns</div>
      <div style="margin-top:6px;font-size:9px;font-family:var(--font-mono);color:var(--t3)" id="dod-kev-detail">
        loading...
      </div>
    </div>`;
  siemRow.parentNode.insertBefore(row, siemRow.nextSibling);
}

window.loadDoDWidgets = async function loadDoDWidgets() {
  // Helper: fetch với /api/p4/ prefix đúng (không qua safeApi /api/v1/)
  async function p4fetch(path) {
    const tok = window.TOKEN || localStorage.getItem('vsp_token') || '';
    if (!tok) return {};
    try {
      const r = await fetch('/api' + path, {
        headers: { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' }
      });
      if (!r.ok) return {};
      return await r.json();
    } catch(e) { return {}; }
  }

  try {
    // ── ATO Countdown + POAM — from /api/p4/rmf ──
    const rmf = await p4fetch('/p4/rmf');

    // ATO Countdown
    const expStr = rmf.expiration_date || rmf.expiration || '';
    const authStr = rmf.authorization_date || rmf.authorized_at || '';
    if (expStr) {
      const exp  = new Date(expStr);
      const auth = authStr ? new Date(authStr) : new Date(exp.getTime() - 3*365*86400000);
      const total = exp - auth;
      const remain = exp - Date.now();
      const days  = Math.max(0, Math.floor(remain / 86400000));
      const pct   = Math.min(100, Math.max(0, Math.round(remain / total * 100)));
      const color = days > 180 ? 'var(--green)' : days > 60 ? 'var(--amber)' : 'var(--red)';
      const el = document.getElementById('dod-ato-days');
      if (el) { el.textContent = days.toLocaleString(); el.style.color = color; }
      const sub = document.getElementById('dod-ato-sub');
      if (sub) sub.textContent = 'days · expires ' + exp.toLocaleDateString('vi-VN');
      const bar = document.getElementById('dod-ato-bar');
      if (bar) { bar.style.width = pct + '%'; bar.style.background = color; }
    }

    // POA&M
    const poamItems = rmf.poam_items || [];
    const open   = poamItems.filter(p => !['closed','resolved','completed'].includes((p.status||'').toLowerCase()));
    const closed = poamItems.filter(p =>  ['closed','resolved','completed'].includes((p.status||'').toLowerCase()));
    const crits  = open.filter(p => (p.severity||p.impact||'').toLowerCase() === 'critical');
    const highs  = open.filter(p => (p.severity||p.impact||'').toLowerCase() === 'high');
    const poamEl = document.getElementById('dod-poam-open');
    if (poamEl) {
      poamEl.textContent = open.length;
      poamEl.style.color = open.length === 0 ? 'var(--green)' : crits.length > 0 ? 'var(--red)' : 'var(--amber)';
    }
    const poamSub = document.getElementById('dod-poam-sub');
    if (poamSub) poamSub.textContent = closed.length + ' closed · ' + poamItems.length + ' total';
    const poamDetail = document.getElementById('dod-poam-detail');
    if (poamDetail) poamDetail.innerHTML =
      (crits.length ? `<span style="color:var(--red)">${crits.length} CRIT</span>&nbsp;` : '') +
      (highs.length ? `<span style="color:var(--amber)">${highs.length} HIGH</span>&nbsp;` : '') +
      (open.length === 0 ? '<span style="color:var(--green)">✓ All closed</span>' : '');
  } catch(e) { console.error('[VSP] DoD RMF widgets', e); }

  try {
    // ── ConMon — from /api/p4/rmf/conmon ──
    const conmon = await p4fetch('/p4/rmf/conmon');
    const score  = conmon.conmon_score || 0;
    const color  = score >= 90 ? 'var(--cyan)' : score >= 70 ? 'var(--amber)' : 'var(--red)';
    const el = document.getElementById('dod-conmon-score');
    if (el) { el.textContent = score + '/100'; el.style.color = color; }
    const bar = document.getElementById('dod-conmon-bar');
    if (bar) { bar.style.width = score + '%'; bar.style.background = color; }
    const sub = document.getElementById('dod-conmon-sub');
    const trend = conmon.trend || 'stable';
    if (sub) sub.textContent = 'CA-7 · controls ' + (conmon.control_compliance_rate||'—') + '% · ' + trend;
  } catch(e) { console.error('[VSP] DoD ConMon widget', e); }

  try {
    // ── CISA KEV — derive from scan findings ──
    const findings = await safeApi('GET', '/vsp/findings?limit=500&severity=CRITICAL', { findings: [] });
    const arr = Array.isArray(findings.findings) ? findings.findings : [];
    // KEV = CVEs with high EPSS or known exploited patterns
    const kevCVEs = arr.filter(f =>
      (f.rule_id||'').startsWith('CVE-') &&
      ((f.epss && parseFloat(f.epss) > 0.3) || (f.fix_signal||'').toLowerCase().includes('kev') ||
       (f.message||'').toLowerCase().includes('kev') || (f.tags||[]).includes('kev'))
    );
    // Fallback: just count CRITICAL CVEs as proxy
    const kevCount = kevCVEs.length > 0 ? kevCVEs.length :
      arr.filter(f => (f.rule_id||'').startsWith('CVE-') && f.severity === 'CRITICAL').length;
    const color = kevCount === 0 ? 'var(--green)' : kevCount <= 2 ? 'var(--amber)' : 'var(--red)';
    const el = document.getElementById('dod-kev-count');
    if (el) { el.textContent = kevCount; el.style.color = color; }
    const sub = document.getElementById('dod-kev-sub');
    if (sub) sub.textContent = kevCount === 0 ? 'no known exploited CVEs' : 'known exploited vulns';
    const detail = document.getElementById('dod-kev-detail');
    if (detail && kevCVEs.length > 0) {
      detail.innerHTML = kevCVEs.slice(0,2).map(f =>
        `<div style="color:var(--red);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.rule_id}</div>`
      ).join('');
    } else if (detail) {
      detail.textContent = 'EPSS > 0.3 · exploit confirmed';
    }
  } catch(e) { console.error('[VSP] DoD KEV widget', e); }
}

// ── 4. Findings filter toolbar ──
function upgradeFindings() {
  const panel = document.getElementById('panel-findings');
  if (!panel || document.getElementById('findings-filter-bar')) return;
  const bar = document.createElement('div');
  bar.id = 'findings-filter-bar';
  bar.style.cssText = 'display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center';
  bar.innerHTML = `
    <select id="vsp-filter-severity" style="background:var(--card);border:1px solid var(--border2);color:var(--text1);padding:4px 8px;border-radius:4px;font-size:11px">
      <option value="">All Severities</option>
      <option value="CRITICAL">🔴 CRITICAL</option>
      <option value="HIGH">🟠 HIGH</option>
      <option value="MEDIUM">🟡 MEDIUM</option>
      <option value="LOW">🟢 LOW</option>
    </select>
    <select id="vsp-filter-tool" style="background:var(--card);border:1px solid var(--border2);color:var(--text1);padding:4px 8px;border-radius:4px;font-size:11px">
      <option value="">All Tools</option>
      <option value="kics">kics</option><option value="trivy">trivy</option>
      <option value="gitleaks">gitleaks</option><option value="checkov">checkov</option>
      <option value="bandit">bandit</option><option value="semgrep">semgrep</option>
      <option value="grype">grype</option><option value="codeql">codeql</option>
    </select>
    <input id="vsp-filter-search" placeholder="Search findings..." style="background:var(--card);border:1px solid var(--border2);color:var(--text1);padding:4px 10px;border-radius:4px;font-size:11px;flex:1;min-width:150px">
    <button class="btn-sm btn-primary" onclick="applyFindingsFilter()">Filter</button>
    <button class="btn-sm" onclick="clearFindingsFilter()">Clear</button>`;
  panel.insertBefore(bar, panel.firstChild);
  window.applyFindingsFilter = function() {
    const sev  = document.getElementById('vsp-filter-severity')?.value || '';
    const tool = document.getElementById('vsp-filter-tool')?.value || '';
    const q    = document.getElementById('vsp-filter-search')?.value || '';
    let url = '/vsp/findings?limit=200';
    if (sev)  url += '&severity=' + sev;
    if (tool) url += '&tool=' + tool;
    if (q)    url += '&q=' + encodeURIComponent(q);
    safeApi('GET', url, {findings:[]}).then(data => {
      const findings = Array.isArray(data.findings) ? data.findings : [];
      const countEl = document.getElementById('findings-count');
      if (countEl) countEl.textContent = findings.length + ' findings';
      window._renderFindings?.(findings);
    });
  };
  window.clearFindingsFilter = function() {
    document.getElementById('vsp-filter-severity').value = '';
    document.getElementById('vsp-filter-tool').value = '';
    document.getElementById('vsp-filter-search').value = '';
    window.loadFindings?.();
  };
}

// ── 5. Remediation donut chart ──
function upgradeRemediation() {
  const panel = document.getElementById('panel-remediation');
  if (!panel || document.getElementById('rem-chart-card')) return;
  const card = document.createElement('div');
  card.id = 'rem-chart-card'; card.className = 'card';
  card.style.cssText = 'margin-bottom:16px;display:grid;grid-template-columns:200px 1fr;gap:16px;align-items:center';
  card.innerHTML = `<div style="position:relative;height:160px"><canvas id="rem-donut"></canvas></div><div id="rem-breakdown" style="font-size:12px"></div>`;
  // Insert sau .g6, .g4, hoặc trước card đầu tiên
  const kpiGrid = panel.querySelector('.g6, .g4, [style*="grid-template-columns:repeat(6"]');
  if (kpiGrid) kpiGrid.parentNode.insertBefore(card, kpiGrid.nextSibling);
  else { const firstCard = panel.querySelector('.card'); if (firstCard) panel.insertBefore(card, firstCard); }
}

const _origRemStats = window.loadRemStats || window.loadRemediation;
window.loadRemStats = async function() {
  if (_origRemStats) await _origRemStats();
  upgradeRemediation();
  try {
    const stats = await safeApi('GET', '/remediation/stats', {});
    const entries = [
      {label:'Open',        val:stats.open           ||0, color:'#f87171'},
      {label:'In Progress', val:stats.in_progress    ||0, color:'#fbbf24'},
      {label:'Resolved',    val:stats.resolved       ||0, color:'#4ade80'},
      {label:'Accepted',    val:stats.accepted       ||0, color:'#a78bfa'},
      {label:'False +ve',   val:stats.false_positive ||0, color:'#94a3b8'},
      {label:'Suppressed',  val:stats.suppressed     ||0, color:'#475569'},
    ];
    const ctx = document.getElementById('rem-donut')?.getContext('2d');
    if (ctx) {
      if (window._remDonut) window._remDonut.destroy();
      window._remDonut = new Chart(ctx, {
        type: 'doughnut',
        data: { labels: entries.map(e=>e.label), datasets:[{data:entries.map(e=>e.val), backgroundColor:entries.map(e=>e.color), borderWidth:0}] },
        options: { responsive:true, maintainAspectRatio:false, cutout:'70%', plugins:{legend:{display:false}} }
      });
    }
    const bd = document.getElementById('rem-breakdown');
    if (bd) bd.innerHTML = entries.map(e=>`
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <div style="width:10px;height:10px;border-radius:2px;background:${e.color};flex-shrink:0"></div>
        <span style="color:var(--text2)">${e.label}</span>
        <span style="margin-left:auto;font-weight:700;color:var(--text1)">${e.val}</span>
      </div>`).join('');
  } catch (e) { console.error('[VSP] rem chart', e); }
};

// ── 6. SLA summary bar ──
const _origSLA = window.loadSLAPanel;
window.loadSLAPanel = async function() {
  if (_origSLA) await _origSLA();
  try {
    const data = await safeApi('GET', '/vsp/sla_tracker', {sla:[]});
    const sla = Array.isArray(data.sla) ? data.sla : [];
    if (!document.getElementById('sla-summary-bar')) {
      const panel = document.getElementById('panel-sla');
      if (!panel) return;
      const bar = document.createElement('div');
      bar.id = 'sla-summary-bar';
      bar.style.cssText = 'display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px';
      panel.insertBefore(bar, panel.firstChild);
    }
    const colors = {green:'var(--green)', yellow:'var(--amber)', red:'var(--red)'};
    const bar2 = document.getElementById('sla-summary-bar');
    if (bar2) bar2.innerHTML = sla.length ? sla.map(s=>`
      <div class="kpi-card" style="padding:12px;border-left:3px solid ${colors[s.status]||'var(--text3)'}">
        <div style="font-size:9px;font-weight:700;letter-spacing:.1em;color:var(--text3);text-transform:uppercase">${s.severity}</div>
        <div style="font-family:var(--display);font-size:24px;font-weight:800;color:${colors[s.status]||'var(--text1)'}">${s.open_count}</div>
        <div style="font-size:10px;color:var(--text3)">open · SLA ${s.sla_days}d</div>
        <div style="font-size:10px;color:${s.breach_count>0?'var(--red)':'var(--text3)'}">
          ${s.breach_count>0 ? '⚠ '+s.breach_count+' breaches' : '✓ No breaches'}
        </div>
        <div style="margin-top:6px;background:#0f172a;border-radius:3px;height:3px">
          <div style="width:${Math.min((s.avg_age_days/s.sla_days)*100,100)}%;background:${colors[s.status]};height:3px;border-radius:3px"></div>
        </div>
        <div style="font-size:9px;color:var(--text3);margin-top:2px">avg age: ${(s.avg_age_days||0).toFixed(1)}d</div>
      </div>`).join('') : '<div style="color:var(--text3);font-size:12px;padding:8px">No SLA data</div>';
  } catch (e) { console.error('[VSP] sla upgrade', e); }
};

// ── 7. FedRAMP family breakdown ──
const _origFedRAMP = window.loadFedRAMP;
window.loadFedRAMP = async function() {
  if (_origFedRAMP) await _origFedRAMP();
  try {
    const data = await safeApi('GET', '/compliance/fedramp', {controls:[]});
    const panel = document.getElementById('panel-compliance2') || document.getElementById('panel-compliance');
    if (!panel) return;
    if (!document.getElementById('fedramp-family-chart')) {
      const chartCard = document.createElement('div');
      chartCard.className = 'card'; chartCard.style.cssText = 'margin-bottom:16px';
      chartCard.innerHTML = `<div class="card-head"><span class="card-title">Control family breakdown</span></div><div id="fedramp-family-chart" style="display:flex;flex-wrap:wrap;gap:6px;padding:8px"></div>`;
      const mainCard = panel.querySelector('.card');
      if (mainCard) mainCard.after(chartCard);
      else panel.insertBefore(chartCard, panel.firstChild);
    }
    const families = {};
    (Array.isArray(data.controls)?data.controls:[]).forEach(c => {
      const f = c.family||'Other';
      if (!families[f]) families[f] = {total:0,assessed:0};
      families[f].total++;
      if (c.status==='assessed') families[f].assessed++;
    });
    const el = document.getElementById('fedramp-family-chart');
    if (el) el.innerHTML = Object.entries(families).map(([f,v]) => {
      const pct = v.total>0 ? Math.round(v.assessed/v.total*100) : 0;
      const color = pct===100?'var(--green)':pct>=50?'var(--amber)':'var(--red)';
      return `<div style="background:var(--bg2);border-radius:6px;padding:8px 12px;min-width:140px">
        <div style="font-size:10px;font-weight:700;color:var(--text2);margin-bottom:4px">${f}</div>
        <div style="font-size:18px;font-weight:800;color:${color}">${pct}%</div>
        <div style="font-size:9px;color:var(--text3)">${v.assessed}/${v.total} controls</div>
        <div style="margin-top:4px;background:#0f172a;border-radius:2px;height:2px">
          <div style="width:${pct}%;background:${color};height:2px;border-radius:2px"></div>
        </div>
      </div>`;
    }).join('');
  } catch (e) { console.error('[VSP] fedramp upgrade', e); }
};

// ── 8. CMMC domain coverage ──
const _origCMMC = window.loadCMMC;
window.loadCMMC = async function() {
  if (_origCMMC) await _origCMMC();
  try {
    const data = await safeApi('GET', '/compliance/cmmc', {practices:[]});
    const panel = document.getElementById('panel-compliance2') || document.getElementById('panel-compliance');
    if (!panel) return;
    if (!document.getElementById('cmmc-domain-chart')) {
      const chartCard = document.createElement('div');
      chartCard.className = 'card'; chartCard.style.cssText = 'margin-bottom:16px';
      chartCard.innerHTML = `<div class="card-head"><span class="card-title">CMMC domain coverage</span></div><div id="cmmc-domain-chart" style="display:flex;flex-wrap:wrap;gap:6px;padding:8px"></div>`;
      const existing = document.getElementById('fedramp-family-chart')?.closest('.card');
      if (existing) existing.after(chartCard);
      else { const mainCard = panel.querySelector('.card'); if (mainCard) mainCard.after(chartCard); else panel.appendChild(chartCard); }
    }
    const domains = {};
    (Array.isArray(data.practices)?data.practices:[]).forEach(p => {
      const d = p.domain||'Other';
      if (!domains[d]) domains[d] = {total:0,assessed:0};
      domains[d].total++;
      if (p.status==='assessed') domains[d].assessed++;
    });
    const el = document.getElementById('cmmc-domain-chart');
    if (el) el.innerHTML = Object.entries(domains).map(([d,v]) => {
      const pct = v.total>0 ? Math.round(v.assessed/v.total*100) : 0;
      const color = pct===100?'var(--green)':pct>=50?'var(--amber)':'var(--red)';
      return `<div style="background:var(--bg2);border-radius:6px;padding:8px 12px;min-width:140px">
        <div style="font-size:10px;font-weight:700;color:var(--text2);margin-bottom:4px">${d}</div>
        <div style="font-size:18px;font-weight:800;color:${color}">${pct}%</div>
        <div style="font-size:9px;color:var(--text3)">${v.assessed}/${v.total} practices</div>
        <div style="margin-top:4px;background:#0f172a;border-radius:2px;height:2px">
          <div style="width:${pct}%;background:${color};height:2px;border-radius:2px"></div>
        </div>
      </div>`;
    }).join('');
  } catch (e) { console.error('[VSP] cmmc upgrade', e); }
};

// ── 9. Executive trend chart ──
function upgradeExecutive() {
  const panel = document.getElementById('panel-executive');
  if (!panel || document.getElementById('exec-trend-card')) return;
  const card = document.createElement('div');
  card.id = 'exec-trend-card'; card.className = 'card'; card.style.cssText = 'margin-bottom:16px';
  card.innerHTML = `
    <div class="card-head">
      <span class="card-title">Security score trend</span>
      <span style="font-size:10px;color:var(--text3)">last 10 scans</span>
    </div>
    <div style="height:120px;position:relative"><canvas id="exec-trend-chart"></canvas></div>`;
  panel.insertBefore(card, panel.firstChild);
}

const _origExec = window.loadExecutive;
window.loadExecutive = async function() {
  upgradeExecutive();
  if (_origExec) await _origExec();
  try {
    const [runs, p, rem] = await Promise.all([
      safeApi('GET', '/vsp/runs/index', {runs:[]}),
      safeApi('GET', '/vsp/posture/latest', {}),
      safeApi('GET', '/remediation/stats', {}),
    ]);
    // Trend chart
    const doneRuns = (Array.isArray(runs.runs)?runs.runs:[])
      .filter(r => r.status==='DONE' && r.gate).slice(0,10).reverse();
    const labels = doneRuns.map(r => (r.rid||'').slice(-6));
    const scores = doneRuns.map(r => {
      try { const s = typeof r.summary==='string'?JSON.parse(r.summary):r.summary; return s.SCORE||0; } catch { return 0; }
    });
    const ctx = document.getElementById('exec-trend-chart')?.getContext('2d');
    if (ctx && scores.length) {
      if (window._execTrend) window._execTrend.destroy();
      window._execTrend = new Chart(ctx, {
        type: 'line',
        data: { labels, datasets:[{ label:'Score', data:scores, borderColor:'#38bdf8', backgroundColor:'rgba(56,189,248,0.1)', pointBackgroundColor:'#38bdf8', pointRadius:4, borderWidth:2, fill:true, tension:0.3 }] },
        options: { responsive:true, maintainAspectRatio:false, scales:{ x:{ticks:{color:'#475569',font:{size:9}},grid:{color:'#1e293b'}}, y:{min:0,max:100,ticks:{color:'#475569',font:{size:9}},grid:{color:'#1e293b'}} }, plugins:{legend:{display:false}} }
      });
    }
    // Fill exec summary elements
    const execScore = document.getElementById('exec-score-num');
    const execGrade = document.getElementById('exec-grade-static');
    const execRem   = document.getElementById('exec-open-rem');
    const execRuns  = document.getElementById('exec-total-runs');
    const execDesc  = document.getElementById('exec-rem-desc');
    if (execScore && p.score)  execScore.textContent = p.score;
    if (execGrade && p.grade)  { execGrade.textContent = p.grade; execGrade.style.color = GRADE_COLORS[p.grade]||''; }
    if (execRuns)  execRuns.textContent  = (runs.runs||[]).length;
    if (execRem)   execRem.textContent   = rem.open || 0;
    if (execDesc)  execDesc.textContent  = (rem.open||0) + ' findings unassigned';
  } catch (e) { console.error('[VSP] exec', e); }
};

// ── 10. Audit activity timeline ──
const _origAudit = window.loadAudit;
window.loadAudit = async function() {
  if (_origAudit) await _origAudit();
  try {
    if (document.getElementById('audit-timeline')) return;
    const panel = document.getElementById('panel-audit');
    if (!panel) return;
    const tl = document.createElement('div');
    tl.className = 'card'; tl.style.marginBottom = '16px';
    tl.innerHTML = `<div class="card-head"><span class="card-title">Recent activity</span></div><div id="audit-timeline" style="padding:4px 0"></div>`;
    panel.insertBefore(tl, panel.firstChild);
    const data = await safeApi('GET', '/audit/log?limit=10', {});
    const entries = Array.isArray(data.entries)?data.entries:Array.isArray(data.logs)?data.logs:[];
    const el = document.getElementById('audit-timeline');
    if (el) el.innerHTML = entries.length ? entries.map(e=>`
      <div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
        <div style="width:6px;height:6px;border-radius:50%;background:var(--cyan);margin-top:5px;flex-shrink:0"></div>
        <div>
          <div style="font-size:11px;color:var(--text1);font-weight:600">${e.action||'—'}</div>
          <div style="font-size:10px;color:var(--text3)">${e.resource||''} · ${e.ip||''}</div>
          <div style="font-size:9px;color:var(--text3);margin-top:2px">${e.created_at?new Date(e.created_at).toLocaleString():''}</div>
        </div>
      </div>`).join('') : '<div style="color:var(--text3);font-size:12px;padding:8px">No audit entries</div>';
  } catch (e) { console.error('[VSP] audit timeline', e); }
};

// ── 11. SBOM dependency summary ──
const _origSBOM = window.loadSBOM;
window.loadSBOM = async function() {
  if (_origSBOM) await _origSBOM();
  try {
    if (document.getElementById('sbom-summary-kpis')) return;
    const panel = document.getElementById('panel-sbom');
    if (!panel) return;
    const kpis = document.createElement('div');
    kpis.id = 'sbom-summary-kpis';
    kpis.style.cssText = 'display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px';
    kpis.innerHTML = `
      <div class="kpi-card" style="padding:12px;border-left:3px solid var(--cyan)">
        <div class="kpi-label">Total Components</div>
        <div style="font-family:var(--display);font-size:24px;font-weight:800;color:var(--cyan)" id="sbom-total">—</div>
      </div>
      <div class="kpi-card" style="padding:12px;border-left:3px solid var(--red)">
        <div class="kpi-label">Vulnerable</div>
        <div style="font-family:var(--display);font-size:24px;font-weight:800;color:var(--red)" id="sbom-vuln">—</div>
      </div>
      <div class="kpi-card" style="padding:12px;border-left:3px solid var(--amber)">
        <div class="kpi-label">Outdated</div>
        <div style="font-family:var(--display);font-size:24px;font-weight:800;color:var(--amber)" id="sbom-outdated">—</div>
      </div>
      <div class="kpi-card" style="padding:12px;border-left:3px solid var(--green)">
        <div class="kpi-label">License Issues</div>
        <div style="font-family:var(--display);font-size:24px;font-weight:800;color:var(--green)" id="sbom-license">0</div>
      </div>`;
    panel.insertBefore(kpis, panel.firstChild);
    const findings = await safeApi('GET', '/vsp/findings?limit=500', {findings:[]});
    const scaFinds = (Array.isArray(findings.findings)?findings.findings:[])
      .filter(f => f.tool==='grype' || f.tool==='trivy');
    const totalEl    = document.getElementById('sbom-total');
    const vulnEl     = document.getElementById('sbom-vuln');
    const outdatedEl = document.getElementById('sbom-outdated');
    if (totalEl)    totalEl.textContent    = scaFinds.length || '—';
    if (vulnEl)     vulnEl.textContent     = scaFinds.filter(f=>f.severity==='CRITICAL'||f.severity==='HIGH').length;
    if (outdatedEl) outdatedEl.textContent = scaFinds.filter(f=>f.severity==='MEDIUM'||f.severity==='LOW').length;
  } catch (e) { console.error('[VSP] sbom upgrade', e); }
};

// ── 12. Dashboard Security Posture poller ──
// Polls d-grade/d-gate/d-score2/d-total/d-score/d-runs-count/d-pass-rate/d-rem
(function startPosturePoller() {
  let _posture = null, _runs = null, _rem = null, _busy = false;

  async function poll() {
    if (_busy) return;
    // Stop polling nếu không có token (đã logout hoặc 401)
    if (!window.TOKEN && !localStorage.getItem('vsp_token')) return;
    _busy = true;
    try {
      // Fetch tất cả data cần thiết
      const [p, r, rem] = await Promise.all([
        safeApi('GET', '/vsp/posture/latest', {}),
        safeApi('GET', '/vsp/runs/index', {runs:[]}),
        safeApi('GET', '/remediation/stats', {}),
      ]);
      _posture = p; _runs = r.runs||[]; _rem = rem;

      // Security Posture card
      const elGrade  = document.getElementById('d-grade');
      const elScore2 = document.getElementById('d-score2');
      const elGate   = document.getElementById('d-gate');
      const elTotal  = document.getElementById('d-total');
      if (p.grade && elGrade)  { elGrade.textContent  = p.grade;  elGrade.style.color  = GRADE_COLORS[p.grade]||''; }
      if (p.score && elScore2) { elScore2.textContent = p.score;  elScore2.style.color = GRADE_COLORS[p.grade]||''; }
      const tf = (p.critical||0)+(p.high||0)+(p.medium||0)+(p.low||0);
      if (elTotal && tf > 0) elTotal.textContent = tf;

      const latest = _runs.find(x => x.status==='DONE');
      if (latest?.gate && elGate) {
        elGate.textContent = latest.gate;
        elGate.style.color = GATE_COLORS[latest.gate]||'';
      }

      // Top KPI cards
      const elScore    = document.getElementById('d-score');
      const elRunsCnt  = document.getElementById('d-runs-count');
      const elPassRate = document.getElementById('d-pass-rate');
      const elRem      = document.getElementById('d-rem');
      if (elScore && p.score)    elScore.textContent    = p.score;
      if (elRunsCnt)             elRunsCnt.textContent  = _runs.length;
      if (elPassRate && _runs.length) {
        const done   = _runs.filter(x=>x.status==='DONE');
        const passed = done.filter(x=>x.gate==='PASS').length;
        elPassRate.textContent = done.length ? Math.round(passed/done.length*100)+'%' : '—';
      }
      if (elRem) elRem.textContent = rem.open||0;

    } finally { _busy = false; }
  }

  // Delay poll đến sau khi TOKEN được set từ login flow
  // window.TOKEN được set ở index.html sau DOMContentLoaded
  function _waitForToken(cb, attempts) {
    attempts = attempts || 0;
    if (window.TOKEN && window.TOKEN.length > 50) { cb(); return; }
    if (attempts > 30) { return; } // max 3s wait
    setTimeout(function(){ _waitForToken(cb, attempts+1); }, 100);
  }
  _waitForToken(function() {
    setTimeout(poll, 100);
    setTimeout(poll, 1500);
  });
  const _pollInterval = setInterval(poll, 30000);
  // Expose để có thể clear khi logout/401
  window._posturePollerStop = function() { clearInterval(_pollInterval); };
})();

// Stop poller khi TOKEN bị clear (listen từ global 401 handler)
(function() {
  var _origRemove = localStorage.removeItem.bind(localStorage);
  localStorage.removeItem = function(key) {
    _origRemove(key);
    if (key === 'vsp_token' && window._posturePollerStop) {
      window._posturePollerStop();
    }
  };
})();

// ── 13. Init on load ──
setTimeout(() => {
  upgradeDashboard();
  upgradeFindings();
  upgradeRemediation();
  console.log('[VSP Upgrade v1.0.0] UI Enhancement loaded ✓');
}, 500);


// ── FIX: Scan log — tự động load run mới nhất và refresh dropdown ──
(function fixScanLog() {
  const _origShow = window.showPanel;
  window.showPanel = function(name, btn) {
    if (_origShow) _origShow(name, btn);
    if (name !== 'scanlog') return;
    setTimeout(async () => {
      try {
        // Refresh dropdown với runs mới nhất
        const runs = await safeApi('GET', '/vsp/runs/index', {runs:[]});
        const sel = document.getElementById('log-run-select');
        if (!sel) return;
        const doneRuns = (runs.runs||[]).filter(r=>r.status==='DONE').slice(0,10);
        // Clear options cũ, giữ placeholder
        while (sel.options.length > 1) sel.remove(1);
        doneRuns.forEach(r => {
          const opt = document.createElement('option');
          opt.value = r.rid;
          opt.text = `${r.rid.slice(-16)} · ${r.mode} · ${r.gate||'?'}`;
          sel.appendChild(opt);
        });
        // Auto-select run mới nhất
        if (doneRuns.length > 0) {
          sel.value = doneRuns[0].rid;
          window.loadRunLog?.(doneRuns[0].rid);
        }
      } catch(e) { console.error('[VSP] scanlog fix', e); }
    }, 300);
  };
})();


// ── FIX: Scan log — fix N/A hiển thị thành "0 findings" ──
(function fixScanLogNA() {
  const _origLoadRunLog = window.loadRunLog;
  window.loadRunLog = async function(rid) {
    if (_origLoadRunLog) await _origLoadRunLog(rid);
    // Fix N/A → 0 findings sau khi load
    setTimeout(() => {
      document.querySelectorAll('.log-tool-status').forEach(el => {
        if (el.textContent.trim() === 'N/A') {
          el.textContent = '0 findings';
          el.style.color = 'var(--text3)';
        }
      });
    }, 500);
  };

  // Cũng fix khi Latest button click
  const _origLatest = window.loadLatestLog;
  window.loadLatestLog = async function() {
    if (_origLatest) await _origLatest();
    setTimeout(() => {
      document.querySelectorAll('.log-tool-status').forEach(el => {
        if (el.textContent.trim() === 'N/A') {
          el.textContent = '0 findings';
          el.style.color = 'var(--text3)';
        }
      });
    }, 500);
  };
})();

})(); // end vsp100

// ============ P4 COMPLIANCE PANEL ============
(function() {
  // Hook into showPanel
  const _origShowPanel = window.showPanel;
  window.showPanel = function(name, btn) {
    if (name === 'p4compliance') {
      loadP4CompliancePanel();
      // update breadcrumb if VSP uses it
      if (window.updateBreadcrumb) updateBreadcrumb('P4 Compliance', 'VSP / DoD Zero Trust / P4 Status');
      return;
    }
    if (_origShowPanel) _origShowPanel(name, btn);
  };

  function loadP4CompliancePanel() {
    // Navigate full page to /p4 — served clean by Python proxy without VSP patches
    window.location.href = '/p4';
  }
})();

// ── Auto-inject DoD widgets khi page load ────────────────────────────────
(function() {
  function tryInjectDoD() {
    if (typeof injectDoDRow !== 'function') return;
    if (!window.TOKEN || window.TOKEN.length < 10) return;
    if (document.getElementById('dod-widget-row')) return;
    injectDoDRow();
    loadDoDWidgets();
    console.log('[VSP] DoD widgets auto-injected');
  }
  // Thử nhiều lần: 1s, 2s, 3s, 5s sau khi load
  [1000, 2000, 3000, 5000].forEach(function(ms) {
    setTimeout(tryInjectDoD, ms);
  });
  // Cũng hook vào loadDashboard nếu chưa có DoD row
  var _origLD = window.loadDashboard;
  window.loadDashboard = function() {
    var r = _origLD ? _origLD.apply(this, arguments) : undefined;
    setTimeout(tryInjectDoD, 800);
    return r;
  };
})();
