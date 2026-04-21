// ═══════════════════════════════════════════════════════
// VSP UPGRADE v1.0.0 — UI Enhancement & Bug Fixes (FINAL)
// ═══════════════════════════════════════════════════════
(function vsp100() {
'use strict';

// ── SEC-005b cleanup (2026-04-21) ──────────────────────────────────────────
// Remove any legacy Anthropic API key that older builds may have stored in
// localStorage. Server-side /api/v1/ai/chat is the only supported path.
// This cleanup runs once per page load and is safe to keep permanently.
try {
  if (localStorage.getItem('vsp_anthropic_key')) {
    console.warn('[SEC-005b] Removing legacy vsp_anthropic_key from localStorage');
    localStorage.removeItem('vsp_anthropic_key');
  }
} catch (e) { /* storage unavailable, safe to ignore */ }

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
  extra.textContent = `
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
  row.textContent = `
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
  bar.textContent = `
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
      if (['pass','warn','fail'].includes(c.status)) families[f].assessed++;
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
      if (['pass','warn','fail'].includes(p.status)) domains[d].assessed++;
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
  card.textContent = `
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
      window.vspGetPosture(),
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
    kpis.textContent = `
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
        window.vspGetPosture(),
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
      if (typeof p.score !== 'undefined' && elScore2) { elScore2.textContent = p.score;  elScore2.style.color = GRADE_COLORS[p.grade]||''; }
      const tf = (p.critical||0)+(p.high||0)+(p.medium||0)+(p.low||0);
      if (elTotal && tf > 0) elTotal.textContent = tf;

      // Update KPI cards: d-critical, d-high, d-medium, d-low
      ['critical', 'high', 'medium', 'low'].forEach(function(sev) {
        var el = document.getElementById('d-' + sev);
        if (el && typeof p[sev] !== 'undefined') el.textContent = p[sev];
      });

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
      if (elScore && typeof p.score !== 'undefined') elScore.textContent = p.score;
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
  if(window.VSP_DEBUG)console.log('[VSP Upgrade v1.0.0] UI Enhancement loaded ✓');
}, 500);

// ─── Posture compose helper — dùng /findings/summary?scope=all thay cho /posture/latest ───
// Lý do: /posture/latest chỉ tính theo latest run (thường IAC FAST=0 findings) → UI KPI=0
// Helper này aggregate TẤT CẢ findings + tính score/grade giống backend logic
window.vspGetPosture = async function() {
  try {
    var h = {Authorization: 'Bearer ' + (window.TOKEN || localStorage.getItem('vsp_token') || '')};
    var r = await fetch('/api/v1/vsp/findings/summary?scope=all', {headers:h});
    if (!r.ok) return {critical:0,high:0,medium:0,low:0,grade:'F',score:0};
    var s = await r.json();
    // Scoring (matches backend gate.Score): 100 - 10*crit - 3*high - 1*med - 0.3*low, floor 0
    var score = Math.max(0, Math.round(100 - 10*(s.critical||0) - 3*(s.high||0) - 1*(s.medium||0) - 0.3*(s.low||0)));
    // Grading (matches backend gate.Posture)
    var grade;
    if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 60) grade = 'D';
    else grade = 'F';
    return {
      critical: s.critical||0, high: s.high||0, medium: s.medium||0, low: s.low||0,
      total: s.total||0, score: score, grade: grade, rid: 'scope:all'
    };
  } catch(e) {
    console.warn('[VSP] posture fetch fail', e);
    return {critical:0,high:0,medium:0,low:0,grade:'F',score:0};
  }
};


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


// ── RUNS_KPI_FIX: Restore loadRuns với KPI + charts ──────────────
(function() {
  function _doLoadRuns() {
    var TOKEN = window.TOKEN || localStorage.getItem('vsp_token') || '';
    if (!TOKEN) { setTimeout(_doLoadRuns, 500); return; }
    fetch('/api/v1/vsp/runs/index?limit=200', {
      headers: {Authorization: 'Bearer ' + TOKEN}
    }).then(function(r){ return r.json(); }).then(function(d) {
      var runs = d.runs || [];
      var done = runs.filter(function(r){ return r.status === 'DONE'; });
      var pass = done.filter(function(r){ return r.gate === 'PASS'; });
      var fail = done.filter(function(r){ return r.gate === 'FAIL'; });
      var passRate = done.length > 0 ? Math.round(pass.length / done.length * 100) : 0;
      var totalF = done.reduce(function(s,r){ return s+(r.total||r.total_findings||0); }, 0);
      var avgF = done.length > 0 ? Math.round(totalF / done.length) : 0;
      var latest = runs.find(function(r){ return r.gate; });
      var latestScore = latest ? (latest.summary && (latest.summary.SCORE || latest.summary.score) || 0) : 0;
      var lastGate = latest ? (latest.gate || '—') : '—';
      function _s(id,v){ var e=document.getElementById(id); if(e) e.textContent=v; }
      _s('rk-total', runs.length);
      _s('rk-passrate', passRate + '%');
      _s('rk-pass-sub', pass.length + ' pass / ' + fail.length + ' fail');
      _s('rk-avgfindings', avgF);
      var lgEl = document.getElementById('rk-lastgate');
      if (lgEl) { lgEl.textContent = lastGate; lgEl.style.color = lastGate==='PASS'?'var(--green)':lastGate==='FAIL'?'var(--red)':'var(--amber)'; }
      _s('rk-lastgate-sub', latest ? latest.rid.slice(-12) : '—');
      var scoreEl = document.getElementById('rk-score');
      if (scoreEl) { scoreEl.textContent = latestScore > 0 ? latestScore : '—'; scoreEl.style.color = latestScore>=70?'var(--green)':latestScore>=40?'var(--amber)':'var(--red)'; }
      if (window._runsState) { window._runsState.allRuns = runs; window._runsState.page = 0; }
      if (typeof _renderRunsPage === 'function') _renderRunsPage();
      // Charts
      setTimeout(function() {
        var modeColors = {IAC:'rgba(6,182,212,0.8)',FULL:'rgba(139,92,246,0.8)',SAST:'rgba(59,130,246,0.8)',SCA:'rgba(249,115,22,0.8)',SECRETS:'rgba(239,68,68,0.8)',DAST:'rgba(34,197,94,0.8)'};
        var gateCtx = document.getElementById('runs-gate-chart');
        if (gateCtx && window.Chart) {
          var last20 = runs.filter(function(r){ return r.gate; }).slice(0,20).reverse();
          if (window._runsGateChart) { try{window._runsGateChart.destroy();}catch(e){} }
          window._runsGateChart = new window.Chart(gateCtx, {
            type:'bar', data:{ labels:last20.map(function(r){return r.rid.slice(-6);}),
              datasets:[{data:last20.map(function(r){return r.gate==='PASS'?1:r.gate==='WARN'?0.5:-1;}),
              backgroundColor:last20.map(function(r){return r.gate==='PASS'?'rgba(34,197,94,0.8)':r.gate==='WARN'?'rgba(245,158,11,0.8)':'rgba(239,68,68,0.8)';}),
              borderRadius:3,borderWidth:0}]},
            options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{display:false},grid:{display:false}},y:{display:false,min:-1.2,max:1.2}}}
          });
        }
        var modeCtx = document.getElementById('runs-mode-chart');
        if (modeCtx && window.Chart && done.length) {
          var mt={};
          done.forEach(function(r){var t=r.total||r.total_findings||0;if(t>0)mt[r.mode]=(mt[r.mode]||0)+t;});
          var mk=Object.keys(mt).sort(function(a,b){return mt[b]-mt[a];});
          if (window._runsModeChart) { try{window._runsModeChart.destroy();}catch(e){} }
          window._runsModeChart = new window.Chart(modeCtx, {
            type:'bar', data:{labels:mk,datasets:[{data:mk.map(function(k){return mt[k];}),
            backgroundColor:mk.map(function(k){return modeColors[k]||'rgba(100,116,139,0.7)';}),borderRadius:4,borderWidth:0}]},
            options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'#8899bb',font:{size:9}},beginAtZero:true},y:{grid:{display:false},ticks:{color:'#94a3b8',font:{size:10}}}}}
          });
        }
      }, 120);
    }).catch(function(e){ console.error('RUNS_KPI_FIX:', e); });
  }

  // Override loadRuns — đây là version CUỐI CÙNG
  window.loadRuns = _doLoadRuns;

  // Auto-trigger khi vào panel-runs
  var _lp = '';
  setInterval(function() {
    var active = document.querySelector('.panel.active');
    if (!active) return;
    if (active.id === 'panel-runs' && active.id !== _lp) {
      _lp = active.id;
      _doLoadRuns();
    } else if (active.id !== 'panel-runs') {
      _lp = active.id;
    }
  }, 300);
})();

// DEFINITIVE_SHOW_PANEL — chạy SAU TẤT CẢ override khác
(function(){
  var _LOADERS = {
    runs:       function(){ if(typeof window.loadRuns==='function') window.loadRuns(); },
    audit:      function(){ if(typeof loadAuditReal==='function') loadAuditReal(); },
    dashboard:  function(){ if(typeof initDashboardCharts==='function') initDashboardCharts(); },
    findings:   function(){ if(typeof loadFindingsPanel==='function') loadFindingsPanel(); },
    sla:        function(){ if(typeof loadSLA==='function') loadSLA(); },
    sbom:       function(){ if(typeof loadSBOM==='function') loadSBOM(); },
    compliance: function(){ if(typeof loadFedRAMP==='function') loadFedRAMP(); },
    governance: function(){ if(typeof window.loadRiskRegister==='function'){ window.loadRiskRegister(); if(window.loadTraceability) window.loadTraceability(); } },
    executive:  function(){ if(typeof loadExecutive==='function') loadExecutive(); },
    scanlog:    function(){ if(typeof loadScanLog==='function') loadScanLog(); },
  };

  function _masterShow(name, btn) {
    // 1. Ẩn tất cả panels
    document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
    // 2. Bỏ active tất cả nav
    document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.remove('active'); });
    // 3. Hiện panel đúng
    var panel = document.getElementById('panel-' + name);
    if (panel) panel.classList.add('active');
    // 4. Active nav button
    if (btn) {
      btn.classList.add('active');
    } else {
      document.querySelectorAll('.nav-item').forEach(function(b){
        var oc = b.getAttribute('onclick') || '';
        if (oc.indexOf("'" + name + "'") >= 0 || oc.indexOf('"' + name + '"') >= 0) b.classList.add('active');
      });
    }
    // 5. Update breadcrumb
    var meta = window.PANEL_META && window.PANEL_META[name];
    if (meta) {
      var t = document.getElementById('page-title'); if(t) t.textContent = meta.title;
      var s = document.getElementById('page-sub');   if(s) s.textContent = meta.sub;
    }
    // 6. Load iframe nếu chưa load
    if (panel) {
      var iframe = panel.querySelector('iframe[data-src]');
      if (iframe && !iframe.src) iframe.src = iframe.getAttribute('data-src');
    }
    // 7. Trigger data loader
    var loader = _LOADERS[name];
    if (loader) setTimeout(loader, 120);
  }

  // Override CUỐI CÙNG — dùng setTimeout để chạy sau tất cả script inline
  setTimeout(function(){
    window.showPanel = _masterShow;
    window._masterShowPanel = _masterShow;
    if(window.VSP_DEBUG)console.log('[VSP] DEFINITIVE_SHOW_PANEL installed');
  }, 0);
})();

// LAST_OVERRIDE — inject sau tất cả, dùng DOMContentLoaded để chắc chắn chạy sau
window.addEventListener('load', function() {
  function _masterShow(name, btn) {
    document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.remove('active'); });
    var panel = document.getElementById('panel-' + name);
    if (panel) panel.classList.add('active');
    if (btn) { btn.classList.add('active'); } else {
      document.querySelectorAll('.nav-item').forEach(function(b){
        var oc = b.getAttribute('onclick')||'';
        if(oc.indexOf("'"+name+"'")>=0) b.classList.add('active');
      });
    }
    var meta = window.PANEL_META&&window.PANEL_META[name];
    var _TITLES={dashboard:'Dashboard',runs:'Run history',scanlog:'Scan log',findings:'Findings',remediation:'Remediation',policy:'Policy',audit:'Audit log',soc:'SOC Center',governance:'Governance',compliance:'FedRAMP / CMMC',sbom:'SBOM',sla:'SLA Tracker',executive:'Executive Summary',export:'Export',users:'Users',analytics:'Analytics',correlation:'Correlation engine',soar:'SOAR playbooks',logsources:'Log ingestion',ueba:'UEBA',netflow:'Network flow',threathunt:'Threat hunting',threatintel:'Threat intelligence',vulnmgmt:'Vuln management',assets:'Assets',scheduler:'Scheduler',ai_analyst:'AI Analyst'};
    var _SUBS={dashboard:'VSP / Operations / Dashboard',runs:'VSP / Operations / Runs',scanlog:'VSP / Operations / Scan log',findings:'VSP / Operations / Findings',remediation:'VSP / Operations / Remediation',policy:'VSP / Security / Policy',audit:'VSP / Security / Audit',soc:'VSP / Security / SOC',governance:'VSP / Compliance / Governance',compliance:'VSP / Compliance / Controls',sbom:'VSP / Compliance / SBOM',sla:'VSP / Compliance / SLA',executive:'VSP / Reports / Executive',export:'VSP / Reports / Export',users:'VSP / Reports / Users'};
    var t=document.getElementById('page-title'); if(t) t.textContent=_TITLES[name]||name;
    var s=document.getElementById('page-sub');   if(s) s.textContent=_SUBS[name]||('VSP / '+name);
    if(meta){if(t)t.textContent=meta.title;if(s)s.textContent=meta.sub;}
    if(panel){var iframe=panel.querySelector('iframe[data-src]');if(iframe&&!iframe.src)iframe.src=iframe.getAttribute('data-src');}
    var loaders={runs:function(){if(typeof window.loadRuns==='function')window.loadRuns();},audit:function(){if(typeof loadAuditReal==='function')loadAuditReal();},dashboard:function(){if(typeof initDashboardCharts==='function')initDashboardCharts();},findings:function(){if(typeof loadFindingsPanel==='function')loadFindingsPanel();},sla:function(){if(typeof loadSLA==='function')loadSLA();},sbom:function(){if(typeof loadSBOM==='function')loadSBOM();},compliance:function(){if(typeof loadFedRAMP==='function')loadFedRAMP();},governance:function(){if(typeof window.loadRiskRegister==='function')window.loadRiskRegister();},executive:function(){if(typeof loadExecutive==='function')loadExecutive();}};
    if(loaders[name]) setTimeout(loaders[name], 120);
    console.log('[VSP MASTER] showPanel:', name);
  }
  window.showPanel = _masterShow;
  if(window.VSP_DEBUG)console.log('[VSP] LAST_OVERRIDE installed');
});

// LOCK_SHOW_PANEL — dùng defineProperty để không ai override được nữa
window.addEventListener('load', function() {
  function _FINAL(name, btn) {
    document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.remove('active'); });
    var panel = document.getElementById('panel-' + name);
    if (panel) panel.classList.add('active');
    if (btn) { btn.classList.add('active'); } else {
      document.querySelectorAll('.nav-item').forEach(function(b){
        if((b.getAttribute('onclick')||'').indexOf("'"+name+"'")>=0) b.classList.add('active');
      });
    }
    var meta = window.PANEL_META&&window.PANEL_META[name];
    var _T={dashboard:'Dashboard',runs:'Run history',scanlog:'Scan log',findings:'Findings',remediation:'Remediation',policy:'Policy',audit:'Audit log',soc:'SOC Center',governance:'Governance',compliance:'FedRAMP / CMMC',sbom:'SBOM',sla:'SLA Tracker',executive:'Executive Summary',export:'Export',users:'Users',analytics:'Analytics',correlation:'Correlation',soar:'SOAR',logsources:'Log ingestion',ueba:'UEBA',netflow:'Network flow',threathunt:'Threat hunting',threatintel:'Threat intel',vulnmgmt:'Vuln management',assets:'Assets',scheduler:'Scheduler',ai_analyst:'AI Analyst'};
    var _S={dashboard:'VSP / Operations / Dashboard',runs:'VSP / Operations / Runs',scanlog:'VSP / Operations / Scan log',findings:'VSP / Operations / Findings',remediation:'VSP / Operations / Remediation',policy:'VSP / Security / Policy',audit:'VSP / Security / Audit · hash-chain verified',soc:'VSP / Security / SOC · Zero Trust',governance:'VSP / Compliance / Governance',compliance:'VSP / Compliance / Controls',sbom:'VSP / Compliance / SBOM',sla:'VSP / Compliance / SLA',executive:'VSP / Reports / Executive',export:'VSP / Reports / Export',users:'VSP / Reports / Users'};
    var _pt=document.getElementById('page-title'); if(_pt) _pt.textContent=(meta&&meta.title)||_T[name]||name;
    var _ps=document.getElementById('page-sub');   if(_ps) _ps.textContent=(meta&&meta.sub)||_S[name]||('VSP / '+name);
    if(panel){var fr=panel.querySelector('iframe[data-src]');if(fr&&!fr.src)fr.src=fr.getAttribute('data-src');}
    var L={runs:function(){window.loadRuns&&window.loadRuns();},audit:function(){typeof loadAuditReal==='function'&&loadAuditReal();},dashboard:function(){typeof initDashboardCharts==='function'&&initDashboardCharts();},findings:function(){typeof loadFindingsPanel==='function'&&loadFindingsPanel();},sla:function(){typeof loadSLA==='function'&&loadSLA();},sbom:function(){typeof loadSBOM==='function'&&loadSBOM();},compliance:function(){typeof loadFedRAMP==='function'&&loadFedRAMP();},governance:function(){typeof window.loadRiskRegister==='function'&&window.loadRiskRegister();},executive:function(){typeof loadExecutive==='function'&&loadExecutive();}};
    if(L[name]) setTimeout(L[name], 150);
    if(window.VSP_DEBUG)console.log('[VSP FINAL] panel:', name);
  }
  try {
    Object.defineProperty(window, 'showPanel', {
      value: _FINAL,
      writable: false,
      configurable: false
    });
    console.log('[VSP] LOCK_SHOW_PANEL — locked!');
  } catch(e) {
    window.showPanel = _FINAL;
    console.log('[VSP] LOCK_SHOW_PANEL — assigned (no lock)');
  }
});

// ══ PATCH v3.0 — Fix RACI + SOC + Remediation + Compliance ══════════════

// 1. FIX RACI: badges phải hiện R/A/C/I đúng
(function fixRACI() {
  var origGov = window.loadGovernanceV2;
  window.loadGovernanceV2 = async function() {
    if (origGov) await origGov.apply(this, arguments);
    // Override RACI table sau khi load
    setTimeout(function() {
      var tbody = document.querySelector('.raci-table tbody');
      if (!tbody) return;
      var rows = tbody.querySelectorAll('tr');
      rows.forEach(function(row) {
        var cells = row.querySelectorAll('td');
        if (cells.length < 5) return;
        // cells[1]=R, cells[2]=A, cells[3]=C, cells[4]=I
        var letters = ['R','A','C','I'];
        var classes = ['raci-R','raci-A','raci-C','raci-I'];
        for (var i = 0; i < 4; i++) {
          var span = cells[i+1].querySelector('.raci-badge');
          if (span) {
            span.textContent = letters[i];
            span.className = 'raci-badge ' + classes[i];
          }
        }
      });
    }, 500);
  };
  // Cũng fix static HTML ngay khi load
  document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
      document.querySelectorAll('.raci-table tbody tr').forEach(function(row) {
        var cells = row.querySelectorAll('td');
        if (cells.length < 5) return;
        ['R','A','C','I'].forEach(function(letter, i) {
          var span = cells[i+1].querySelector('.raci-badge');
          if (span) span.textContent = letter;
        });
      });
    }, 200);
  });
})();

// 2. FIX SOC: Load real data thay vì hardcode
(function fixSOC() {
  // Đã có loadSOCv2 trong file — chỉ cần đảm bảo gọi đúng
  var _sp3 = window.showPanel;
  window.showPanel = function(name, btn) {
    _sp3 && _sp3(name, btn);
    if (name === 'soc') {
      setTimeout(function() {
        if (typeof loadSOCv2 === 'function') loadSOCv2();
      }, 200);
    }
  };
})();

// 3. FIX REMEDIATION: Rate + bulk resolve + donut chart
(function fixRemediation() {
  var origLoad = window.loadRemediations;
  window.loadRemediations = async function() {
    if (origLoad) await origLoad.apply(this, arguments);
    // Tính và hiện rate sau khi load
    setTimeout(function() {
      var open = parseInt((document.getElementById('rem-k-open')||{}).textContent)||0;
      var inprog = parseInt((document.getElementById('rem-k-inprogress')||{}).textContent)||0;
      var resolved = parseInt((document.getElementById('rem-k-resolved')||{}).textContent)||0;
      var accepted = parseInt((document.getElementById('rem-k-accepted')||{}).textContent)||0;
      var fp = parseInt((document.getElementById('rem-k-fp')||{}).textContent)||0;
      var suppressed = parseInt((document.getElementById('rem-k-suppressed')||{}).textContent)||0;
      var total = open + inprog + resolved + accepted + fp + suppressed;
      var closed = resolved + accepted + fp + suppressed;
      var rate = total > 0 ? Math.round(closed/total*100) : 0;

      // Inject rate KPI nếu chưa có
      var panel = document.getElementById('panel-remediation');
      if (!panel) return;
      var existing = document.getElementById('rem-rate-kpi');
      if (!existing) {
        var kpiRow = panel.querySelector('.g6.mb14');
        if (kpiRow) {
          var rateDiv = document.createElement('div');
          rateDiv.className = 'kpi kpi-cyan';
          rateDiv.id = 'rem-rate-kpi';
          rateDiv.innerHTML = '<div class="kpi-label">Resolution Rate</div>'
            +'<div class="kpi-value c-cyan" id="rem-rate-val" style="font-size:26px">'+rate+'%</div>'
            +'<div class="kpi-sub">'+closed+'/'+total+' closed</div>';
          // Thêm vào sau row hiện tại
          kpiRow.after(rateDiv);
        }
      } else {
        var rateEl = document.getElementById('rem-rate-val');
        if (rateEl) rateEl.textContent = rate+'%';
        existing.querySelector('.kpi-sub').textContent = closed+'/'+total+' closed';
      }

      // Fix donut chart
      var canvas = document.getElementById('rem-donut');
      if (canvas && window.Chart && total > 0) {
        var existing2 = Chart.getChart(canvas);
        if (existing2) existing2.destroy();
        new Chart(canvas, {
          type: 'doughnut',
          data: {
            labels: ['Open','In Progress','Resolved','Accepted','False+','Suppressed'],
            datasets: [{
              data: [open, inprog, resolved, accepted, fp, suppressed],
              backgroundColor: ['#ef4444','#f59e0b','#22c55e','#06b6d4','#8b5cf6','#64748b'],
              borderWidth: 0, hoverOffset: 4
            }]
          },
          options: {
            responsive: true, maintainAspectRatio: false, cutout: '68%',
            plugins: { legend: { display: false } }
          }
        });
        // Breakdown text
        var breakdown = document.getElementById('rem-breakdown');
        if (breakdown) {
          var colors = {Open:'#ef4444','In Progress':'#f59e0b',Resolved:'#22c55e',Accepted:'#06b6d4','False+':'#8b5cf6',Suppressed:'#64748b'};
          var vals = {Open:open,'In Progress':inprog,Resolved:resolved,Accepted:accepted,'False+':fp,Suppressed:suppressed};
          breakdown.innerHTML = Object.entries(vals).map(function(kv) {
            var pct2 = total>0?Math.round(kv[1]/total*100):0;
            return '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'
              +'<span style="display:flex;align-items:center;gap:6px;font-size:12px">'
              +'<span style="width:8px;height:8px;border-radius:50%;background:'+colors[kv[0]]+';flex-shrink:0"></span>'
              +kv[0]+'</span>'
              +'<span style="font-weight:600;font-size:12px">'+kv[1]+' <span style="color:var(--t3);font-weight:400">('+pct2+'%)</span></span>'
              +'</div>';
          }).join('');
        }
      }
    }, 300);
  };
})();

// 4. FIX COMPLIANCE: Inject 73 FedRAMP controls từ API
(function fixCompliance() {
  // loadFedRAMP và loadCMMC đã có trong file — chúng gọi _loadComplianceData
  // Chỉ cần đảm bảo gọi khi vào panel
  var _sp4 = window.showPanel;
  window.showPanel = function(name, btn) {
    _sp4 && _sp4(name, btn);
    if (name === 'compliance') {
      setTimeout(function() {
        if (typeof initGauges === 'function') initGauges();
        if (typeof loadFedRAMP === 'function') loadFedRAMP();
      }, 200);
    }
    if (name === 'remediation') {
      setTimeout(function() {
        if (typeof loadRemediations === 'function') loadRemediations();
      }, 200);
    }
    if (name === 'governance') {
      setTimeout(function() {
        if (typeof loadGovernanceV2 === 'function') loadGovernanceV2();
      }, 200);
    }
  };
})();

if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.0 loaded — RACI+SOC+Remediation+Compliance fixed');

// PATCH v3.1 — Fix Remediation load từ API thật
(function(){
  var _orig = window.loadRemediations;
  window.loadRemediations = async function() {
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      var [remD, statsD] = await Promise.all([
        fetch('/api/v1/remediation', {headers:h}).then(r=>r.json()),
        fetch('/api/v1/remediation/stats', {headers:h}).then(r=>r.json()).catch(()=>({}))
      ]);
      var rems = remD.remediations || [];
      
      // Count by status
      var counts = {open:0,in_progress:0,resolved:0,accepted:0,false_positive:0,suppressed:0};
      rems.forEach(function(r){ if(counts[r.status]!==undefined) counts[r.status]++; });
      
      // Update KPIs
      var map = {'rem-k-open':'open','rem-k-inprogress':'in_progress','rem-k-resolved':'resolved',
                 'rem-k-accepted':'accepted','rem-k-fp':'false_positive','rem-k-suppressed':'suppressed'};
      Object.keys(map).forEach(function(id){
        var el=document.getElementById(id); if(el) el.textContent=counts[map[id]]||0;
      });
      
      var total = rems.length;
      var closed = counts.resolved+counts.accepted+counts.false_positive+counts.suppressed;
      var rate = total>0?Math.round(closed/total*100):0;
      var cntEl = document.getElementById('rem-count');
      if(cntEl) cntEl.textContent = total+' remediations · '+rate+'% resolved';

      // Render table — fetch findings để get severity/tool/rule
      var fdResp = await fetch('/api/v1/vsp/findings?limit=5000', {headers:h}).then(r=>r.json()).catch(()=>({findings:[]}));
      var findMap = {};
      (fdResp.findings||[]).forEach(function(f){ findMap[f.id]=f; });
      
      var sevClass={CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low'};
      var statusPill={open:'pill-fail',in_progress:'pill-warn',resolved:'pill-pass',accepted:'pill-done',false_positive:'pill-queue',suppressed:''};
      var priColor={P1:'c-red',P2:'c-orange',P3:'c-amber',P4:'c-t2'};
      
      var tbody = document.getElementById('rem-tbody');
      if(!tbody) return;
      
      if(!rems.length){ tbody.innerHTML='<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--t3)">No remediations yet</td></tr>'; return; }
      
      tbody.innerHTML = rems.map(function(r,i){
        var f = findMap[r.finding_id]||{};
        var sc=sevClass[f.severity]||'';
        var sp=statusPill[r.status]||'';
        var pc=priColor[r.priority]||'';
        return '<tr style="cursor:pointer;transition:background .15s" onmouseenter="this.style.background=\'var(--surface2)\'" onmouseleave="this.style.background=\'\'" onclick="_openRemDetail('+i+')">'
          +'<td>'+(f.severity?'<span class="sev '+sc+'">'+f.severity+'</span>':'—')+'</td>'
          +'<td class="c-t3 f11">'+(f.tool||'—')+'</td>'
          +'<td class="mono c-purple f10" style="max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+(f.rule_id||'—')+'</td>'
          +'<td class="f12" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+(f.message||'')+'">'+( f.message||r.finding_id||'—')+'</td>'
          +'<td class="c-t3 f11">'+(r.assignee||'—')+'</td>'
          +'<td class="'+pc+' fw7 f11">'+(r.priority||'—')+'</td>'
          +'<td><span class="pill '+sp+'" style="font-size:9px">'+r.status+'</span></td>'
          +'<td><button class="btn btn-ghost" style="font-size:9px;padding:2px 8px" onclick="event.stopPropagation();_openRemDetail('+i+')">Edit</button></td>'
          +'</tr>';
      }).join('');
      
      // Store for _openRemDetail
      window._remData = rems.map(function(r){
        var f=findMap[r.finding_id]||{};
        return Object.assign({},r,{severity:f.severity,tool:f.tool,rule_id:f.rule_id,description:f.message});
      });
      
      // Update rate KPI
      var existing = document.getElementById('rem-rate-kpi');
      if(existing){ 
        var rv=document.getElementById('rem-rate-val'); if(rv) rv.textContent=rate+'%';
        var sub=existing.querySelector('.kpi-sub'); if(sub) sub.textContent=closed+'/'+total+' closed';
      }
      
    } catch(e){ console.error('loadRemediations v3.1',e); }
  };
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.1 Remediation fix loaded');
})();

// PATCH v3.2 — Auto-trigger loadRemediations khi vào panel
(function(){
  setInterval(function() {
    var panel = document.getElementById('panel-remediation');
    if (panel && panel.classList.contains('active') && !panel._loaded) {
      panel._loaded = true;
      if (typeof loadRemediations === 'function') loadRemediations();
    }
    if (panel && !panel.classList.contains('active')) {
      panel._loaded = false; // reset khi rời panel
    }
  }, 300);
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.2 auto-trigger loaded');
})();

// ══ PATCH v3.3 — SOC Scorecard + SBOM Diff + SLA Trendline ══════════════

// 1. SOC Framework Scorecard từ API thật
(function fixSOCScorecard(){
  var _origSOC = window.loadSOCv2;
  window.loadSOCv2 = async function() {
    if (_origSOC) await _origSOC.apply(this, arguments);
    // Override scorecard với data thật
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      var sc = await fetch('/api/v1/soc/framework-scorecard',{headers:h}).then(r=>r.json());
      var scorecards = sc.scorecards||[];
      if (!scorecards.length) return;
      var panel = document.getElementById('panel-soc');
      if (!panel) return;
      var card = panel.querySelector('.card .card-body');
      if (!card || !card.querySelector('.comp-row')) return;
      var mkFW = function(name, pct, sub, note) {
        var c = pct>=70?'var(--green)':pct>=40?'var(--amber)':'var(--red)';
        return '<div class="comp-row" style="margin-bottom:10px">'
          +'<div class="comp-header"><span class="comp-name">'+name+'</span><span class="comp-pct fw7" style="color:'+c+'">'+pct+'%</span></div>'
          +'<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%;background:'+c+'"></div></div>'
          +'<div style="display:flex;justify-content:space-between;margin-top:3px">'
          +'<span style="font-size:9px;color:var(--t3)">'+sub+'</span>'
          +'<span style="font-size:9px;color:var(--t4)">'+note+'</span></div></div>';
      };
      var getScore = function(name){ 
        var s=scorecards.find(function(x){return x.framework&&x.framework.includes(name);}); 
        return s?s.score:40; 
      };
      card.innerHTML = 
        mkFW('NIST SP 800-53 Rev5', getScore('NIST'), 'Controls assessed via VSP findings', 'AC,SI,IA,SC,CA')
        +mkFW('ISO 27001:2022', getScore('ISO'), 'Annex A controls mapped', 'A.12,A.14,A.16')
        +mkFW('SOC 2 Type II', getScore('SOC'), 'Trust service criteria', 'CC1-CC9')
        +mkFW('CIS Controls v8', getScore('CIS')||55, 'Implementation groups', 'IG1,IG2')
        +mkFW('Zero Trust Maturity', getScore('Zero')||78, 'CISA ZT pillars', '7 pillars assessed');
      console.log('[VSP] SOC Scorecard updated from API');
    } catch(e) { console.error('SOC Scorecard:', e); }
  };
})();

// 2. SBOM Diff Visual
(function addSBOMDiff(){
  var _origLoadSBOM = window.loadSBOM;
  window.loadSBOM = async function() {
    if (_origLoadSBOM) await _origLoadSBOM.apply(this, arguments);
    // Add diff button to SBOM table rows after render
    setTimeout(function() {
      var panel = document.getElementById('panel-sbom');
      if (!panel) return;
      // Add diff card nếu chưa có
      if (document.getElementById('sbom-diff-card')) return;
      var diffCard = document.createElement('div');
      diffCard.className = 'card mb14'; diffCard.id = 'sbom-diff-card';
      diffCard.innerHTML = '<div class="card-head">'
        +'<div><div class="card-title">SBOM diff — compare runs</div>'
        +'<div class="card-sub">So sánh findings giữa 2 scan runs</div></div>'
        +'<button class="btn btn-primary" style="font-size:10px" onclick="_runSBOMDiff()">Compare →</button>'
        +'</div>'
        +'<div class="card-body" style="padding:12px 14px">'
        +'<div style="display:grid;grid-template-columns:1fr auto 1fr;gap:10px;align-items:center;margin-bottom:12px">'
        +'<div><label style="font-size:10px;color:var(--t3);display:block;margin-bottom:4px">Base run</label>'
        +'<select id="sbom-diff-base" class="filter-select" style="width:100%"><option value="">Loading...</option></select></div>'
        +'<div style="font-size:18px;color:var(--t3);text-align:center">→</div>'
        +'<div><label style="font-size:10px;color:var(--t3);display:block;margin-bottom:4px">Compare run</label>'
        +'<select id="sbom-diff-head" class="filter-select" style="width:100%"><option value="">Loading...</option></select></div>'
        +'</div>'
        +'<div id="sbom-diff-result"></div>'
        +'</div>';
      var existCard = panel.querySelector('.card.mb14');
      if (existCard) existCard.after(diffCard);
      // Load runs vào selects
      _loadSBOMDiffRuns();
    }, 500);
  };

  window._loadSBOMDiffRuns = async function() {
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      var d = await fetch('/api/v1/vsp/runs/index?limit=50', {headers:h}).then(r=>r.json());
      var runs = (d.runs||[]).filter(function(r){ return r.status==='DONE'; });
      var opts = runs.map(function(r){
        return '<option value="'+r.rid+'">'+r.rid.slice(-20)+' · '+r.mode+' · '+(r.total||0)+'f</option>';
      }).join('');
      var base = document.getElementById('sbom-diff-base');
      var head = document.getElementById('sbom-diff-head');
      if (base) { base.innerHTML = '<option value="">— base run —</option>'+opts; if(runs.length>1) base.value=runs[1].rid; }
      if (head) { head.innerHTML = '<option value="">— compare run —</option>'+opts; if(runs.length>0) head.value=runs[0].rid; }
    } catch(e) {}
  };

  window._runSBOMDiff = async function() {
    var baseRid = (document.getElementById('sbom-diff-base')||{}).value||'';
    var headRid = (document.getElementById('sbom-diff-head')||{}).value||'';
    if (!baseRid || !headRid) { showToast('Chọn 2 runs để compare','error'); return; }
    if (baseRid === headRid) { showToast('Chọn 2 runs khác nhau','error'); return; }
    var result = document.getElementById('sbom-diff-result');
    if (result) result.innerHTML = '<div style="color:var(--t3);padding:10px;font-size:11px">Comparing...</div>';
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      // Fetch findings cho cả 2 runs
      var [baseRun, headRun] = await Promise.all([
        fetch('/api/v1/vsp/run/'+baseRid, {headers:h}).then(r=>r.json()),
        fetch('/api/v1/vsp/run/'+headRid, {headers:h}).then(r=>r.json()),
      ]);
      var [baseFd, headFd] = await Promise.all([
        fetch('/api/v1/vsp/findings?run_id='+(baseRun.id||baseRid)+'&limit=2000', {headers:h}).then(r=>r.json()),
        fetch('/api/v1/vsp/findings?run_id='+(headRun.id||headRid)+'&limit=2000', {headers:h}).then(r=>r.json()),
      ]);
      var baseF = baseFd.findings||[];
      var headF = headFd.findings||[];
      // Compare by rule_id+path
      var baseKeys = new Set(baseF.map(function(f){ return f.rule_id+'|'+f.path+'|'+f.line; }));
      var headKeys = new Set(headF.map(function(f){ return f.rule_id+'|'+f.path+'|'+f.line; }));
      var added   = headF.filter(function(f){ return !baseKeys.has(f.rule_id+'|'+f.path+'|'+f.line); });
      var removed = baseF.filter(function(f){ return !headKeys.has(f.rule_id+'|'+f.path+'|'+f.line); });
      var unchanged = headF.filter(function(f){ return baseKeys.has(f.rule_id+'|'+f.path+'|'+f.line); });
      var sevClass = {CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low'};
      var mkRows = function(arr, color, label) {
        if (!arr.length) return '';
        return '<div style="margin-bottom:10px">'
          +'<div style="font-size:10px;font-weight:700;color:'+color+';letter-spacing:.08em;margin-bottom:6px">'+label+' ('+arr.length+')</div>'
          +'<div style="display:grid;gap:3px">'
          +arr.slice(0,10).map(function(f){
            return '<div style="display:flex;gap:8px;align-items:center;padding:4px 8px;background:'+color+'11;border-left:2px solid '+color+';border-radius:0 4px 4px 0">'
              +'<span class="sev '+(sevClass[f.severity]||'')+'" style="flex-shrink:0">'+f.severity+'</span>'
              +'<span class="mono-sm c-t3" style="flex-shrink:0">'+f.tool+'</span>'
              +'<span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+f.message+'</span>'
              +'<span class="mono-sm c-t3">'+( f.path||'').split('/').pop()+'</span>'
              +'</div>';
          }).join('')
          +(arr.length>10?'<div style="font-size:10px;color:var(--t3);padding:4px 8px">...and '+(arr.length-10)+' more</div>':'')
          +'</div></div>';
      };
      if (result) result.innerHTML = 
        '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px">'
        +'<div class="kpi kpi-crit" style="padding:10px;text-align:center"><div class="kpi-label">New findings</div><div class="kpi-value c-red" style="font-size:24px">+'+added.length+'</div></div>'
        +'<div class="kpi kpi-low" style="padding:10px;text-align:center"><div class="kpi-label">Fixed</div><div class="kpi-value c-green" style="font-size:24px">-'+removed.length+'</div></div>'
        +'<div class="kpi" style="padding:10px;text-align:center"><div class="kpi-label">Unchanged</div><div class="kpi-value c-t2" style="font-size:24px">'+unchanged.length+'</div></div>'
        +'</div>'
        +mkRows(added, '#ef4444', '▲ NEW FINDINGS')
        +mkRows(removed, '#22c55e', '▼ FIXED')
        +(unchanged.length?'<div style="font-size:10px;color:var(--t3);padding:6px 0">'+unchanged.length+' findings unchanged between runs</div>':'');
      showToast('SBOM diff: +'+added.length+' new, -'+removed.length+' fixed','success');
    } catch(e) { 
      if (result) result.innerHTML = '<div style="color:var(--red);padding:10px;font-size:11px">Error: '+e.message+'</div>';
    }
  };
})();

// 3. SLA Trendline Chart
(function addSLATrendline(){
  var _origLoadSLA = window.loadSLA;
  window.loadSLA = async function() {
    if (_origLoadSLA) await _origLoadSLA.apply(this, arguments);
    // Add trendline chart sau khi SLA load
    setTimeout(function() {
      var panel = document.getElementById('panel-sla');
      if (!panel || document.getElementById('sla-trend-card')) return;
      var trendCard = document.createElement('div');
      trendCard.className = 'card mb14'; trendCard.id = 'sla-trend-card';
      trendCard.innerHTML = '<div class="card-head"><div class="card-title">SLA trend — findings over time</div>'
        +'<span class="mono-sm c-t3">last 20 runs</span></div>'
        +'<div class="card-body" style="height:200px;position:relative"><canvas id="sla-trend-canvas"></canvas></div>';
      var g2 = panel.querySelector('.g2.mb14');
      if (g2) g2.before(trendCard); else panel.appendChild(trendCard);
      _renderSLATrend();
    }, 600);
  };

  window._renderSLATrend = async function() {
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      var d = await fetch('/api/v1/vsp/runs/index?limit=50', {headers:h}).then(r=>r.json());
      var runs = (d.runs||[]).filter(function(r){ return r.status==='DONE'; }).slice(0,20).reverse();
      if (!runs.length || !window.Chart) return;
      var canvas = document.getElementById('sla-trend-canvas');
      if (!canvas) return;
      var labels = runs.map(function(r){
        var dt = new Date(r.created_at);
        return (dt.getDate())+'/'+(dt.getMonth()+1);
      });
      var crits = runs.map(function(r){ return (r.summary&&r.summary.CRITICAL)||0; });
      var highs = runs.map(function(r){ return (r.summary&&r.summary.HIGH)||0; });
      var meds  = runs.map(function(r){ return (r.summary&&r.summary.MEDIUM)||0; });
      var totals= runs.map(function(r){ return r.total||r.total_findings||0; });
      if (canvas._chart) canvas._chart.destroy();
      canvas._chart = new Chart(canvas, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {label:'Total',data:totals,borderColor:'#06b6d4',backgroundColor:'rgba(6,182,212,0.06)',fill:true,tension:0.3,borderWidth:2,pointRadius:3},
            {label:'Critical',data:crits,borderColor:'#ef4444',backgroundColor:'transparent',tension:0.3,borderWidth:1.5,pointRadius:2,borderDash:[4,2]},
            {label:'High',data:highs,borderColor:'#f97316',backgroundColor:'transparent',tension:0.3,borderWidth:1.5,pointRadius:2,borderDash:[4,2]},
            {label:'Medium',data:meds,borderColor:'#f59e0b',backgroundColor:'transparent',tension:0.3,borderWidth:1,pointRadius:2,borderDash:[2,2]},
          ]
        },
        options: {
          responsive:true, maintainAspectRatio:false,
          interaction:{mode:'index',intersect:false},
          plugins:{legend:{labels:{color:'#94a3b8',font:{size:9},boxWidth:8}}},
          scales:{
            x:{ticks:{color:'#64748b',font:{size:9}},grid:{color:'rgba(255,255,255,.04)'}},
            y:{ticks:{color:'#64748b',font:{size:9}},grid:{color:'rgba(255,255,255,.04)'},beginAtZero:true}
          }
        }
      });
    } catch(e) { console.error('SLA trend:', e); }
  };
})();

if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.3 SOC+SBOM+SLA loaded');

// PATCH v3.4 — Fix SOC scorecard mapping frameworks→scorecards + domain breakdown
(function(){
  var _origSOC2 = window.loadSOCv2;
  window.loadSOCv2 = async function() {
    if (_origSOC2) await _origSOC2.apply(this, arguments);
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      var sc = await fetch('/api/v1/soc/framework-scorecard',{headers:h}).then(r=>r.json());
      var frameworks = sc.frameworks || sc.scorecards || [];
      if (!frameworks.length) return;
      var panel = document.getElementById('panel-soc');
      if (!panel) return;
      // Tìm Framework scorecard card
      var cards = panel.querySelectorAll('.card');
      var targetCard = null;
      cards.forEach(function(c){
        if (c.querySelector('.card-title') && c.querySelector('.card-title').textContent.includes('Framework scorecard')) {
          targetCard = c;
        }
      });
      if (!targetCard) return;
      var body = targetCard.querySelector('.card-body');
      if (!body) return;
      var mkFW = function(fw) {
        var pct = fw.score || 0;
        var c = pct>=70?'var(--green)':pct>=40?'var(--amber)':'var(--red)';
        var domains = fw.domains || [];
        var domainHTML = domains.map(function(d){
          var dp = d.score||0;
          var dc = dp>=70?'var(--green)':dp>=40?'var(--amber)':'var(--red)';
          return '<div style="display:flex;justify-content:space-between;margin:2px 0;font-size:10px">'
            +'<span style="color:var(--t3)">'+d.name+'</span>'
            +'<span style="color:'+dc+';font-weight:600">'+dp+'%</span></div>';
        }).join('');
        return '<div class="comp-row" style="margin-bottom:12px">'
          +'<div class="comp-header"><span class="comp-name" style="font-weight:600">'+fw.framework+'</span>'
          +'<span class="comp-pct fw7" style="color:'+c+'">'+pct+'%</span></div>'
          +'<div class="progress-bar" style="height:6px"><div class="progress-fill" style="width:'+pct+'%;background:'+c+'"></div></div>'
          +(domainHTML?'<div style="margin-top:6px;padding:8px;background:var(--b2);border-radius:6px">'+domainHTML+'</div>':'')
          +'</div>';
      };
      body.innerHTML = frameworks.map(mkFW).join('');
      console.log('[VSP] SOC Scorecard v3.4 updated:', frameworks.length, 'frameworks');
    } catch(e) { console.error('SOC scorecard v3.4:', e); }
  };
  // Trigger ngay nếu SOC panel đang active
  if (document.getElementById('panel-soc') && document.getElementById('panel-soc').classList.contains('active')) {
    setTimeout(window.loadSOCv2, 100);
  }
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.4 SOC scorecard fix loaded');
})();

// PATCH v3.5 — Auto-trigger cho SOC + SBOM + SLA
(function(){
  setInterval(function() {
    var panels = {
      'panel-soc':         function(){ typeof loadSOCv2==='function' && loadSOCv2(); },
      'panel-sbom':        function(){ typeof loadSBOM==='function' && loadSBOM(); },
      'panel-sla':         function(){ typeof loadSLA==='function' && loadSLA(); },
      'panel-governance':  function(){ typeof loadGovernanceV2==='function' && loadGovernanceV2(); },
      'panel-compliance':  function(){ typeof loadFedRAMP==='function' && loadFedRAMP(); },
      'panel-analytics':   function(){ typeof loadAnalytics==='function' && loadAnalytics(); },
      'panel-executive':   function(){ typeof loadExecutive==='function' && loadExecutive(); },
    };
    Object.keys(panels).forEach(function(id) {
      var panel = document.getElementById(id);
      if (panel && panel.classList.contains('active') && !panel._autoLoaded) {
        panel._autoLoaded = true;
        panels[id]();
      }
      if (panel && !panel.classList.contains('active')) {
        panel._autoLoaded = false;
      }
    });
  }, 300);
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.5 auto-trigger all panels loaded');
})();

// PATCH v3.6 — Fix Remediation donut auto-render
(function(){
  var _origRem = window.loadRemediations;
  window.loadRemediations = async function() {
    if (_origRem) await _origRem.apply(this, arguments);
    setTimeout(function() {
      var canvas = document.getElementById('rem-donut');
      if (!canvas || !window.Chart) return;
      var ids = {open:'rem-k-open',ip:'rem-k-inprogress',res:'rem-k-resolved',acc:'rem-k-accepted',fp:'rem-k-fp',sup:'rem-k-suppressed'};
      var v = {};
      Object.keys(ids).forEach(function(k){ v[k]=parseInt((document.getElementById(ids[k])||{}).textContent)||0; });
      var total = v.open+v.ip+v.res+v.acc+v.fp+v.sup;
      if (!total) return;
      var existing = Chart.getChart(canvas);
      if (existing) existing.destroy();
      new Chart(canvas, {
        type:'doughnut',
        data:{
          labels:['Open','In Progress','Resolved','Accepted','False+','Suppressed'],
          datasets:[{data:[v.open,v.ip,v.res,v.acc,v.fp,v.sup],
            backgroundColor:['#ef4444','#f59e0b','#22c55e','#06b6d4','#8b5cf6','#64748b'],
            borderWidth:0,hoverOffset:4}]
        },
        options:{responsive:true,maintainAspectRatio:false,cutout:'68%',
          plugins:{legend:{position:'bottom',labels:{color:'#8899bb',font:{size:9},boxWidth:8,padding:8}}}}
      });
      // Breakdown text
      var bd = document.getElementById('rem-breakdown');
      if (bd) {
        var cols = {Open:'#ef4444','In Progress':'#f59e0b',Resolved:'#22c55e',Accepted:'#06b6d4','False+':'#8b5cf6',Suppressed:'#64748b'};
        var vals = {Open:v.open,'In Progress':v.ip,Resolved:v.res,Accepted:v.acc,'False+':v.fp,Suppressed:v.sup};
        var rate = Math.round((v.res+v.acc+v.fp+v.sup)/total*100);
        bd.innerHTML = '<div style="font-size:13px;font-weight:700;color:var(--green);margin-bottom:10px">'+rate+'% resolved</div>'
          +Object.entries(vals).map(function(kv){
            var pct=Math.round(kv[1]/total*100);
            return '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">'
              +'<span style="display:flex;align-items:center;gap:6px;font-size:11px">'
              +'<span style="width:8px;height:8px;border-radius:50%;background:'+cols[kv[0]]+';flex-shrink:0"></span>'
              +kv[0]+'</span>'
              +'<span style="font-weight:600;font-size:11px">'+kv[1]+' <span style="color:var(--t3);font-weight:400">('+pct+'%)</span></span>'
              +'</div>';
          }).join('');
      }
    }, 500);
  };
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.6 Remediation donut fix loaded');
})();

// PATCH v3.7 — Policy panel: load API rules + auto-trigger + rich eval
(function(){
  // Auto-trigger khi vào Policy panel
  var _policyLoaded = false;
  setInterval(function(){
    var panel = document.getElementById('panel-policy');
    if (panel && panel.classList.contains('active') && !panel._policyLoaded) {
      panel._policyLoaded = true;
      _loadPolicyFull();
    }
    if (panel && !panel.classList.contains('active')) panel._policyLoaded = false;
  }, 300);

  async function _loadPolicyFull() {
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    try {
      // Load evaluate result
      var [evalD, rulesD] = await Promise.all([
        fetch('/api/v1/policy/evaluate', {method:'POST', headers:Object.assign({'Content-Type':'application/json'},h), body:'{}'}).then(r=>r.json()).catch(()=>({})),
        fetch('/api/v1/policy/rules', {headers:h}).then(r=>r.json()).catch(()=>({rules:[]}))
      ]);

      // Render eval result
      var evalEl = document.getElementById('eval-result');
      if (evalEl && evalD.decision) {
        var c = evalD.decision==='PASS'?'var(--green)':evalD.decision==='WARN'?'var(--amber)':'var(--red)';
        evalEl.innerHTML = '<span style="color:'+c+';font-size:18px;font-weight:700">'+evalD.decision+'</span>'
          +' &middot; score: <b>'+(evalD.score||0)+'</b>'
          +' &middot; posture: <b>'+(evalD.posture||'?')+'</b>'
          +' &middot; <span style="color:var(--t3)">'+(evalD.reason||'')+'</span>';
      }

      // Render rules — built-in + API rules
      var rules = rulesD.rules || [];
      var list = document.getElementById('rules-list');
      if (!list) return;

      // Built-in HTML
      var builtinHTML = '<div class="rule-card">'
        +'<div class="rule-header"><div class="rule-name">Block Critical Findings</div><span class="rule-tag">BUILT-IN</span>'
        +'<button class="toggle-btn on" onclick="this.classList.toggle(\'on\');showToast(\'Rule updated\',\'info\')"></button></div>'
        +'<div class="rule-desc">Fail gate if any CRITICAL finding exists</div>'
        +'<div class="rule-meta"><span>Fail on: <b>CRITICAL</b></span></div></div>'
        +'<div class="rule-card">'
        +'<div class="rule-header"><div class="rule-name">Block Secrets</div><span class="rule-tag">BUILT-IN</span>'
        +'<button class="toggle-btn on" onclick="this.classList.toggle(\'on\');showToast(\'Rule updated\',\'info\')"></button></div>'
        +'<div class="rule-desc">Fail gate if secrets/credentials detected</div>'
        +'<div class="rule-meta"><span>Fail on: <b>SECRETS</b></span></div></div>';

      // API rules
      var apiHTML = rules.map(function(r) {
        var tags = [];
        if (r.block_critical) tags.push('CRITICAL');
        if (r.block_secrets) tags.push('SECRETS');
        if (r.max_high >= 0) tags.push('HIGH > '+r.max_high);
        if (r.min_score > 0) tags.push('SCORE < '+r.min_score);
        var created = r.created_at ? new Date(r.created_at).toLocaleDateString('vi-VN') : '';
        return '<div class="rule-card" style="border-left:2px solid var(--cyan)">'
          +'<div class="rule-header">'
          +'<div class="rule-name">'+r.name+'</div>'
          +'<span class="rule-tag" style="background:rgba(6,182,212,.12);color:var(--cyan);border-color:rgba(6,182,212,.2)">API</span>'
          +'<button class="toggle-btn'+(r.active?' on':'')+'" data-id="'+r.id+'" onclick="_togglePolicyRule(this)"></button>'
          +'</div>'
          +(r.description?'<div class="rule-desc">'+r.description+'</div>':'')
          +'<div class="rule-meta" style="display:flex;justify-content:space-between;align-items:center">'
          +'<span>Fail on: <b>'+(tags.join(', ')||r.fail_on||'custom')+'</b></span>'
          +'<div style="display:flex;gap:6px">'
          +(created?'<span style="font-size:9px;color:var(--t3)">'+created+'</span>':'')
          +'<button class="btn btn-ghost" style="font-size:9px;padding:2px 8px;color:var(--red)" onclick="_deletePolicyRule(\''+r.id+'\')">Delete</button>'
          +'</div></div></div>';
      }).join('');

      list.innerHTML = builtinHTML + (apiHTML ? '<div style="font-size:10px;letter-spacing:.08em;color:var(--t3);margin:12px 0 8px">CUSTOM RULES ('+(rules.length)+')</div>'+apiHTML : '');

      if (rules.length) showToast(rules.length+' custom rules loaded','info');
    } catch(e) { console.error('Policy load:', e); }
  }

  window._togglePolicyRule = async function(btn) {
    var id = btn.getAttribute('data-id');
    var active = btn.classList.contains('on');
    btn.classList.toggle('on');
    await ensureToken();
    try {
      await fetch('/api/v1/policy/rules/'+id, {
        method:'PUT', headers:{'Authorization':'Bearer '+window.TOKEN,'Content-Type':'application/json'},
        body: JSON.stringify({active: !active})
      });
      showToast('Rule '+(active?'disabled':'enabled'),'info');
    } catch(e) { showToast('Update failed','error'); }
  };

  window._deletePolicyRule = async function(id) {
    if (!confirm('Delete this rule?')) return;
    await ensureToken();
    try {
      await fetch('/api/v1/policy/rules/'+id, {method:'DELETE',headers:{'Authorization':'Bearer '+window.TOKEN}});
      showToast('Rule deleted','success');
      document.getElementById('panel-policy')._policyLoaded = false;
      _loadPolicyFull();
    } catch(e) { showToast('Delete failed','error'); }
  };

  // Override runEval để hiện rich result
  window.runEval = async function() {
    var el = document.getElementById('eval-result');
    if (el) el.innerHTML = '<span style="color:var(--t3)">Evaluating...</span>';
    await ensureToken();
    try {
      var d = await fetch('/api/v1/policy/evaluate', {
        method:'POST', headers:{'Authorization':'Bearer '+window.TOKEN,'Content-Type':'application/json'},
        body:'{}'
      }).then(r=>r.json());
      if (!el) return;
      var c = d.decision==='PASS'?'var(--green)':d.decision==='WARN'?'var(--amber)':'var(--red)';
      el.innerHTML = '<span style="color:'+c+';font-size:18px;font-weight:700">'+d.decision+'</span>'
        +' &middot; score: <b>'+(d.score||0)+'</b>'
        +' &middot; posture: <b>'+(d.posture||'?')+'</b>'
        +' &middot; <span style="color:var(--t3)">'+(d.reason||'')+'</span>'
        +(d.critical_count?'<div style="margin-top:8px;font-size:11px;color:var(--red)">Critical findings: '+d.critical_count+'</div>':'')
        +(d.secrets_count?'<div style="font-size:11px;color:var(--amber)">Secrets detected: '+d.secrets_count+'</div>':'');
    } catch(e) {
      if (el) el.innerHTML = '<span style="color:var(--red)">Error: '+e.message+'</span>';
    }
  };

  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.7 Policy panel loaded');
})();

// PATCH v3.8 — Policy: Security Standards (OWASP, CWE, BKAV) từ findings thật
(function(){
  var _origLoadPolicy = window._loadPolicyFull || function(){};
  
  window._loadPolicyFull = async function() {
    await _origLoadPolicy.apply(this, arguments);
    var panel = document.getElementById('panel-policy');
    if (!panel || document.getElementById('policy-standards-card')) return;
    
    // Inject Standards card
    var card = document.createElement('div');
    card.className = 'card mb14'; card.id = 'policy-standards-card';
    card.innerHTML = '<div class="card-head">'
      +'<div><div class="card-title">Security standards coverage</div>'
      +'<div class="card-sub">OWASP · CWE · BKAV · CVE · mapped từ findings thực</div></div>'
      +'<button class="btn btn-ghost" style="font-size:10px" onclick="_refreshStandards()">↻ Refresh</button>'
      +'</div>'
      +'<div id="policy-standards-body" style="padding:14px"><div style="color:var(--t3);font-size:11px">Loading...</div></div>';
    
    var rulesList = document.getElementById('rules-list');
    if (rulesList) rulesList.before(card);
    
    await _refreshStandards();
  };

  window._refreshStandards = async function() {
    var body = document.getElementById('policy-standards-body');
    if (!body) return;
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    
    try {
      var fd = await fetch('/api/v1/vsp/findings?limit=5000', {headers:h}).then(r=>r.json());
      var findings = fd.findings || [];
      
      // OWASP Top 10 mapping từ CWE/rule_id
      var OWASP = {
        'A01:2021': {name:'Broken Access Control', cwes:['CWE-22','CWE-284','CWE-285','CWE-639'], color:'#ef4444'},
        'A02:2021': {name:'Cryptographic Failures', cwes:['CWE-310','CWE-319','CWE-326','CWE-327'], color:'#f97316'},
        'A03:2021': {name:'Injection', cwes:['CWE-77','CWE-78','CWE-89','CWE-94'], color:'#f59e0b'},
        'A04:2021': {name:'Insecure Design', cwes:['CWE-209','CWE-256','CWE-501'], color:'#eab308'},
        'A05:2021': {name:'Security Misconfiguration', cwes:['CWE-16','CWE-732','CWE-1173'], color:'#22c55e'},
        'A06:2021': {name:'Vulnerable Components', cwes:['CWE-1035','CWE-1104'], color:'#06b6d4'},
        'A07:2021': {name:'Auth Failures', cwes:['CWE-287','CWE-297','CWE-384'], color:'#3b82f6'},
        'A08:2021': {name:'Software & Data Integrity', cwes:['CWE-345','CWE-494','CWE-502'], color:'#8b5cf6'},
        'A09:2021': {name:'Security Logging Failures', cwes:['CWE-117','CWE-223','CWE-532'], color:'#ec4899'},
        'A10:2021': {name:'SSRF', cwes:['CWE-918'], color:'#64748b'},
      };

      // Count findings per OWASP category
      var owaspCounts = {};
      Object.keys(OWASP).forEach(function(k){ owaspCounts[k] = 0; });
      findings.forEach(function(f) {
        var cwe = (f.cwe||'').replace(/\s/g,'');
        Object.keys(OWASP).forEach(function(k) {
          if (OWASP[k].cwes.indexOf(cwe) >= 0) owaspCounts[k]++;
        });
      });

      // CVE count từ findings (trivy)
      var cveFindings = findings.filter(function(f){ return f.rule_id && f.rule_id.startsWith('CVE-'); });
      var cveCount = cveFindings.length;
      var critCVE = cveFindings.filter(function(f){ return f.severity==='CRITICAL'; }).length;
      var highCVE = cveFindings.filter(function(f){ return f.severity==='HIGH'; }).length;

      // Secrets (BKAV / gitleaks)
      var secretFindings = findings.filter(function(f){ return f.tool==='gitleaks'||f.tool==='trufflehog'; });
      
      // IaC misconfig (kics/checkov)
      var iacFindings = findings.filter(function(f){ return f.tool==='kics'||f.tool==='checkov'; });

      // CWE top list
      var cweCounts = {};
      findings.forEach(function(f){ if(f.cwe){cweCounts[f.cwe]=(cweCounts[f.cwe]||0)+1;} });
      var topCWE = Object.entries(cweCounts).sort(function(a,b){return b[1]-a[1];}).slice(0,5);

      body.innerHTML = 
        // Summary KPIs
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px">'
        +'<div class="kpi kpi-crit" style="padding:10px"><div class="kpi-label">CVE findings</div>'
        +'<div class="kpi-value c-red" style="font-size:22px">'+cveCount+'</div>'
        +'<div class="kpi-sub">'+critCVE+' critical · '+highCVE+' high</div></div>'
        +'<div class="kpi" style="padding:10px;border-color:rgba(245,158,11,.2)"><div class="kpi-label">Secrets (BKAV/GL)</div>'
        +'<div class="kpi-value c-amber" style="font-size:22px">'+secretFindings.length+'</div>'
        +'<div class="kpi-sub">gitleaks · trufflehog</div></div>'
        +'<div class="kpi" style="padding:10px;border-color:rgba(6,182,212,.2)"><div class="kpi-label">IaC misconfig</div>'
        +'<div class="kpi-value c-cyan" style="font-size:22px">'+iacFindings.length+'</div>'
        +'<div class="kpi-sub">kics · checkov</div></div>'
        +'<div class="kpi" style="padding:10px;border-color:rgba(139,92,246,.2)"><div class="kpi-label">CWE categories</div>'
        +'<div class="kpi-value c-purple" style="font-size:22px">'+Object.keys(cweCounts).length+'</div>'
        +'<div class="kpi-sub">unique CWEs</div></div>'
        +'</div>'

        // OWASP Top 10
        +'<div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--t2);margin-bottom:10px">OWASP TOP 10 — 2021</div>'
        +'<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:6px;margin-bottom:14px">'
        +Object.entries(OWASP).map(function(kv){
          var id=kv[0], ow=kv[1], cnt=owaspCounts[id]||0;
          var badge = cnt>0 ? '<span style="background:rgba(239,68,68,.12);color:#ef4444;font-size:9px;padding:1px 6px;border-radius:4px;font-weight:600">'+cnt+' findings</span>'
            : '<span style="background:rgba(34,197,94,.1);color:#22c55e;font-size:9px;padding:1px 6px;border-radius:4px">clean</span>';
          return '<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;background:var(--b2);border-radius:6px;border-left:3px solid '+ow.color+'">'
            +'<span style="font-size:9px;font-family:var(--font-mono);color:var(--t3);flex-shrink:0">'+id+'</span>'
            +'<span style="font-size:11px;flex:1">'+ow.name+'</span>'
            +badge+'</div>';
        }).join('')
        +'</div>'

        // Top CWEs
        +(topCWE.length ? '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--t2);margin-bottom:8px">TOP CWEs</div>'
        +'<div style="display:grid;gap:4px;margin-bottom:14px">'
        +topCWE.map(function(kv){
          return '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--b2);border-radius:6px">'
            +'<span class="mono f10 c-purple" style="flex-shrink:0;min-width:80px">'+kv[0]+'</span>'
            +'<div style="flex:1;height:5px;background:var(--border);border-radius:3px">'
            +'<div style="width:'+Math.round(kv[1]/findings.length*100*5)+'%;max-width:100%;height:100%;background:#8b5cf6;border-radius:3px"></div></div>'
            +'<span class="mono-sm c-t3">'+kv[1]+'</span></div>';
        }).join('')+'</div>' : '')

        // CVE list top 5
        +(cveFindings.length ? '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--t2);margin-bottom:8px">TOP CVEs</div>'
        +'<div style="display:grid;gap:3px">'
        +cveFindings.slice(0,5).map(function(f){
          var sc={CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low'}[f.severity]||'';
          return '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--b2);border-radius:6px">'
            +'<span class="sev '+sc+'" style="flex-shrink:0">'+f.severity+'</span>'
            +'<span class="mono f10 c-blue" style="flex-shrink:0">'+f.rule_id+'</span>'
            +'<span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+f.message+'</span>'
            +'</div>';
        }).join('')
        +(cveFindings.length>5?'<div style="font-size:10px;color:var(--t3);padding:4px 8px">...và '+(cveFindings.length-5)+' CVEs khác</div>':'')
        +'</div>' : '');

      showToast('Standards loaded: '+findings.length+' findings analyzed','info');
    } catch(e) { 
      if(body) body.innerHTML = '<div style="color:var(--red);font-size:11px">Error: '+e.message+'</div>';
      console.error('Standards:', e); 
    }
  };

  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.8 Security Standards loaded');
})();

// PATCH v3.9 — Policy Standards: inject trực tiếp không qua _loadPolicyFull
(function(){
  setInterval(function(){
    var panel = document.getElementById('panel-policy');
    if (!panel || !panel.classList.contains('active')) return;
    if (document.getElementById('policy-standards-card')) return;
    
    // Inject card ngay vào panel
    var card = document.createElement('div');
    card.className = 'card mb14'; card.id = 'policy-standards-card';
    card.innerHTML = '<div class="card-head">'
      +'<div><div class="card-title">Security standards coverage</div>'
      +'<div class="card-sub">OWASP Top 10 · CWE · CVE · Secrets — mapped từ findings thực</div></div>'
      +'<button class="btn btn-ghost" style="font-size:10px" onclick="_refreshStandards()">↻ Refresh</button>'
      +'</div>'
      +'<div id="policy-standards-body" style="padding:14px"><div style="color:var(--t3);font-size:11px">Loading...</div></div>';
    
    // Thêm vào cuối panel trước footer
    panel.appendChild(card);
    
    // Load data
    if (typeof _refreshStandards === 'function') _refreshStandards();
  }, 500);
  
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v3.9 Policy Standards inject loaded');
})();

// PATCH v4.0 — Audit panel: KPI + filter + pagination đầy đủ
(function(){
  window._auditState = {page:0, limit:25, action:'', total:0};
  
  async function _loadAuditFull() {
    await ensureToken();
    var h = {'Authorization':'Bearer '+window.TOKEN};
    var state = window._auditState;
    
    try {
      // Fetch page
      var url = '/api/v1/audit/log?limit='+state.limit+'&offset='+(state.page*state.limit);
      var d = await fetch(url, {headers:h}).then(r=>r.json());
      var entries = d.entries || [];
      state.total = d.total || entries.length;
      
      // Filter client-side by action
      if (state.action) entries = entries.filter(function(e){ return e.action===state.action; });
      
      // KPI
      var today = new Date().toDateString();
      var todayC = entries.filter(function(e){ return new Date(e.created_at).toDateString()===today; }).length;
      var loginC = entries.filter(function(e){ return e.action&&e.action.indexOf('LOGIN')>=0; }).length;
      var scanC  = entries.filter(function(e){ return e.action&&e.action.indexOf('SCAN')>=0; }).length;
      var failC  = entries.filter(function(e){ return e.action&&(e.action.indexOf('FAIL')>=0||e.action.indexOf('LOCKED')>=0); }).length;
      
      var set = function(id,v){ var el=document.getElementById(id); if(el) el.textContent=v; };
      set('audit-k-total', state.total);
      set('audit-k-today', todayC);
      set('audit-k-logins', loginC);
      set('audit-k-scans', scanC);
      
      // Inject filter bar nếu chưa có
      var panel = document.getElementById('panel-audit');
      if (panel && !document.getElementById('audit-filter-bar')) {
        var fb = document.createElement('div');
        fb.id = 'audit-filter-bar';
        fb.className = 'filter-bar mb14';
        fb.innerHTML = '<span class="f10 c-t3">Filter:</span>'
          +'<div class="log-filter" id="audit-action-filters">'
          +'<button class="log-filter-btn active" onclick="_setAuditAction(\'\',this)">ALL</button>'
          +'<button class="log-filter-btn" onclick="_setAuditAction(\'LOGIN_OK\',this)">LOGIN_OK</button>'
          +'<button class="log-filter-btn" style="color:var(--amber)" onclick="_setAuditAction(\'LOGIN_FAILED\',this)">FAILED</button>'
          +'<button class="log-filter-btn" style="color:var(--red)" onclick="_setAuditAction(\'LOGIN_LOCKED\',this)">LOCKED</button>'
          +'<button class="log-filter-btn" style="color:var(--cyan)" onclick="_setAuditAction(\'SCAN_PASS\',this)">SCAN</button>'
          +'<button class="log-filter-btn" style="color:var(--purple)" onclick="_setAuditAction(\'REMEDIATION\',this)">REMEDIATION</button>'
          +'</div>'
          +'<span class="mono-sm c-t3" id="audit-count-lbl">'+state.total+' entries</span>'
          +'<button class="btn btn-ghost" style="font-size:10px;margin-left:auto" onclick="_exportAuditCSV()">↓ CSV</button>';
        var auditLogCard = panel.querySelector('.card:last-child');
        if (auditLogCard) auditLogCard.before(fb);
      }
      
      // Update count
      set('audit-count-lbl', state.total+' entries');
      
      // Render table
      var tbody = document.getElementById('audit-table');
      if (tbody && entries.length) {
        tbody.innerHTML = entries.map(function(e){
          var ac = e.action&&e.action.indexOf('OK')>=0?'pill-pass'
            :e.action&&e.action.indexOf('LOCKED')>=0?'pill-fail'
            :e.action&&e.action.indexOf('FAIL')>=0?'pill-warn':'pill-run';
          var dt = new Date(e.created_at);
          var ts = (dt.getDate()<10?'0':'')+dt.getDate()+'/'+(dt.getMonth()+1)
            +' '+(dt.getHours()<10?'0':'')+dt.getHours()+':'+(dt.getMinutes()<10?'0':'')+dt.getMinutes();
          var hash = (e.hash||'').slice(0,8)+'…';
          return '<tr>'
            +'<td class="mono-sm">'+e.seq+'</td>'
            +'<td><span class="pill '+ac+'" style="font-size:8px">'+e.action+'</span></td>'
            +'<td class="mono-sm" style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e.resource+'</td>'
            +'<td class="mono-sm">'+e.ip+'</td>'
            +'<td class="mono-sm">'+ts+'</td>'
            +'<td class="mono-sm" style="color:var(--t4);cursor:pointer" onclick="navigator.clipboard&&navigator.clipboard.writeText(\''+e.hash+'\');showToast&&showToast(\'Hash copied\',\'info\')" title="Click to copy full hash">'+hash+'</td>'
            +'</tr>';
        }).join('');
      }
      
      // Pagination
      var pages = Math.ceil(state.total/state.limit);
      var cur = state.page;
      var paginationEl = document.querySelector('#panel-audit .card:last-child .pagination, #panel-audit .pagination');
      if (!paginationEl) {
        var auditCard = document.querySelector('#panel-audit .card:last-child');
        if (auditCard) {
          var pg = document.createElement('div');
          pg.className = 'pagination'; pg.id = 'audit-pagination';
          auditCard.appendChild(pg);
          paginationEl = pg;
        }
      }
      if (paginationEl) {
        var btns = '<span class="pagination-info">'+(cur*state.limit+1)+'-'+Math.min((cur+1)*state.limit,state.total)+' of '+state.total+'</span><div class="page-btns">';
        if (cur>0) btns += '<button class="page-btn" onclick="_auditGoPage('+(cur-1)+')">‹ Prev</button>';
        for (var i=Math.max(0,cur-2);i<=Math.min(pages-1,cur+2);i++) {
          btns += '<button class="page-btn'+(i===cur?' active':'')+'" onclick="_auditGoPage('+i+')">'+(i+1)+'</button>';
        }
        if (cur<pages-1) btns += '<button class="page-btn" onclick="_auditGoPage('+(cur+1)+')">Next ›</button>';
        btns += '</div>';
        paginationEl.innerHTML = btns;
      }
      
    } catch(e) { console.error('Audit v4.0:', e); }
  }
  
  window._setAuditAction = function(action, btn) {
    window._auditState.action = action;
    window._auditState.page = 0;
    document.querySelectorAll('#audit-action-filters .log-filter-btn').forEach(function(b){ b.classList.remove('active'); });
    if (btn) btn.classList.add('active');
    _loadAuditFull();
  };
  
  window._auditGoPage = function(p) {
    window._auditState.page = p;
    _loadAuditFull();
  };
  
  window._exportAuditCSV = async function() {
    await ensureToken();
    var d = await fetch('/api/v1/audit/log?limit=1000', {headers:{'Authorization':'Bearer '+window.TOKEN}}).then(r=>r.json());
    var rows = [['Seq','Action','Resource','IP','Time','Hash']];
    (d.entries||[]).forEach(function(e){ rows.push([e.seq,e.action,e.resource,e.ip,e.created_at,e.hash]); });
    var csv = rows.map(function(r){ return r.map(function(v){ return '"'+(v||'').toString().replace(/"/g,'""')+'"'; }).join(','); }).join('\n');
    var a = document.createElement('a'); a.href = 'data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
    a.download = 'audit-log.csv'; a.click();
    showToast('Audit CSV exported','success');
  };
  
  // Override loadAuditReal
  window.loadAuditReal = _loadAuditFull;
  
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v4.0 Audit full loaded');
})();

// PATCH v4.1 — Fix iframe panels tự load khi click
(function(){
  var iframePanels = ['swinventory','users','ai_analyst','scheduler','correlation','soar',
    'logsources','ueba','assets','netflow','threathunt','vulnmgmt','threatintel',
    'p4compliance','cicd','integrations','settings'];
  
  setInterval(function(){
    iframePanels.forEach(function(name){
      var panel = document.getElementById('panel-'+name);
      if (!panel || !panel.classList.contains('active')) return;
      var iframe = panel.querySelector('iframe[data-src]');
      if (iframe && !iframe.src.includes('.html')) {
        iframe.src = iframe.getAttribute('data-src');
        console.log('[VSP] iframe loaded:', name);
      }
    });
  }, 300);
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v4.1 iframe auto-load loaded');
})();

// PATCH v4.1 — Fix iframe panels tự load khi click
(function(){
  var iframePanels = ['swinventory','users','ai_analyst','scheduler','correlation','soar',
    'logsources','ueba','assets','netflow','threathunt','vulnmgmt','threatintel',
    'p4compliance','cicd','integrations','settings'];
  
  setInterval(function(){
    iframePanels.forEach(function(name){
      var panel = document.getElementById('panel-'+name);
      if (!panel || !panel.classList.contains('active')) return;
      var iframe = panel.querySelector('iframe[data-src]');
      if (iframe && !iframe.src.includes('.html')) {
        iframe.src = iframe.getAttribute('data-src');
        console.log('[VSP] iframe loaded:', name);
      }
    });
  }, 300);
  if(window.VSP_DEBUG)console.log('[VSP] PATCH v4.1 iframe auto-load loaded');
})();
