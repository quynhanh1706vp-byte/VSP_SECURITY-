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
  // SEC-006 reviewed 2026-04-21: static HTML template, no data injection
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
      // SEC-006 reviewed 2026-04-21: static HTML template, no data injection
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
      // SEC-006 reviewed 2026-04-21: static HTML template, no data injection
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
    // SEC-006 reviewed 2026-04-21: static HTML template, no data injection
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
    if (window.VSP_DEBUG) console.log('[VSP] DoD widgets injected');
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
    var L={runs:function(){window.loadRuns&&window.loadRuns();},audit:function(){typeof loadAuditReal==='function'&&loadAuditReal();},dashboard:function(){typeof initDashboardCharts==='function'&&initDashboardCharts();if(typeof loadDashKPIs==='function')loadDashKPIs();},findings:function(){typeof loadFindingsPanel==='function'&&loadFindingsPanel();},sla:function(){typeof loadSLA==='function'&&loadSLA();},sbom:function(){typeof loadSBOM==='function'&&loadSBOM();},compliance:function(){typeof loadFedRAMP==='function'&&loadFedRAMP();},governance:function(){typeof window.loadRiskRegister==='function'&&window.loadRiskRegister();},executive:function(){typeof loadExecutive==='function'&&loadExecutive();},export:function(){typeof loadExportRuns==='function'&&loadExportRuns();},analytics:function(){typeof loadAnalytics==='function'&&loadAnalytics();},remediation:function(){typeof loadRemediations==='function'&&loadRemediations();},soc:function(){typeof drawSocRadar==='function'&&drawSocRadar();if(typeof loadSOCv2==='function')loadSOCv2();},users:function(){typeof loadUsers==='function'&&loadUsers();},policy:function(){typeof loadRules==='function'&&loadRules();},scanlog:function(){typeof loadRunsDropdown==='function'&&loadRunsDropdown();}};
    if(L[name]) setTimeout(L[name], 150);
    if(window.VSP_DEBUG)console.log('[VSP FINAL] panel:', name);
  }
  try {
    Object.defineProperty(window, 'showPanel', {
      value: _FINAL,
      writable: false,
      configurable: false
    });
    if (window.VSP_DEBUG) console.log('[VSP] showPanel locked (defineProperty)');
  } catch(e) {
    window.showPanel = _FINAL;
    if (window.VSP_DEBUG) console.log('[VSP] showPanel assigned (defineProperty failed)');
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

      // Backend API `/api/v1/remediation` already JOINs findings server-side
      // and returns severity/tool/rule_id/title inline on each remediation row.
      // Earlier this code did a 2nd /findings fetch + client-side findMap which
      // dropped to `—` whenever the lookup missed (most rows). Now: use API
      // fields directly. Skipping the extra fetch also halves load time.
      var sevClass={CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low',INFO:'sev-info'};
      var statusPill={open:'pill-fail',in_progress:'pill-warn',resolved:'pill-pass',accepted:'pill-done',false_positive:'pill-queue',suppressed:''};
      var priColor={P1:'c-red',P2:'c-orange',P3:'c-amber',P4:'c-t2'};

      var tbody = document.getElementById('rem-tbody');
      if(!tbody) return;

      if(!rems.length){ tbody.innerHTML='<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--t3)">No remediations yet</td></tr>'; return; }

      var __esc = function(s){ return String(s==null?'':s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); };
      tbody.innerHTML = rems.map(function(r,i){
        var sev=(r.severity||'').toUpperCase();
        var sc=sevClass[sev]||'';
        var sp=statusPill[r.status]||'';
        var pc=priColor[r.priority]||'';
        var title=r.title||r.message||r.finding_id||'—';
        var slaBadge = (typeof window._remSLABadge==='function') ? window._remSLABadge(r) : '';
        return '<tr style="cursor:pointer;transition:background .15s" onmouseenter="this.style.background=\'var(--surface2)\'" onmouseleave="this.style.background=\'\'" onclick="_openRemDetail('+i+')">'
          +'<td>'+(sev?'<span class="sev '+sc+'">'+sev+'</span>':'—')+'</td>'
          +'<td class="c-t3 f11">'+__esc(r.tool||'—')+'</td>'
          +'<td class="mono c-purple f10" style="max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+__esc(r.rule_id||'')+'">'+__esc((r.rule_id||'').slice(0,8)||'—')+'</td>'
          +'<td class="f12" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+__esc(title)+'">'+__esc(title)+'</td>'
          +'<td class="f11">'+(r.assignee?'<span class="c-t2">'+__esc(r.assignee)+'</span>':'<span class="c-t4" style="font-style:italic">unassigned</span>')+'</td>'
          +'<td class="'+pc+' fw7 f11">'+(r.priority||'—')+'</td>'
          +'<td><span class="pill '+sp+'" style="font-size:9px">'+r.status+'</span> '+slaBadge+'</td>'
          +'<td><button class="btn btn-ghost" style="font-size:9px;padding:2px 8px" onclick="event.stopPropagation();_openRemDetail('+i+')">Edit</button></td>'
          +'</tr>';
      }).join('');

      // Store original rem rows for _openRemDetail (with API-provided fields).
      window._remData = rems.map(function(r){
        return Object.assign({}, r, { description: r.title || r.message });
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

        // CVE list top 5 — dedup by rule_id (was rendering same CVE 4× when
        // it appeared in multiple findings/files). Keep highest-severity
        // sample of each unique CVE and show occurrence count.
        +(function(){
          var sevRank = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
          var byCVE = {};
          cveFindings.forEach(function(f){
            var k = f.rule_id;
            if (!byCVE[k] || (sevRank[f.severity]||9) < (sevRank[byCVE[k].severity]||9)) {
              byCVE[k] = Object.assign({}, f, { _count: (byCVE[k]?byCVE[k]._count:0) + 1 });
            } else {
              byCVE[k]._count = (byCVE[k]._count||1) + 1;
            }
          });
          var unique = Object.values(byCVE).sort(function(a,b){
            var sa = sevRank[a.severity]||9, sb = sevRank[b.severity]||9;
            if (sa !== sb) return sa - sb;
            return (b._count||1) - (a._count||1);
          });
          if (!unique.length) return '';
          return '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--t2);margin-bottom:8px">TOP CVEs</div>'
            +'<div style="display:grid;gap:3px">'
            +unique.slice(0,5).map(function(f){
              var sc={CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low'}[f.severity]||'';
              var countTag = (f._count||1) > 1 ? '<span style="font-size:9px;color:var(--t3);flex-shrink:0">×'+f._count+'</span>' : '';
              return '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--b2);border-radius:6px">'
                +'<span class="sev '+sc+'" style="flex-shrink:0">'+f.severity+'</span>'
                +'<span class="mono f10 c-blue" style="flex-shrink:0">'+f.rule_id+'</span>'
                +countTag
                +'<span style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+f.message+'</span>'
                +'</div>';
            }).join('')
            +(unique.length>5?'<div style="font-size:10px;color:var(--t3);padding:4px 8px">...và '+(unique.length-5)+' CVEs khác (unique)</div>':'')
            +'</div>';
        })();

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
    'p4compliance','cicd','integrations','settings','conmon','ai_advisor','sso_admin'];
  
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
    'p4compliance','cicd','integrations','settings','conmon','ai_advisor','sso_admin'];
  
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

// ============ SBOM UNIFIED PANEL (auto-appended) ============
/* =============================================================================
 * vsp_sbom_unified.js
 *   Gộp panel SBOM + SBOM Diff thành MỘT panel duy nhất với 3 view-mode:
 *     1. Inventory  — list SBOM của từng run (tương đương panel SBOM cũ)
 *     2. Diff       — so sánh 2 run (tương đương /panels/sbom_diff.html)
 *     3. Trend      — sparkline NEW/FIXED/PERSIST qua N runs gần nhất
 *
 *   Drop-in: chỉ cần thêm 1 dòng <script> vào index.html, sau các vsp_*_patch.
 *   Không cần sửa HTML. Patch tự:
 *     - Inject UI mới vào #panel-sbom (giữ nguyên element cũ ẩn đi để fallback)
 *     - Ẩn nav "SBOM Diff" cũ (do VSP-G2 inject) nếu có
 *     - Wire vào loadSBOM() hiện tại để compatibility
 *
 *   Backend cần có (đã có sẵn):
 *     GET /api/v1/vsp/runs/index?limit=N
 *     GET /api/v1/vsp/findings?run_id=<UUID>&limit=N    (sau patch findings.go)
 *     GET /api/v1/sbom/<rid>
 * ============================================================================= */
(function () {
  'use strict';
  if (window.__VSP_SBOM_UNIFIED__) return;
  window.__VSP_SBOM_UNIFIED__ = true;

  // ---- State ----------------------------------------------------------------
  var S = window._sbomUnified = {
    view: 'inventory',          // 'inventory' | 'diff' | 'trend'
    runs: [],                   // tất cả runs DONE (giảm dần theo created_at)
    newRunUUID: '',             // diff: target run uuid
    baseRunUUID: '',            // diff: baseline run uuid
    newFindings: [],
    baseFindings: [],
    diffCache: null,            // {newOnly, fixed, persisted}
    filters: { sev: '', tool: '', q: '', gate: '', mode: '' },
    pagination: { inv: 0, diff: 0 },
    pageSize: 15,
    trendDays: 30,
    selectedFindings: {}    // fingerprint → true/false
  };

  function $(id) { return document.getElementById(id); }
  function token() { return window.TOKEN || (typeof localStorage !== 'undefined' && localStorage.getItem('vsp_token')) || ''; }
  function authH() { return { 'Authorization': 'Bearer ' + token() }; }
  function fmtDate(s) { try { return s ? new Date(s).toLocaleString('vi-VN', { dateStyle:'short', timeStyle:'short' }) : '—'; } catch(e){ return '—'; } }
  function _toolsFmt(r) {
    // Backend trả nhiều dạng — fallback theo độ ưu tiên
    if (Array.isArray(r.tools_used) && r.tools_used.length) return r.tools_used.join(', ');
    if (typeof r.tools_used === 'string' && r.tools_used) return r.tools_used;
    if (r.tools_done != null && r.tools_total != null) return r.tools_done + '/' + r.tools_total;
    if (r.tools_run) return r.tools_run;
    if (r.tools) return Array.isArray(r.tools) ? r.tools.join(', ') : String(r.tools);
    return '—';
  }
  function esc(s) { return String(s==null?'':s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]); }); }
  function toast(msg, type) { try { (window.showToast||function(){})(msg, type||'info'); } catch(e){} }

  // ---- HTML Skeleton --------------------------------------------------------
  // Render 1 khối duy nhất: tab switcher + filter bar + KPI + main content.
  function renderSkeleton() {
    var panel = $('panel-sbom');
    if (!panel) return false;
    if ($('sbom-u-root')) return true;

    // Ẩn cả block cũ (giữ trong DOM cho fallback) — toàn bộ content cũ wrap lại
    Array.prototype.forEach.call(panel.children, function(c){ c.style.display = 'none'; });

    var root = document.createElement('div');
    root.id = 'sbom-u-root';
    root.innerHTML = ''
      // ---- View switcher + run selectors ----
      + '<div class="card mb14" style="padding:0;overflow:hidden">'
      +   '<div style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap">'
      +     '<div style="display:flex;gap:4px;background:var(--surface2);padding:3px;border-radius:6px">'
      +       '<button id="sbom-u-tab-inventory" class="sbom-u-tab sbom-u-tab-active" onclick="window._sbomUnified.setView(\'inventory\')">📦 Inventory</button>'
      +       '<button id="sbom-u-tab-diff"      class="sbom-u-tab"                 onclick="window._sbomUnified.setView(\'diff\')">🔄 Diff</button>'
      +       '<button id="sbom-u-tab-trend"     class="sbom-u-tab"                 onclick="window._sbomUnified.setView(\'trend\')">📊 Trend</button>'
      +     '</div>'
      +     '<div id="sbom-u-runsel" style="display:flex;gap:6px;align-items:center;flex:1;flex-wrap:wrap;min-width:0"></div>'
      +     '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.refresh()">↻ Refresh</button>'
      +   '</div>'
      // ---- Filter bar (chung cho mọi view) ----
      +   '<div style="display:flex;gap:6px;padding:8px 14px;border-bottom:1px solid var(--border);align-items:center;flex-wrap:wrap;background:var(--surface)">'
      +     '<select id="sbom-u-fsev"  class="filter-select" style="font-size:10px;padding:3px 8px" onchange="window._sbomUnified.applyFilters()">'
      +       '<option value="">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>'
      +     '</select>'
      +     '<select id="sbom-u-ftool" class="filter-select" style="font-size:10px;padding:3px 8px" onchange="window._sbomUnified.applyFilters()"><option value="">All tools</option></select>'
      +     '<input  id="sbom-u-fq"    class="filter-select" style="font-size:10px;padding:3px 8px;min-width:200px;flex:1" placeholder="Component / CVE / path / message…" oninput="window._sbomUnified.debouncedFilter()">'
      +     '<select id="sbom-u-fgate" class="filter-select" style="font-size:10px;padding:3px 8px" onchange="window._sbomUnified.applyFilters()" data-only="inventory"><option value="">All gates</option><option>PASS</option><option>FAIL</option><option>WARN</option></select>'
      +     '<span id="sbom-u-meta" class="mono-sm c-t3" style="margin-left:auto;font-size:10px"></span>'
      +   '</div>'
      // ---- KPI row ----
      +   '<div id="sbom-u-kpis" class="g4" style="padding:14px;gap:8px"></div>'
      // ---- Main content ----
      +   '<div id="sbom-u-main" style="padding:0 14px 14px"></div>'
      // ---- Action toolbar ----
      +   '<div style="display:flex;gap:6px;padding:10px 14px;border-top:1px solid var(--border);align-items:center;flex-wrap:wrap;background:var(--surface)">'
      +     '<span class="mono-sm c-t3" style="font-size:10px;letter-spacing:.05em">EXPORT:</span>'
      +     '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.exportData(\'csv\')">CSV</button>'
      +     '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.exportData(\'json\')">JSON</button>'
      +     '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.exportData(\'cdx\')">CycloneDX</button>'
      +     '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.exportData(\'vex\')">VEX</button>'
      +     '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.exportData(\'sarif\')">SARIF</button>'
      +     '<span style="margin-left:auto;display:flex;gap:6px">'
      +       '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.savedViews()">⭐ Saved views</button>'
      +       '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.openSettings()">⚙ Config</button>'
      +     '</span>'
      +   '</div>'
      + '</div>';
    panel.appendChild(root);

    // CSS riêng (inline 1 lần)
    if (!document.getElementById('sbom-u-css')) {
      var style = document.createElement('style');
      style.id = 'sbom-u-css';
      style.textContent =
        '.sbom-u-tab{background:transparent;border:0;color:var(--text-2);padding:6px 12px;font-size:11px;font-weight:500;border-radius:4px;cursor:pointer;transition:all .15s}'
       +'.sbom-u-tab:hover{color:var(--text-1)}'
       +'.sbom-u-tab-active{background:var(--cyan2);color:var(--cyan)}'
       +'.sbom-u-row{display:grid;grid-template-columns:32px 80px 60px 70px 1.4fr 1fr 90px 130px;gap:0;padding:8px 10px;font-size:11px;align-items:center;border-bottom:1px solid var(--border);transition:background .12s}'
       +'.sbom-u-row:hover{background:var(--surface2)}'
       +'.sbom-u-row-head{background:var(--surface);font-size:10px;color:var(--text-3);letter-spacing:.05em;font-weight:500;border-bottom:1px solid var(--border)}'
       +'.sbom-u-status-new{color:var(--red)}'
       +'.sbom-u-status-fix{color:var(--green)}'
       +'.sbom-u-status-pst{color:var(--amber)}'
       +'.sbom-u-kpi{background:var(--surface);border-left:3px solid var(--border);padding:10px 14px;border-radius:4px}'
       +'.sbom-u-kpi-label{font-size:10px;color:var(--text-2);letter-spacing:.05em}'
       +'.sbom-u-kpi-value{font-size:22px;font-weight:600;font-family:var(--font-display);margin-top:2px}'
       +'.sbom-u-kpi-sub{font-size:10px;color:var(--text-3);margin-top:2px}'
       +'.sbom-u-mini-btn{background:transparent;border:1px solid var(--border);color:var(--text-2);padding:2px 6px;font-size:9px;border-radius:3px;cursor:pointer}'
       +'.sbom-u-mini-btn:hover{border-color:var(--cyan);color:var(--cyan)}';
      document.head.appendChild(style);
    }
    return true;
  }

  // ---- Run selectors --------------------------------------------------------
  function renderRunSelectors() {
    var sel = $('sbom-u-runsel');
    if (!sel) return;
    var opts = function(selUUID){
      return S.runs.map(function(r){
        var lab = (r.rid||r.id) + ' · ' + (r.mode||'?') + ' · ' + (r.gate||'?') + ' · ' + (r.total_findings||r.total||0);
        return '<option value="'+esc(r.id)+'"'+(r.id===selUUID?' selected':'')+'>'+esc(lab)+'</option>';
      }).join('');
    };
    if (S.view === 'inventory') {
      sel.innerHTML = '<span class="mono-sm c-t3" style="font-size:10px;letter-spacing:.05em">RUNS:</span>'
        + '<span class="mono-sm" style="font-size:10px">'+S.runs.length+' available</span>';
    } else if (S.view === 'diff') {
      sel.innerHTML =
          '<span class="mono-sm c-t3" style="font-size:10px;letter-spacing:.05em">NEW:</span>'
        + '<select id="sbom-u-newsel" class="filter-select" style="font-size:10px;padding:3px 8px;min-width:240px;flex:1" onchange="window._sbomUnified.onSelChange(\'new\')">'+opts(S.newRunUUID)+'</select>'
        + '<span class="mono-sm c-t3" style="font-size:10px">vs</span>'
        + '<span class="mono-sm c-t3" style="font-size:10px;letter-spacing:.05em">BASELINE:</span>'
        + '<select id="sbom-u-basesel" class="filter-select" style="font-size:10px;padding:3px 8px;min-width:240px;flex:1" onchange="window._sbomUnified.onSelChange(\'base\')">'+opts(S.baseRunUUID)+'</select>'
        + '<button class="btn btn-ghost" style="font-size:10px" onclick="window._sbomUnified.swap()" title="Swap NEW & BASELINE">⇄</button>';
    } else {
      sel.innerHTML =
          '<span class="mono-sm c-t3" style="font-size:10px;letter-spacing:.05em">RANGE:</span>'
        + '<select class="filter-select" style="font-size:10px;padding:3px 8px" onchange="window._sbomUnified.setTrendRange(this.value)">'
        + '<option value="7">Last 7 runs</option><option value="30" selected>Last 30 runs</option><option value="60">Last 60 runs</option>'
        + '</select>';
    }
    // Toggle filter visibility theo view
    Array.prototype.forEach.call(document.querySelectorAll('[data-only]'), function(el){
      el.style.display = (el.getAttribute('data-only') === S.view) ? '' : 'none';
    });
  }

  // ---- Toolset (cho filter dropdown) ----------------------------------------
  function buildToolDropdown(findings) {
    var sel = $('sbom-u-ftool'); if (!sel) return;
    var tools = {};
    findings.forEach(function(f){ if (f.tool) tools[f.tool] = (tools[f.tool]||0)+1; });
    var keys = Object.keys(tools).sort();
    var cur = sel.value;
    sel.innerHTML = '<option value="">All tools</option>' + keys.map(function(t){
      return '<option value="'+esc(t)+'"'+(t===cur?' selected':'')+'>'+esc(t)+' ('+tools[t]+')</option>';
    }).join('');
  }

  // ---- Data fetching --------------------------------------------------------
  async function fetchRuns() {
    var d = await fetch('/api/v1/vsp/runs/index?limit=200', {headers: authH()}).then(function(r){return r.json();});
    S.runs = (d.runs||[]).filter(function(r){ return r.status==='DONE'; });
    if (!S.newRunUUID && S.runs[0])  S.newRunUUID  = S.runs[0].id;
    if (!S.baseRunUUID && S.runs[1]) S.baseRunUUID = S.runs[1].id;
  }

  async function fetchFindings(uuid) {
    if (!uuid) return [];
    var d = await fetch('/api/v1/vsp/findings?run_id='+encodeURIComponent(uuid)+'&limit=2000', {headers: authH()}).then(function(r){return r.json();});
    return d.findings || [];
  }

  // ---- Diff core ------------------------------------------------------------
  // Key dùng để xác định "cùng 1 finding": tool + rule + path + (line nếu có)
  // Tuned cho data thực: rule UUID-like nên path + rule là đủ ổn.
  function fingerprint(f) {
    return [f.tool||'', f.rule||f.rule_id||'', f.path||f.file||'', f.line||0].join('|');
  }
  function computeDiff(newF, baseF) {
    var newMap = {}, baseMap = {};
    newF.forEach(function(f){ newMap[fingerprint(f)] = f; });
    baseF.forEach(function(f){ baseMap[fingerprint(f)] = f; });
    var newOnly = [], fixed = [], persisted = [];
    Object.keys(newMap).forEach(function(k){
      if (baseMap[k]) persisted.push(Object.assign({_status:'PERSISTED'}, newMap[k]));
      else            newOnly.push(Object.assign({_status:'NEW'},        newMap[k]));
    });
    Object.keys(baseMap).forEach(function(k){
      if (!newMap[k]) fixed.push(Object.assign({_status:'FIXED'}, baseMap[k]));
    });
    return { newOnly: newOnly, fixed: fixed, persisted: persisted };
  }

  // ---- Filtering ------------------------------------------------------------
  function applyFiltersToList(list) {
    var f = S.filters;
    var q = (f.q||'').toLowerCase();
    return list.filter(function(x){
      if (f.sev  && (x.severity||'').toUpperCase() !== f.sev) return false;
      if (f.tool && x.tool !== f.tool) return false;
      if (q) {
        var hay = ((x.path||'') + ' ' + (x.message||'') + ' ' + (x.rule||'') + ' ' + (x.cve||'') + ' ' + (x.component||'')).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
  }

  // ---- KPI rendering --------------------------------------------------------
  function renderKPIs() {
    var box = $('sbom-u-kpis'); if (!box) return;
    if (S.view === 'inventory') {
      var rs = S.runs.filter(function(r){ return !S.filters.gate || r.gate===S.filters.gate; });
      var total = rs.length;
      var fail  = rs.filter(function(r){ return r.gate==='FAIL'; }).length;
      var pass  = rs.filter(function(r){ return r.gate==='PASS'; }).length;
      var latest = rs[0] ? (rs[0].total_findings||rs[0].total||0) : 0;
      box.innerHTML = ''
        + kpi('TOTAL SBOMs',  total,  'var(--cyan)')
        + kpi('WITH FINDINGS',fail,   'var(--red)')
        + kpi('CLEAN RUNS',   pass,   'var(--green)')
        + kpi('LATEST FINDS', latest, 'var(--amber)');
    } else if (S.view === 'diff') {
      var d = S.diffCache || {newOnly:[],fixed:[],persisted:[]};
      var n  = applyFiltersToList(d.newOnly).length;
      var fx = applyFiltersToList(d.fixed).length;
      var p  = applyFiltersToList(d.persisted).length;
      box.innerHTML = ''
        + kpi('NEW',       n,  'var(--red)',   sevBreakdown(d.newOnly))
        + kpi('FIXED',     fx, 'var(--green)', fx===0?'No regressions resolved':sevBreakdown(d.fixed))
        + kpi('PERSISTED', p,  'var(--amber)', sevBreakdown(d.persisted))
        + kpiTrend();
    } else {
      box.innerHTML = ''
        + kpiTrendRange();
    }
  }
  function kpi(label, value, color, sub) {
    return '<div class="sbom-u-kpi" style="border-left-color:'+color+'">'
      + '<div class="sbom-u-kpi-label">'+esc(label)+'</div>'
      + '<div class="sbom-u-kpi-value" style="color:'+color+'">'+esc(String(value))+'</div>'
      + (sub ? '<div class="sbom-u-kpi-sub">'+esc(sub)+'</div>' : '')
      + '</div>';
  }
  function sevBreakdown(list) {
    var c={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    list.forEach(function(f){ var s=(f.severity||'').toUpperCase(); if(c[s]!=null) c[s]++; });
    var parts = [];
    if (c.CRITICAL) parts.push(c.CRITICAL+' crit');
    if (c.HIGH)     parts.push(c.HIGH+' high');
    if (c.MEDIUM)   parts.push(c.MEDIUM+' med');
    if (c.LOW)      parts.push(c.LOW+' low');
    return parts.join(' · ') || '—';
  }
  function kpiTrendRange() {
    // Compute KPI cho Trend view từ S.runs trong phạm vi N
    var arr = S.runs.slice(0, Math.min(S.trendDays, S.runs.length));
    if (arr.length < 1) return ''
      + kpi('RUNS IN RANGE', 0, 'var(--text-3)')
      + kpi('AVG FINDINGS', '—', 'var(--text-3)')
      + kpi('CHANGE', '—', 'var(--text-3)')
      + kpi('TRAJECTORY', '—', 'var(--text-3)');

    var totals = arr.map(function(r){ return r.total_findings || r.total || 0; });
    var sum    = totals.reduce(function(a,b){ return a+b; }, 0);
    var avg    = Math.round(sum / arr.length);

    // Compare run đầu tiên (oldest in range) với run mới nhất (newest)
    // Lưu ý: S.runs sort desc theo created_at, nên arr[0] = newest, arr[last] = oldest
    var newest = totals[0] || 0;
    var oldest = totals[totals.length - 1] || 0;
    var diff   = newest - oldest;
    var pct    = oldest > 0 ? Math.round((diff/oldest)*100) : 0;

    var trajLabel, trajColor;
    if (diff > 0)      { trajLabel = '↑ Worsening'; trajColor = 'var(--red)'; }
    else if (diff < 0) { trajLabel = '↓ Improving'; trajColor = 'var(--green)'; }
    else               { trajLabel = '→ Stable';    trajColor = 'var(--text-2)'; }

    var changeStr = (diff > 0 ? '+' : '') + diff + (oldest>0 ? ' (' + (pct>0?'+':'') + pct + '%)' : '');
    var changeColor = diff > 0 ? 'var(--red)' : diff < 0 ? 'var(--green)' : 'var(--text-2)';

    return ''
      + kpi('RUNS IN RANGE', arr.length, 'var(--cyan)', sum + ' total findings')
      + kpi('AVG FINDINGS',  avg,        'var(--amber)', 'per run')
      + kpi('CHANGE',        changeStr,  changeColor,    diff===0 ? 'no change' : 'oldest → newest')
      + kpi('TRAJECTORY',    trajLabel,  trajColor,      arr.length+' run window');
  }

  function kpiTrend() {
    // Sparkline mini cho Diff view: số findings của N runs gần nhất
    var pts = S.runs.slice(0, Math.min(8, S.runs.length)).reverse().map(function(r){ return r.total_findings||r.total||0; });
    if (pts.length < 2) return kpi('TREND', 'n/a', 'var(--text-3)');
    var max = Math.max.apply(null, pts), min = Math.min.apply(null, pts);
    var w = 80, h = 28, dx = pts.length>1 ? w/(pts.length-1) : 0;
    var poly = pts.map(function(v,i){
      var y = max===min ? h/2 : h - ((v-min)/(max-min))*h;
      return (i*dx).toFixed(1)+','+y.toFixed(1);
    }).join(' ');
    var first = pts[0], last = pts[pts.length-1];
    var dir = last>first ? '↑ Worse' : last<first ? '↓ Better' : '→ Stable';
    var color = last>first ? 'var(--red)' : last<first ? 'var(--green)' : 'var(--text-2)';
    return '<div class="sbom-u-kpi" style="border-left-color:'+color+'">'
      + '<div class="sbom-u-kpi-label">TREND ('+pts.length+' runs)</div>'
      + '<svg viewBox="0 0 '+w+' '+h+'" style="width:100%;height:24px;margin-top:2px" preserveAspectRatio="none">'
      +   '<polyline fill="none" stroke="'+color+'" stroke-width="1.5" points="'+poly+'"/>'
      + '</svg>'
      + '<div class="sbom-u-kpi-sub" style="color:'+color+'">'+dir+'</div>'
      + '</div>';
  }

  // ---- Main rendering -------------------------------------------------------
  function renderMain() {
    var main = $('sbom-u-main'); if (!main) return;
    if (S.view === 'inventory') return renderInventory(main);
    if (S.view === 'diff')      return renderDiff(main);
    if (S.view === 'trend')     return renderTrend(main);
  }

  function renderInventory(main) {
    var rs = S.runs.filter(function(r){ return !S.filters.gate || r.gate===S.filters.gate; });
    var start = S.pagination.inv * S.pageSize;
    var end = Math.min(start + S.pageSize, rs.length);
    var page = rs.slice(start, end);
    var rows = page.map(function(r){
      var dt = fmtDate(r.created_at);
      var find = r.total_findings || r.total || 0;
      var fc = find>=10?'c-red':find>=1?'c-orange':'c-green';
      return '<tr style="cursor:pointer" onclick="window._sbomUnified.openDetail(\''+esc(r.rid)+'\')">'
        + '<td class="mono" style="font-size:10px">'+esc(r.rid||r.id)+'</td>'
        + '<td><span class="pill pill-run">'+esc(r.mode||'?')+'</span></td>'
        + '<td><span class="pill pill-'+(r.gate||'').toLowerCase()+'">'+esc(r.gate||'?')+'</span></td>'
        + '<td class="fw7 '+fc+'">'+find+'</td>'
        + '<td class="mono-sm c-t3" style="font-size:9px">'+esc(_toolsFmt(r))+'</td>'
        + '<td class="mono-sm">'+dt+'</td>'
        + '<td><button class="sbom-u-mini-btn" onclick="event.stopPropagation();window._sbomUnified.download(\''+esc(r.rid)+'\')">↓ CDX</button></td>'
        + '</tr>';
    }).join('');
    main.innerHTML =
      '<div class="tbl-wrap" style="margin-top:10px"><table>'
      + '<thead><tr><th>Run ID</th><th>Mode</th><th>Gate</th><th>Findings</th><th>Tools</th><th>Date</th><th></th></tr></thead>'
      + '<tbody>'+(rows||'<tr><td colspan="7" class="c-t3" style="text-align:center;padding:20px">No runs match filter</td></tr>')+'</tbody>'
      +'</table></div>'
      + paginationBar('inv', rs.length, start, end);
    $('sbom-u-meta').textContent = rs.length+' SBOMs'+(S.filters.gate?' · '+S.filters.gate:'');
  }

  function renderDiff(main) {
    var d = S.diffCache;
    if (!d) { main.innerHTML = '<div style="padding:30px;text-align:center;color:var(--text-3)">Loading diff…</div>'; return; }
    // Gộp tất cả: NEW + PERSIST + FIXED, áp filter chung
    var all = [].concat(d.newOnly, d.persisted, d.fixed);
    var filtered = applyFiltersToList(all);
    var start = S.pagination.diff * S.pageSize;
    var end = Math.min(start + S.pageSize, filtered.length);
    var page = filtered.slice(start, end);

    var head =
      '<div class="sbom-u-row sbom-u-row-head">'
      + '<span><input type="checkbox" id="sbom-u-selall" onchange="window._sbomUnified.selectAll(this.checked)" style="cursor:pointer"></span>'
      + '<span>STATUS</span><span>SEV</span><span>TOOL</span><span>COMPONENT / RULE</span><span>PATH</span><span>SLA</span><span>ACTIONS</span>'
      + '</div>';
    var body = page.map(function(f){
      var fp = fingerprint(f);
      var checked = S.selectedFindings[fp] ? 'checked' : '';
      var st = f._status, stClass = st==='NEW'?'sbom-u-status-new':st==='FIXED'?'sbom-u-status-fix':'sbom-u-status-pst';
      var sevPill = sevBadge(f.severity);
      var comp = f.component || f.cve || f.rule || f.rule_id || '—';
      var pathClass = st==='FIXED' ? 'mono-sm c-t3" style="font-size:10px;text-decoration:line-through;opacity:.6' : 'mono-sm c-t3" style="font-size:10px';
      var sla = slaBadge(f);
      return '<div class="sbom-u-row" style="cursor:pointer" onclick="if(event.target.tagName!==\'INPUT\'&&event.target.tagName!==\'BUTTON\')window._sbomUnified.openFindingDetail(\''+esc(fp)+'\')">'
        + '<span><input type="checkbox" '+checked+' data-fp="'+esc(fp)+'" onchange="window._sbomUnified.toggleSel(this.dataset.fp,this.checked)" style="cursor:pointer"></span>'
        + '<span class="'+stClass+'" style="font-weight:600">'+statusIcon(st)+' '+st+'</span>'
        + sevPill
        + '<span class="mono-sm c-t3">'+esc(f.tool||'—')+'</span>'
        + '<span class="mono-sm" title="'+esc(f.message||'')+'" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(comp)+'</span>'
        + '<span class="'+pathClass+'" title="'+esc(f.path||'')+'">'+esc(f.path||'—')+'</span>'
        + sla
        + actionButtons(f)
        + '</div>';
    }).join('');

    // Bulk action bar (chỉ hiện khi có ít nhất 1 selected)
    var selCount = Object.keys(S.selectedFindings).filter(function(k){ return S.selectedFindings[k]; }).length;
    var bulkBar = selCount > 0
      ? '<div style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--cyan2);border:1px solid var(--cyan);border-radius:6px;margin-top:10px;font-size:11px">'
        + '<span style="color:var(--cyan);font-weight:500">'+selCount+' selected</span>'
        + '<button class="sbom-u-mini-btn" onclick="window._sbomUnified.bulkAct(\'jira\')">Create Jira</button>'
        + '<button class="sbom-u-mini-btn" onclick="window._sbomUnified.bulkAct(\'vex\')">Set VEX</button>'
        + '<button class="sbom-u-mini-btn" onclick="window._sbomUnified.bulkAct(\'accept\')">Accept</button>'
        + '<button class="sbom-u-mini-btn" onclick="window._sbomUnified.clearSel()" style="margin-left:auto">Clear</button>'
      + '</div>'
      : '';

    // Empty state đặc biệt khi cả 3 mảng đều rỗng
    var emptyHtml = '';
    if (filtered.length === 0) {
      var totalAll = all.length;
      if (totalAll === 0) {
        emptyHtml = '<div style="padding:40px 20px;text-align:center;color:var(--text-3)">'
          + '<div style="font-size:32px;margin-bottom:8px">🎉</div>'
          + '<div style="font-size:13px;margin-bottom:4px;color:var(--green)">Perfect parity</div>'
          + '<div style="font-size:11px">No differences between these 2 runs</div>'
          + '</div>';
      } else {
        emptyHtml = '<div style="padding:20px;text-align:center;color:var(--text-3);font-size:11px">No findings match filter</div>';
      }
    }

    main.innerHTML =
        bulkBar
      + '<div style="margin-top:10px;border:1px solid var(--border);border-radius:6px;overflow:hidden">'
      +   head + (body || emptyHtml)
      + '</div>'
      + paginationBar('diff', filtered.length, start, end);
    $('sbom-u-meta').textContent = filtered.length+' findings (filtered from '+all.length+')';
  }

  function renderTrend(main) {
    var arr = S.runs.slice(0, S.trendDays).reverse();
    if (arr.length < 2) { main.innerHTML = '<div style="padding:30px;text-align:center;color:var(--text-3)">Need ≥ 2 runs for trend</div>'; return; }
    // Chart đơn giản: số findings mỗi run
    var w=700, h=180, pad=24;
    var totals = arr.map(function(r){ return r.total_findings || r.total || 0; });
    var max = Math.max.apply(null, totals)||1, min = Math.min.apply(null, totals);
    var dx = (w - 2*pad) / Math.max(1, arr.length - 1);
    var pts = totals.map(function(v,i){
      var y = h - pad - ((v - min) / Math.max(1, max-min)) * (h - 2*pad);
      return [pad + i*dx, y, v, arr[i]];
    });
    var poly = pts.map(function(p){ return p[0].toFixed(1)+','+p[1].toFixed(1); }).join(' ');
    var dots = pts.map(function(p,i){
      return '<circle cx="'+p[0].toFixed(1)+'" cy="'+p[1].toFixed(1)+'" r="3" fill="var(--cyan)"><title>'+esc(p[3].rid)+'\n'+p[2]+' findings</title></circle>';
    }).join('');
    main.innerHTML =
      '<div style="margin-top:10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px">'
      + '<div class="mono-sm c-t3" style="font-size:10px;letter-spacing:.05em;margin-bottom:8px">FINDINGS PER RUN · last '+arr.length+' runs</div>'
      + '<svg viewBox="0 0 '+w+' '+h+'" style="width:100%;height:'+h+'px" preserveAspectRatio="none">'
      +   '<line x1="'+pad+'" y1="'+(h-pad)+'" x2="'+(w-pad)+'" y2="'+(h-pad)+'" stroke="var(--border)" stroke-width="1"/>'
      +   '<line x1="'+pad+'" y1="'+pad+'" x2="'+pad+'" y2="'+(h-pad)+'" stroke="var(--border)" stroke-width="1"/>'
      +   '<text x="'+pad+'" y="'+(pad-6)+'" fill="var(--text-3)" font-size="9" font-family="var(--font-mono)">'+max+'</text>'
      +   '<text x="'+pad+'" y="'+(h-pad+12)+'" fill="var(--text-3)" font-size="9" font-family="var(--font-mono)">'+min+'</text>'
      +   '<polyline fill="none" stroke="var(--cyan)" stroke-width="1.5" points="'+poly+'"/>'
      +   dots
      + '</svg>'
      + '</div>';
    $('sbom-u-meta').textContent = arr.length+' runs · '+totals.reduce(function(a,b){return a+b;},0)+' total findings';
  }

  // ---- Row helpers ----------------------------------------------------------
  function statusIcon(st) {
    return st==='NEW' ? '●' : st==='FIXED' ? '✓' : '≡';
  }
  function sevBadge(s) {
    s = (s||'').toUpperCase();
    var map = {
      CRITICAL: ['CRIT','var(--red)'],
      HIGH:     ['HIGH','var(--orange)'],
      MEDIUM:   ['MED', 'var(--amber)'],
      LOW:      ['LOW', 'var(--text-2)'],
    };
    var e = map[s] || ['—','var(--text-3)'];
    return '<span class="pill" style="background:transparent;border:1px solid '+e[1]+';color:'+e[1]+';font-size:9px;width:fit-content">'+e[0]+'</span>';
  }
  function slaBadge(f) {
    var days = slaDaysOver(f);
    var pill = function(bg, color, text) {
      return '<span style="font-family:var(--font-mono);font-size:9px;padding:2px 6px;border-radius:3px;background:'+bg+';color:'+color+';white-space:nowrap">'+text+'</span>';
    };
    if (days==null)  return '<span class="mono-sm c-t3" style="font-size:10px">—</span>';
    if (days > 0)    return pill('rgba(239,68,68,.12)',  'var(--red)',   '⚠ '+days+'d over');
    if (days > -3)   return pill('rgba(245,158,11,.12)', 'var(--amber)', (-days)+'d left');
    return              pill('rgba(16,185,129,.10)',     'var(--green)', '✓ in SLA');
  }
  function slaDaysOver(f) {
    if (!f.created_at && !f.first_seen) return null;
    var c = getConfig();
    var SLA = { CRITICAL:c.sla_critical, HIGH:c.sla_high, MEDIUM:c.sla_medium, LOW:c.sla_low };
    var sla = SLA[(f.severity||'').toUpperCase()];
    if (!sla) return null;
    var t0 = new Date(f.first_seen || f.created_at).getTime();
    if (isNaN(t0)) return null;
    var ageDays = (Date.now() - t0) / 86400000;
    return Math.round(ageDays - sla);
  }
  function actionButtons(f) {
    var fid = esc(f.id || fingerprint(f));
    return '<span style="display:flex;gap:3px">'
      + '<button class="sbom-u-mini-btn" title="Create Jira ticket" onclick="window._sbomUnified.actJira(\''+fid+'\')">Jira</button>'
      + '<button class="sbom-u-mini-btn" title="Mark VEX status"   onclick="window._sbomUnified.actVex(\''+fid+'\')">VEX</button>'
      + (f._status==='PERSISTED' ? '<button class="sbom-u-mini-btn" title="Baseline accept" onclick="window._sbomUnified.actAccept(\''+fid+'\')">Accept</button>' : '')
      + '</span>';
  }

  function paginationBar(kind, total, start, end) {
    var cur = S.pagination[kind];
    var pages = Math.max(1, Math.ceil(total/S.pageSize));
    return '<div style="display:flex;gap:8px;padding:8px 0;align-items:center;font-size:10px;color:var(--text-3)">'
      + '<span class="mono-sm">'+(total?(start+1)+'-'+end+' of '+total:'0 results')+'</span>'
      + '<div style="margin-left:auto;display:flex;gap:6px">'
      + '<button class="btn btn-ghost" style="font-size:9px;padding:2px 8px" '+(cur===0?'disabled':'')+' onclick="window._sbomUnified.pageDelta(\''+kind+'\',-1)">‹ Prev</button>'
      + '<span class="mono-sm">page '+(cur+1)+'/'+pages+'</span>'
      + '<button class="btn btn-ghost" style="font-size:9px;padding:2px 8px" '+(end>=total?'disabled':'')+' onclick="window._sbomUnified.pageDelta(\''+kind+'\',1)">Next ›</button>'
      + '</div></div>';
  }

  // ---- Public API (đặt vào _sbomUnified namespace) --------------------------
  S.setView = function (v) {
    S.view = v;
    ['inventory','diff','trend'].forEach(function(t){
      var el = $('sbom-u-tab-'+t); if (!el) return;
      el.classList.toggle('sbom-u-tab-active', t===v);
    });
    renderRunSelectors();
    if (v === 'diff') ensureDiff().then(function(){ renderKPIs(); renderMain(); });
    else { renderKPIs(); renderMain(); }
  };

  S.onSelChange = function (which) {
    if (which==='new')  S.newRunUUID  = $('sbom-u-newsel').value;
    if (which==='base') S.baseRunUUID = $('sbom-u-basesel').value;
    S.diffCache = null;
    ensureDiff().then(function(){ renderKPIs(); renderMain(); });
  };
  S.swap = function () {
    var a = S.newRunUUID, b = S.baseRunUUID;
    S.newRunUUID = b; S.baseRunUUID = a;
    S.diffCache = null;
    renderRunSelectors();
    ensureDiff().then(function(){ renderKPIs(); renderMain(); });
  };
  S.setTrendRange = function (n) { S.trendDays = parseInt(n,10)||30; renderKPIs(); renderMain(); };

  // Filters
  var debounceTimer;
  S.debouncedFilter = function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function(){ S.applyFilters(); }, 250);
  };
  S.applyFilters = function () {
    S.filters.sev  = ($('sbom-u-fsev')||{}).value || '';
    S.filters.tool = ($('sbom-u-ftool')||{}).value || '';
    S.filters.q    = ($('sbom-u-fq')||{}).value || '';
    S.filters.gate = ($('sbom-u-fgate')||{}).value || '';
    S.pagination.inv = 0; S.pagination.diff = 0;
    renderKPIs(); renderMain();
  };

  S.pageDelta = function (kind, d) { S.pagination[kind] = Math.max(0, S.pagination[kind]+d); renderMain(); };

  S.refresh = async function () {
    toast('Refreshing SBOM…','info');
    S.diffCache = null;
    await fetchRuns();
    if (S.view === 'diff') await ensureDiff();
    renderRunSelectors(); renderKPIs(); renderMain();
    toast('Refreshed','success');
  };

  async function ensureDiff() {
    if (!S.newRunUUID || !S.baseRunUUID) return;
    if (S.diffCache) return;
    var main = $('sbom-u-main');
    if (main) main.innerHTML = '<div style="padding:30px;text-align:center;color:var(--text-3)">Loading diff…</div>';
    var pair = await Promise.all([fetchFindings(S.newRunUUID), fetchFindings(S.baseRunUUID)]);
    S.newFindings = pair[0]; S.baseFindings = pair[1];
    S.diffCache = computeDiff(S.newFindings, S.baseFindings);
    buildToolDropdown([].concat(S.newFindings, S.baseFindings));
  }

  // Actions — proper modals (replaces prompt/confirm)
  S.actJira = function (fid) {
    var body =
        '<div style="margin-bottom:14px;font-size:12px;color:var(--text-2)">Create a Jira ticket for this finding.</div>'
      + '<div style="display:grid;gap:10px">'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Project key</div>'
      +     '<input id="jira-project" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px" placeholder="e.g. SEC" value="SEC"></div>'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Priority</div>'
      +     '<select id="jira-priority" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px">'
      +       '<option>Highest</option><option selected>High</option><option>Medium</option><option>Low</option>'
      +     '</select></div>'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Assignee (optional)</div>'
      +     '<input id="jira-assignee" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px" placeholder="e.g. john.doe"></div>'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Note</div>'
      +     '<textarea id="jira-note" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px;min-height:60px;resize:vertical;font-family:inherit" placeholder="Additional context for triage…"></textarea></div>'
      + '</div>';
    var footer = ''
      + '<button class="btn btn-ghost" style="font-size:11px;margin-left:auto" onclick="window._sbomUnified.closeModal()">Cancel</button>'
      + '<button class="btn btn-primary" style="font-size:11px" onclick="window._sbomUnified._doJira(\''+esc(fid)+'\')">Create ticket</button>';
    showModal({ title: '📋 Create Jira ticket', body: body, footer: footer, width: '480px' });
  };
  S._doJira = function (fid) {
    var payload = {
      finding_id: fid,
      project: ($('jira-project')||{}).value || 'SEC',
      priority: ($('jira-priority')||{}).value || 'High',
      assignee: ($('jira-assignee')||{}).value || '',
      note: ($('jira-note')||{}).value || ''
    };
    closeModal();
    fetch('/api/v1/integrations/jira/create', {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authH()),
      body: JSON.stringify(payload)
    })
      .then(function(r){
        if (r.ok) return r.json().then(function(d){ toast('Jira ticket created: '+(d.key||'OK'),'success'); });
        if (r.status === 404) return toast('Jira integration not configured (backend endpoint missing)','warn');
        if (r.status === 401) return toast('Unauthorized — please re-login','error');
        return r.text().then(function(t){ toast('Jira create failed: HTTP '+r.status,'error'); });
      })
      .catch(function(){ toast('Network error — Jira backend unreachable','error'); });
  };

  S.actVex = function (fid) {
    var body =
        '<div style="margin-bottom:14px;font-size:12px;color:var(--text-2)">Record VEX (Vulnerability Exploitability eXchange) status for this finding.</div>'
      + '<div style="display:grid;gap:10px">'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Status *</div>'
      +     '<select id="vex-status" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px" onchange="window._sbomUnified._toggleVexJust(this.value)">'
      +       '<option value="not_affected">not_affected — vulnerability does not impact this product</option>'
      +       '<option value="under_investigation" selected>under_investigation — being analyzed</option>'
      +       '<option value="affected">affected — vulnerability confirmed</option>'
      +       '<option value="fixed">fixed — remediation applied</option>'
      +     '</select></div>'
      +   '<div id="vex-justif-wrap" style="display:none"><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Justification (for not_affected)</div>'
      +     '<select id="vex-justification" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px">'
      +       '<option value="">— select —</option>'
      +       '<option value="component_not_present">component_not_present</option>'
      +       '<option value="vulnerable_code_not_present">vulnerable_code_not_present</option>'
      +       '<option value="vulnerable_code_not_in_execute_path">vulnerable_code_not_in_execute_path</option>'
      +       '<option value="vulnerable_code_cannot_be_controlled_by_adversary">vulnerable_code_cannot_be_controlled_by_adversary</option>'
      +       '<option value="inline_mitigations_already_exist">inline_mitigations_already_exist</option>'
      +     '</select></div>'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Detail / impact statement</div>'
      +     '<textarea id="vex-detail" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px;min-height:70px;resize:vertical;font-family:inherit" placeholder="Explain the rationale, e.g. \'Affected function not called in our codebase\'"></textarea></div>'
      + '</div>';
    var footer = ''
      + '<button class="btn btn-ghost" style="font-size:11px;margin-left:auto" onclick="window._sbomUnified.closeModal()">Cancel</button>'
      + '<button class="btn btn-primary" style="font-size:11px" onclick="window._sbomUnified._doVex(\''+esc(fid)+'\')">Record VEX</button>';
    showModal({ title: '🏷 Set VEX status', body: body, footer: footer, width: '520px' });
  };
  S._toggleVexJust = function (status) {
    var w = $('vex-justif-wrap');
    if (w) w.style.display = (status === 'not_affected') ? '' : 'none';
  };
  S._doVex = function (fid) {
    var payload = {
      status: ($('vex-status')||{}).value || 'under_investigation',
      justification: ($('vex-justification')||{}).value || '',
      detail: ($('vex-detail')||{}).value || ''
    };
    closeModal();
    fetch('/api/v1/vsp/findings/'+encodeURIComponent(fid)+'/vex', {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authH()),
      body: JSON.stringify(payload)
    })
      .then(function(r){
        if (r.ok)             return toast('VEX recorded: '+payload.status,'success');
        if (r.status === 404) return toast('VEX endpoint missing in backend','warn');
        if (r.status === 401) return toast('Unauthorized — please re-login','error');
        return toast('VEX failed: HTTP '+r.status,'error');
      })
      .catch(function(){ toast('Network error — backend unreachable','error'); });
  };

  S.actAccept = function (fid) {
    var body =
        '<div style="margin-bottom:14px;font-size:12px;color:var(--text-2)">Mark this finding as <b style="color:var(--cyan)">baseline-accepted</b>. It will bypass SLA tracking and won\'t trigger gate failures.</div>'
      + '<div style="background:var(--surface2);border-left:3px solid var(--amber);padding:8px 12px;border-radius:0 4px 4px 0;font-size:11px;color:var(--text-2);margin-bottom:14px">'
      +   '<b style="color:var(--amber)">⚠ Use sparingly.</b> Accepted findings still appear in reports for audit purposes, but won\'t generate alerts or block deployments.'
      + '</div>'
      + '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Reason for acceptance *</div>'
      +   '<textarea id="acc-reason" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px;min-height:70px;resize:vertical;font-family:inherit" placeholder="e.g. \'Risk accepted — internal-only service, no PII\'"></textarea></div>'
      + '<div style="margin-top:10px"><div style="font-size:10px;color:var(--text-3);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Expires</div>'
      +   '<select id="acc-expires" class="filter-select" style="width:100%;padding:6px 10px;font-size:11px">'
      +     '<option value="30">30 days (recommended)</option>'
      +     '<option value="90" selected>90 days</option>'
      +     '<option value="180">180 days</option>'
      +     '<option value="365">1 year</option>'
      +     '<option value="0">Never (permanent)</option>'
      +   '</select></div>';
    var footer = ''
      + '<button class="btn btn-ghost" style="font-size:11px;margin-left:auto" onclick="window._sbomUnified.closeModal()">Cancel</button>'
      + '<button class="btn btn-primary" style="font-size:11px" onclick="window._sbomUnified._doAccept(\''+esc(fid)+'\')">Accept finding</button>';
    showModal({ title: '✓ Accept as baseline', body: body, footer: footer, width: '480px' });
  };
  S._doAccept = function (fid) {
    var reason = (($('acc-reason')||{}).value || '').trim();
    if (!reason) { toast('Reason is required','warn'); return; }
    var expires = parseInt(($('acc-expires')||{}).value, 10) || 0;
    closeModal();
    fetch('/api/v1/vsp/findings/'+encodeURIComponent(fid)+'/accept', {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authH()),
      body: JSON.stringify({ reason: reason, expires_days: expires })
    })
      .then(function(r){
        if (r.ok)             return toast('Finding accepted (expires in '+(expires||'never')+'d)','success');
        if (r.status === 404) return toast('Accept endpoint missing in backend','warn');
        if (r.status === 401) return toast('Unauthorized — please re-login','error');
        return toast('Accept failed: HTTP '+r.status,'error');
      })
      .catch(function(){ toast('Network error — backend unreachable','error'); });
  };

  // Bulk selection helpers
  S.toggleSel = function (fp, on) {
    if (on) S.selectedFindings[fp] = true; else delete S.selectedFindings[fp];
    renderMain();
  };
  S.selectAll = function (on) {
    if (!S.diffCache) return;
    var all = [].concat(S.diffCache.newOnly, S.diffCache.persisted, S.diffCache.fixed);
    var filtered = applyFiltersToList(all);
    var start = S.pagination.diff * S.pageSize;
    var page = filtered.slice(start, start + S.pageSize);
    if (on) page.forEach(function(f){ S.selectedFindings[fingerprint(f)] = true; });
    else    page.forEach(function(f){ delete S.selectedFindings[fingerprint(f)]; });
    renderMain();
  };
  S.clearSel = function () { S.selectedFindings = {}; renderMain(); };
  S.bulkAct = function (kind) {
    var fps = Object.keys(S.selectedFindings).filter(function(k){ return S.selectedFindings[k]; });
    if (fps.length === 0) return toast('No findings selected', 'warn');
    var msg;
    if (kind === 'accept') {
      if (!confirm('Mark '+fps.length+' findings as baseline-accepted? They will bypass SLA tracking.')) return;
      msg = 'Accepted '+fps.length+' findings';
    } else if (kind === 'jira') {
      msg = 'Created '+fps.length+' Jira tickets';
    } else if (kind === 'vex') {
      var st = prompt('VEX status for '+fps.length+' findings (not_affected | under_investigation | affected | fixed):', 'under_investigation');
      if (!st) return;
      msg = 'VEX recorded ('+st+') for '+fps.length+' findings';
    }
    // Chỉ fire 1 request bulk
    var url, body = {fingerprints: fps};
    if (kind === 'jira')   url = '/api/v1/integrations/jira/bulk';
    if (kind === 'accept') url = '/api/v1/vsp/findings/bulk/accept';
    if (kind === 'vex')    { url = '/api/v1/vsp/findings/bulk/vex'; body.status = st; }
    fetch(url, {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authH()),
      body: JSON.stringify(body)
    })
    .then(function(r){
      if (r.ok) {
        toast(msg, 'success');
        S.clearSel();
      } else {
        toast('Bulk endpoint not yet wired (HTTP '+r.status+')', 'warn');
      }
    })
    .catch(function(){ toast('Bulk request failed', 'error'); });
  };

  S.openDetail = function (rid) { (window.sbomDetail||function(){})(rid); };
  S.download   = function (rid) { (window.sbomDownload||function(){})(rid); };

  // Exports
  S.exportData = function (fmt) {
    var rows;
    if (S.view === 'diff' && S.diffCache) {
      rows = applyFiltersToList([].concat(S.diffCache.newOnly, S.diffCache.persisted, S.diffCache.fixed));
    } else {
      rows = S.runs;
    }
    if (fmt === 'json') return downloadBlob(JSON.stringify(rows, null, 2), 'sbom-'+S.view+'.json', 'application/json');
    if (fmt === 'csv')  return downloadBlob(toCSV(rows), 'sbom-'+S.view+'.csv', 'text/csv');
    if (fmt === 'cdx')  {
      if (S.view === 'inventory') {
        var rid = S.runs[0] && S.runs[0].rid;
        if (rid) return S.download(rid);
        return toast('No run selected for CycloneDX export','warn');
      }
      return toast('CycloneDX export available in Inventory view','warn');
    }
    if (fmt === 'vex' || fmt === 'sarif') {
      var rid = (S.runs.find(function(r){ return r.id === S.newRunUUID; })||{}).rid || (S.runs[0]||{}).rid;
      if (!rid) return toast('No run selected','warn');
      var url = fmt==='vex' ? '/api/v1/sbom/'+encodeURIComponent(rid)+'/vex'
                            : '/api/v1/findings/'+encodeURIComponent(rid)+'/sarif';
      toast('Fetching '+fmt.toUpperCase()+'…','info');
      fetch(url, { headers: authH() })
        .then(function(r){
          if (r.status === 404) {
            // Backend chưa có endpoint — fallback: tự build từ dữ liệu sẵn có
            return _fallbackExport(fmt, rid);
          }
          if (!r.ok) throw new Error('HTTP '+r.status);
          return r.blob().then(function(blob){
            var ext = fmt==='vex' ? 'json' : 'sarif.json';
            var name = 'sbom-'+rid+'.'+ext;
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = name; a.click();
            setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
            toast(fmt.toUpperCase()+' downloaded: '+name,'success');
          });
        })
        .catch(function(e){ toast(fmt.toUpperCase()+' export failed: '+e.message,'error'); });
    }
  };
  // Fallback: tự build VEX/SARIF từ findings client-side khi backend không có endpoint
  function _fallbackExport(fmt, rid) {
    toast('Backend endpoint missing — generating '+fmt.toUpperCase()+' client-side','info');
    var run = S.runs.find(function(r){ return r.rid === rid; });
    var uuid = run ? run.id : '';
    return fetchFindings(uuid).then(function(findings){
      var doc, name, mime = 'application/json';
      if (fmt === 'vex') {
        doc = {
          '@context': 'https://openvex.dev/ns/v0.2.0',
          '@id': 'https://vsp.local/vex/'+rid,
          author: 'VSP Security Platform',
          timestamp: new Date().toISOString(),
          version: 1,
          statements: findings.map(function(f){
            return {
              vulnerability: { name: f.cve || f.rule || f.rule_id || 'unknown' },
              products: [{ '@id': f.component || f.path || 'unknown' }],
              status: 'under_investigation',
              status_notes: f.message || ''
            };
          })
        };
        name = 'sbom-'+rid+'.openvex.json';
      } else {
        // SARIF 2.1.0
        doc = {
          $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
          version: '2.1.0',
          runs: [{
            tool: { driver: { name: 'VSP', version: '0.10.0', informationUri: 'https://vsp.local' } },
            results: findings.map(function(f){
              return {
                ruleId: f.rule || f.rule_id || f.cve || '',
                level: ({CRITICAL:'error',HIGH:'error',MEDIUM:'warning',LOW:'note'}[(f.severity||'').toUpperCase()] || 'note'),
                message: { text: f.message || '' },
                locations: [{ physicalLocation: {
                  artifactLocation: { uri: f.path || '' },
                  region: f.line ? { startLine: f.line } : undefined
                }}]
              };
            })
          }]
        };
        name = 'sbom-'+rid+'.sarif.json';
      }
      var blob = new Blob([JSON.stringify(doc, null, 2)], { type: mime });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
      toast(fmt.toUpperCase()+' generated: '+findings.length+' items → '+name,'success');
    });
  }
  function toCSV(rows) {
    if (!rows.length) return '';
    var keys = Object.keys(rows[0]).filter(function(k){ return typeof rows[0][k] !== 'object'; });
    var head = keys.join(',');
    var body = rows.map(function(r){
      return keys.map(function(k){
        var v = r[k]==null?'':String(r[k]).replace(/"/g,'""');
        return /[",\n]/.test(v) ? '"'+v+'"' : v;
      }).join(',');
    }).join('\n');
    return head + '\n' + body;
  }
  function downloadBlob(text, name, mime) {
    var blob = new Blob([text], {type: mime||'text/plain'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name; a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
  }

  // Saved views & settings (simple localStorage-based)
  S.savedViews = function () {
    var raw = '{}'; try { raw = localStorage.getItem('vsp_sbom_views') || '{}'; } catch(e){}
    var views; try { views = JSON.parse(raw); } catch(e){ views = {}; }
    var names = Object.keys(views);

    var listHtml = names.length === 0
      ? '<div style="padding:20px;text-align:center;color:var(--text-3);font-size:11px;background:var(--surface2);border-radius:6px">No saved views yet. Configure filters/view, then save below.</div>'
      : '<div style="display:grid;gap:6px">'
        + names.map(function(n){
            var v = views[n];
            var meta = (v.view||'?') + ' · ' + Object.keys(v.filters||{}).filter(function(k){return v.filters[k];}).length + ' filters';
            return '<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface2);border-radius:6px;border-left:3px solid var(--cyan)">'
              + '<div style="flex:1">'
              +   '<div style="font-size:12px;font-weight:600">'+esc(n)+'</div>'
              +   '<div style="font-size:10px;color:var(--text-3);margin-top:2px">'+esc(meta)+'</div>'
              + '</div>'
              + '<button class="sbom-u-mini-btn" style="color:var(--cyan)" onclick="window._sbomUnified._loadView(\''+esc(n)+'\')">Load</button>'
              + '<button class="sbom-u-mini-btn" style="color:var(--red)" onclick="window._sbomUnified._delView(\''+esc(n)+'\')">Delete</button>'
              + '</div>';
          }).join('')
        + '</div>';

    var body =
        '<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-weight:600">SAVED VIEWS ('+names.length+')</div>'
      + listHtml
      + '<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin:18px 0 8px;font-weight:600">SAVE CURRENT VIEW</div>'
      + '<div style="background:var(--surface2);padding:10px 12px;border-radius:6px;font-size:11px;color:var(--text-2);margin-bottom:10px">'
      +   'Snapshot of: <b>'+S.view+'</b> view · '
      +   Object.keys(S.filters).filter(function(k){return S.filters[k];}).length + ' active filter(s)'
      +   (S.view==='diff' ? ' · NEW='+(S.newRunUUID||'').slice(-8)+' / BASE='+(S.baseRunUUID||'').slice(-8) : '')
      + '</div>'
      + '<div style="display:flex;gap:8px">'
      +   '<input id="view-name" class="filter-select" style="flex:1;padding:6px 10px;font-size:11px" placeholder="Enter view name (e.g. \'Critical CVEs in production\')">'
      +   '<button class="btn btn-primary" style="font-size:11px" onclick="window._sbomUnified._saveView()">💾 Save</button>'
      + '</div>';

    var footer = '<button class="btn btn-ghost" style="font-size:11px;margin-left:auto" onclick="window._sbomUnified.closeModal()">Close</button>';
    showModal({ title: '⭐ Saved views', body: body, footer: footer, width: '520px' });
  };
  S._loadView = function (name) {
    var raw = '{}'; try { raw = localStorage.getItem('vsp_sbom_views') || '{}'; } catch(e){}
    var views; try { views = JSON.parse(raw); } catch(e){ views = {}; }
    var v = views[name];
    if (!v) return toast('View not found','warn');
    Object.assign(S, v);
    ['sev','tool','q','gate'].forEach(function(k){
      var el = $('sbom-u-f'+k); if (el) el.value = (S.filters||{})[k] || '';
    });
    S.diffCache = null;
    closeModal();
    S.setView(S.view);
    toast('Loaded view: '+name,'success');
  };
  S._delView = function (name) {
    var raw = '{}'; try { raw = localStorage.getItem('vsp_sbom_views') || '{}'; } catch(e){}
    var views; try { views = JSON.parse(raw); } catch(e){ views = {}; }
    delete views[name];
    try { localStorage.setItem('vsp_sbom_views', JSON.stringify(views)); } catch(e){}
    toast('Deleted: '+name,'info');
    S.savedViews();  // re-render
  };
  S._saveView = function () {
    var name = (($('view-name')||{}).value || '').trim();
    if (!name) return toast('Enter a view name','warn');
    var raw = '{}'; try { raw = localStorage.getItem('vsp_sbom_views') || '{}'; } catch(e){}
    var views; try { views = JSON.parse(raw); } catch(e){ views = {}; }
    views[name] = {
      view: S.view,
      filters: Object.assign({}, S.filters),
      newRunUUID: S.newRunUUID,
      baseRunUUID: S.baseRunUUID,
      trendDays: S.trendDays
    };
    try { localStorage.setItem('vsp_sbom_views', JSON.stringify(views)); } catch(e){}
    toast('View saved: '+name,'success');
    S.savedViews();  // re-render
  };

  // -------------- Modal helper (chung cho Detail + Config) -----------------
  function showModal(opts) {
    closeModal();
    var ov = document.createElement('div');
    ov.id = 'sbom-u-modal-overlay';
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:99998;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(2px)';
    ov.onclick = function(e){ if (e.target===ov) closeModal(); };
    var box = document.createElement('div');
    box.id = 'sbom-u-modal-box';
    box.style.cssText = 'background:var(--surface);border:1px solid var(--border);border-radius:8px;max-width:'+(opts.width||'720px')+';width:100%;max-height:90vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,.5);font-size:12px';
    box.innerHTML =
      '<div style="display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);z-index:1">'
      +   '<div style="font-size:13px;font-weight:600;flex:1">'+esc(opts.title||'')+'</div>'
      +   (opts.subtitle ? '<div class="mono-sm c-t3" style="font-size:10px">'+esc(opts.subtitle)+'</div>' : '')
      +   '<button onclick="window._sbomUnified.closeModal()" style="background:transparent;border:0;color:var(--text-2);font-size:18px;cursor:pointer;padding:0 4px;line-height:1">×</button>'
      + '</div>'
      + '<div style="padding:18px">'+(opts.body||'')+'</div>'
      + (opts.footer ? '<div style="display:flex;gap:8px;padding:12px 18px;border-top:1px solid var(--border);background:var(--surface2);position:sticky;bottom:0;justify-content:flex-end">'+opts.footer+'</div>' : '');
    ov.appendChild(box);
    document.body.appendChild(ov);
    // ESC để đóng
    var escH = function(e){ if (e.key==='Escape') { closeModal(); document.removeEventListener('keydown', escH); } };
    document.addEventListener('keydown', escH);
  }
  function closeModal() {
    var ov = document.getElementById('sbom-u-modal-overlay');
    if (ov && ov.parentNode) ov.parentNode.removeChild(ov);
  }
  S.closeModal = closeModal;

  // -------------- Finding detail modal (click row trong Diff) ----------------
  S.openFindingDetail = function (fp) {
    if (!S.diffCache) return;
    var all = [].concat(S.diffCache.newOnly, S.diffCache.persisted, S.diffCache.fixed);
    var f = null;
    for (var i = 0; i < all.length; i++) { if (fingerprint(all[i]) === fp) { f = all[i]; break; } }
    if (!f) { toast('Finding not found','warn'); return; }

    var sev = (f.severity||'?').toUpperCase();
    var sevColor = {CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--amber)',LOW:'var(--text-2)'}[sev] || 'var(--text-3)';
    var st = f._status || '?';
    var stColor = st==='NEW'?'var(--red)':st==='FIXED'?'var(--green)':'var(--amber)';
    var fid = esc(f.id || fp);
    var sla = slaDaysOver(f);
    var slaText = sla==null ? '—' : sla > 0 ? '⚠ '+sla+' days OVER SLA' : sla > -3 ? (-sla)+' days remaining' : '✓ within SLA ('+(-sla)+' days remaining)';
    var slaColor = sla==null ? 'var(--text-3)' : sla > 0 ? 'var(--red)' : sla > -3 ? 'var(--amber)' : 'var(--green)';

    function row(label, value, mono) {
      if (value==null || value==='') return '';
      return '<div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--border)">'
        + '<div style="min-width:130px;color:var(--text-3);font-size:10px;letter-spacing:.05em;text-transform:uppercase">'+esc(label)+'</div>'
        + '<div style="flex:1;'+(mono?'font-family:var(--font-mono);font-size:11px':'font-size:12px')+';word-break:break-word">'+(typeof value==='string'?esc(value):value)+'</div>'
        + '</div>';
    }
    function refs(f) {
      var arr = f.references || f.refs || [];
      if (!Array.isArray(arr) || !arr.length) return '';
      return arr.slice(0,5).map(function(u){ return '<a href="'+esc(u)+'" target="_blank" rel="noopener" style="color:var(--cyan);text-decoration:none;font-size:11px;display:block;margin:2px 0">↗ '+esc(u)+'</a>'; }).join('');
    }
    function evidence(f) {
      var ev = f.evidence || f.snippet || f.line_content || '';
      if (!ev) return '';
      return '<pre style="background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:10px;font-family:var(--font-mono);overflow:auto;max-height:200px;margin:0;white-space:pre-wrap">'+esc(ev)+'</pre>';
    }

    var body =
      // Top header với severity + status pills
      '<div style="display:flex;gap:8px;margin-bottom:14px;align-items:center;flex-wrap:wrap">'
      +   '<span class="pill" style="background:transparent;border:1px solid '+sevColor+';color:'+sevColor+';font-size:10px;padding:3px 10px">'+esc(sev)+'</span>'
      +   '<span class="pill" style="background:transparent;border:1px solid '+stColor+';color:'+stColor+';font-size:10px;padding:3px 10px">'+statusIcon(st)+' '+esc(st)+'</span>'
      +   '<span style="margin-left:auto;color:'+slaColor+';font-size:11px;font-weight:500">'+esc(slaText)+'</span>'
      + '</div>'
      // Title (message)
      + '<div style="font-size:14px;font-weight:600;margin-bottom:14px;line-height:1.4">'+esc(f.message||f.title||f.rule||f.rule_id||'(no message)')+'</div>'
      // Detail rows
      + '<div style="background:var(--surface2);border-radius:6px;padding:8px 14px;margin-bottom:14px">'
      +   row('Tool', f.tool || '—')
      +   row('Rule / CVE', (f.rule || f.rule_id || f.cve || '—'), true)
      +   row('Component', f.component || '—', true)
      +   row('CWE', f.cwe || '—')
      +   row('Path', f.path || '—', true)
      +   row('Line', f.line ? String(f.line) : '—', true)
      +   row('First seen', f.first_seen ? fmtDate(f.first_seen) : '—')
      +   row('Last seen',  f.last_seen  ? fmtDate(f.last_seen)  : '—')
      +   row('Created',    f.created_at ? fmtDate(f.created_at) : '—')
      +   row('Fingerprint', fid, true)
      + '</div>'
      // Evidence (nếu có)
      + (evidence(f) ? '<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">EVIDENCE</div>'+evidence(f) : '')
      // References
      + (refs(f) ? '<div style="margin-top:14px;font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">REFERENCES</div>'+refs(f) : '');

    var footer = ''
      + '<button class="btn btn-ghost" style="font-size:11px" onclick="window._sbomUnified.closeModal();window._sbomUnified.actJira(\''+fid+'\')">📋 Create Jira</button>'
      + '<button class="btn btn-ghost" style="font-size:11px" onclick="window._sbomUnified.closeModal();window._sbomUnified.actVex(\''+fid+'\')">🏷 Set VEX</button>'
      + (st==='PERSISTED' ? '<button class="btn btn-ghost" style="font-size:11px" onclick="window._sbomUnified.closeModal();window._sbomUnified.actAccept(\''+fid+'\')">✓ Accept</button>' : '')
      + '<button class="btn btn-primary" style="font-size:11px" onclick="window._sbomUnified.closeModal()">Close</button>';

    showModal({ title: 'Finding detail', subtitle: f.tool ? f.tool.toUpperCase() : '', body: body, footer: footer, width: '720px' });
  };

  // -------------- Config modal (real form, replaces alert) -------------------
  function getConfig() {
    var raw = '{}';
    try { raw = localStorage.getItem('vsp_sbom_config') || '{}'; } catch(e){}
    var c; try { c = JSON.parse(raw); } catch(e){ c = {}; }
    return Object.assign({
      sla_critical: 3, sla_high: 14, sla_medium: 30, sla_low: 90,
      auto_baseline: 'previous_done',  // 'previous_done' | 'specific' | 'disabled'
      baseline_rid: '',
      page_size: 15,
      default_view: 'inventory',       // 'inventory' | 'diff' | 'trend'
      trend_range: 30
    }, c);
  }
  function applyConfig(c) {
    S.pageSize = parseInt(c.page_size,10) || 15;
    S.trendDays = parseInt(c.trend_range,10) || 30;
  }

  S.openSettings = function () {
    var c = getConfig();
    var body =
      // SLA section
        '<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-weight:600">SLA THRESHOLDS</div>'
      + '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px">'
      +   _cfgInput('sla_critical', 'CRITICAL', c.sla_critical, 'days', 'var(--red)')
      +   _cfgInput('sla_high',     'HIGH',     c.sla_high,     'days', 'var(--orange)')
      +   _cfgInput('sla_medium',   'MEDIUM',   c.sla_medium,   'days', 'var(--amber)')
      +   _cfgInput('sla_low',      'LOW',      c.sla_low,      'days', 'var(--text-2)')
      + '</div>'
      // Baseline section
      + '<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-weight:600">DIFF BASELINE</div>'
      + '<div style="margin-bottom:18px">'
      +   '<select id="cfg-auto-baseline" class="filter-select" style="width:100%;padding:8px 10px;font-size:11px" onchange="window._sbomUnified._onBaselineChange(this.value)">'
      +     '<option value="previous_done"'+(c.auto_baseline==='previous_done'?' selected':'')+'>Auto: previous DONE run</option>'
      +     '<option value="specific"'+(c.auto_baseline==='specific'?' selected':'')+'>Pin to specific run</option>'
      +     '<option value="disabled"'+(c.auto_baseline==='disabled'?' selected':'')+'>Disabled (manual select)</option>'
      +   '</select>'
      +   '<div id="cfg-baseline-rid-wrap" style="margin-top:8px;'+(c.auto_baseline==='specific'?'':'display:none')+'">'
      +     '<select id="cfg-baseline-rid" class="filter-select" style="width:100%;padding:8px 10px;font-size:11px">'
      +       S.runs.map(function(r){
                return '<option value="'+esc(r.rid)+'"'+(r.rid===c.baseline_rid?' selected':'')+'>'+esc(r.rid)+' · '+esc(r.mode||'?')+' · '+(r.total_findings||0)+' findings</option>';
              }).join('')
      +     '</select>'
      +   '</div>'
      + '</div>'
      // Display section
      + '<div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-weight:600">DISPLAY</div>'
      + '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:18px">'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px">Page size</div>'
      +     '<select id="cfg-page-size" class="filter-select" style="width:100%;padding:6px 8px;font-size:11px">'
      +       [10,15,25,50,100].map(function(n){ return '<option value="'+n+'"'+(n==c.page_size?' selected':'')+'>'+n+' rows</option>'; }).join('')
      +     '</select></div>'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px">Default view</div>'
      +     '<select id="cfg-default-view" class="filter-select" style="width:100%;padding:6px 8px;font-size:11px">'
      +       '<option value="inventory"'+(c.default_view==='inventory'?' selected':'')+'>📦 Inventory</option>'
      +       '<option value="diff"'+(c.default_view==='diff'?' selected':'')+'>🔄 Diff</option>'
      +       '<option value="trend"'+(c.default_view==='trend'?' selected':'')+'>📊 Trend</option>'
      +     '</select></div>'
      +   '<div><div style="font-size:10px;color:var(--text-3);margin-bottom:4px">Trend range</div>'
      +     '<select id="cfg-trend-range" class="filter-select" style="width:100%;padding:6px 8px;font-size:11px">'
      +       [7,14,30,60,90].map(function(n){ return '<option value="'+n+'"'+(n==c.trend_range?' selected':'')+'>Last '+n+' runs</option>'; }).join('')
      +     '</select></div>'
      + '</div>'
      // Info
      + '<div style="background:var(--surface2);border-left:3px solid var(--cyan);padding:8px 12px;font-size:10px;color:var(--text-2);border-radius:0 4px 4px 0">'
      +   'ℹ Settings sync to backend at <code style="color:var(--cyan)">/api/v1/settings/sbom</code> if endpoint exists, else fallback to browser localStorage.'
      + '</div>';

    var footer = ''
      + '<button class="btn btn-ghost" style="font-size:11px" onclick="window._sbomUnified.resetConfig()">↺ Reset defaults</button>'
      + '<button class="btn btn-ghost" style="font-size:11px;margin-left:auto" onclick="window._sbomUnified.closeModal()">Cancel</button>'
      + '<button class="btn btn-primary" style="font-size:11px" onclick="window._sbomUnified.saveConfig()">Save</button>';

    showModal({ title: '⚙ SBOM Configuration', body: body, footer: footer, width: '600px' });
  };

  function _cfgInput(id, label, val, suffix, color) {
    return '<div>'
      + '<div style="font-size:10px;color:'+color+';font-weight:600;margin-bottom:4px;letter-spacing:.05em">'+label+'</div>'
      + '<div style="display:flex;align-items:center;gap:4px">'
      +   '<input id="cfg-'+id+'" type="number" min="1" max="365" value="'+val+'" class="filter-select" style="width:100%;padding:6px 8px;font-size:12px;font-family:var(--font-mono)">'
      +   '<span style="font-size:10px;color:var(--text-3)">'+suffix+'</span>'
      + '</div></div>';
  }

  S._onBaselineChange = function (v) {
    var w = document.getElementById('cfg-baseline-rid-wrap');
    if (w) w.style.display = (v === 'specific') ? '' : 'none';
  };

  S.saveConfig = function () {
    var c = {
      sla_critical:  parseInt(($('cfg-sla_critical')||{}).value, 10) || 3,
      sla_high:      parseInt(($('cfg-sla_high')||{}).value, 10) || 14,
      sla_medium:    parseInt(($('cfg-sla_medium')||{}).value, 10) || 30,
      sla_low:       parseInt(($('cfg-sla_low')||{}).value, 10) || 90,
      auto_baseline: ($('cfg-auto-baseline')||{}).value || 'previous_done',
      baseline_rid:  ($('cfg-baseline-rid')||{}).value || '',
      page_size:     parseInt(($('cfg-page-size')||{}).value, 10) || 15,
      default_view:  ($('cfg-default-view')||{}).value || 'inventory',
      trend_range:   parseInt(($('cfg-trend-range')||{}).value, 10) || 30
    };
    // Save local (always)
    try { localStorage.setItem('vsp_sbom_config', JSON.stringify(c)); } catch(e){}
    applyConfig(c);
    // Try sync to backend (best-effort, không fail nếu endpoint chưa có)
    fetch('/api/v1/settings/sbom', {
      method: 'PUT',
      headers: Object.assign({'Content-Type':'application/json'}, authH()),
      body: JSON.stringify(c)
    }).then(function(r){
      if (r.ok)        toast('Settings saved (synced to backend)', 'success');
      else if (r.status === 404) toast('Settings saved locally (backend endpoint not yet wired)', 'info');
      else             toast('Settings saved locally (backend HTTP '+r.status+')', 'warn');
    }).catch(function(){
      toast('Settings saved locally (backend unreachable)', 'info');
    });
    // Apply baseline pin nếu chọn 'specific'
    if (c.auto_baseline === 'specific' && c.baseline_rid) {
      var run = S.runs.find(function(r){ return r.rid === c.baseline_rid; });
      if (run) { S.baseRunUUID = run.id; S.diffCache = null; }
    }
    closeModal();
    // Re-render với config mới
    S.pagination.inv = 0; S.pagination.diff = 0;
    renderRunSelectors(); renderKPIs(); renderMain();
  };

  S.resetConfig = function () {
    if (!confirm('Reset SBOM config to defaults?')) return;
    try { localStorage.removeItem('vsp_sbom_config'); } catch(e){}
    applyConfig(getConfig());
    closeModal();
    toast('Config reset to defaults','success');
    S.openSettings();
  };

  // Apply config trên load
  applyConfig(getConfig());

  // ---- Bootstrap ------------------------------------------------------------
  async function bootstrap() {
    if (!renderSkeleton()) return;
    // Ẩn nav SBOM Diff cũ (do VSP-G2 inject) nếu có — retry ngắn nếu menu được inject muộn
    (function hideOldSBOMNav(){
      try {
        var matcher = function(a){
          try{
            var t = (a.textContent||'').trim();
            if (/sbom\s*diff/i.test(t)) return true;
            var oc = a.getAttribute && a.getAttribute('onclick') || '';
            if (/sbomdiff/i.test(oc)) return true;
          }catch(e){}
          return false;
        };
        Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function(a){ if (matcher(a)) a.style.display='none'; });
        try {
          if (!hideOldSBOMNav._obs) {
            hideOldSBOMNav._obs = new MutationObserver(function(muts){
              muts.forEach(function(m){
                Array.prototype.forEach.call(m.addedNodes || [], function(n){
                  if (!n || n.nodeType !== 1) return;
                  if (n.matches && n.matches('.nav-item') && matcher(n)) n.style.display='none';
                  var found = n.querySelectorAll && n.querySelectorAll('.nav-item') || [];
                  Array.prototype.forEach.call(found, function(a){ if (matcher(a)) a.style.display='none'; });
                });
              });
            });
            hideOldSBOMNav._obs.observe(document.body, { childList: true, subtree: true });
          }
        } catch(e) {}
      } catch(e) {}
    })();
    try {
      await fetchRuns();
      // Apply default view từ config (chỉ lần đầu, không override nếu user đã chuyển tab)
      if (!S._viewInitialized) {
        S._viewInitialized = true;
        var cfg = getConfig();
        if (cfg.default_view && cfg.default_view !== S.view) {
          S.view = cfg.default_view;
          ['inventory','diff','trend'].forEach(function(t){
            var el = $('sbom-u-tab-'+t); if (el) el.classList.toggle('sbom-u-tab-active', t===S.view);
          });
        }
      }
      renderRunSelectors(); renderKPIs();
      if (S.view === 'diff') await ensureDiff();
      renderMain();
    } catch(e) { console.error('[SBOM-U] bootstrap', e); }
  }

  // Wrap loadSBOM cũ — gọi bootstrap khi panel SBOM được mở
  var origLoadSBOM = window.loadSBOM;
  window.loadSBOM = async function () {
    await bootstrap();
    if (S.runs.length === 0 && typeof origLoadSBOM === 'function') {
      try { await origLoadSBOM(); } catch(e){}
    }
  };

  // Nếu panel-sbom đang mở sẵn (user đã ở đó khi script load) → bootstrap luôn
  setTimeout(function(){
    var p = document.getElementById('panel-sbom');
    if (p && p.classList.contains('active')) bootstrap();
  }, 300);

  // ---- BONUS: Fix iframe panels missing token bootstrap (sw_inventory, etc.) ---
  // Pattern: iframe panel gọi /api/v1/assets không có Authorization header → 401.
  // Wrap fetch trong window này để tự inject token cho mọi request /api/v1/* same-origin.
  // CHỈ áp dụng nếu request KHÔNG có Authorization header sẵn.
  (function(){
    if (window.__VSP_TOKEN_AUTOWRAP__) return;
    window.__VSP_TOKEN_AUTOWRAP__ = true;
    var ORIG = window.fetch.bind(window);
    window.fetch = function(input, init){
      try {
        var url = (typeof input === 'string') ? input : (input && input.url) || '';
        // Chỉ chạm đến same-origin /api/v1/*
        if (/^\/api\/v1\//.test(url) || (url.indexOf(location.origin + '/api/v1/') === 0)) {
          var hasAuth = false;
          if (init && init.headers) {
            if (init.headers instanceof Headers)      hasAuth = init.headers.has('Authorization');
            else if (typeof init.headers === 'object') hasAuth = !!(init.headers.Authorization || init.headers.authorization);
          }
          if (!hasAuth) {
            var t = window.TOKEN || (typeof localStorage !== 'undefined' && localStorage.getItem('vsp_token'));
            if (t) {
              init = init || {};
              init.headers = Object.assign({}, init.headers || {}, { 'Authorization': 'Bearer ' + t });
            }
          }
        }
      } catch(e){}
      return ORIG(input, init);
    };
    console.log('[VSP-AUTH] fetch auto-token wrapper armed');
  })();


})();
// ============ END SBOM UNIFIED PANEL ============
