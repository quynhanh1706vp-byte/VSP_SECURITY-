/* vsp_sw_inventory_panel.js — Phase 7A
 * ─────────────────────────────────────────────────────────────────────────
 * VSP SW Inventory frontend panel.
 *
 * Drop-in companion for vsp_pro_100.js. Wires the Software Inventory
 * panel to the backend microservice on :8094.
 *
 * Endpoints consumed:
 *   GET  /healthz
 *   GET  /hosts?search=&os=&min_risk=
 *   GET  /hosts/{name}
 *   GET  /hosts/{name}/packages
 *   GET  /hosts/{name}/cves
 *   DELETE /hosts/{name}
 *   GET  /stats
 *   GET  /audit?host=&limit=
 *   POST /cve-match
 *   GET  /export/csv
 *
 * Panel layout:
 *   [ KPI row × 5 ]      live every 15s
 *   [ Filters: OS / search / min-risk / Re-match / Export CSV ]
 *   [ Host table ]       sort by risk_score desc
 *   [ Detail modal ]     tabs: Packages | CVEs | Audit
 *   [ Audit feed ]       last 50 events, live every 30s
 * ───────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  const API_BASE = (window.VSP_SW_INVENTORY_API || 'http://127.0.0.1:8094').replace(/\/$/, '');
  const TIMEOUT  = 30_000;

  // ── helpers ──────────────────────────────────────────────────────────
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function toast(msg, kind) {
    if (typeof window.showToast === 'function') return window.showToast(msg, kind || 'info');
    (window.VSP_DEBUG && console.log('[sw-inv]', kind || 'info', msg));
  }
  async function api(path, opts) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), TIMEOUT);
    try {
      const r = await fetch(API_BASE + path, Object.assign({
        headers: { 'Content-Type': 'application/json' },
        signal:  ctrl.signal,
      }, opts || {}));
      const ct = r.headers.get('content-type') || '';
      const body = ct.includes('json') ? await r.json() : await r.text();
      if (!r.ok && typeof body === 'object') {
        throw new Error(body.error || ('HTTP ' + r.status));
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return body;
    } finally { clearTimeout(t); }
  }
  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso); if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }
  function relTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso); const ms = Date.now() - d.getTime();
    if (ms < 60_000)        return Math.floor(ms / 1000)        + 's ago';
    if (ms < 3_600_000)     return Math.floor(ms / 60_000)      + 'm ago';
    if (ms < 86_400_000)    return Math.floor(ms / 3_600_000)   + 'h ago';
    return Math.floor(ms / 86_400_000) + 'd ago';
  }
  function riskPill(score) {
    let c, label;
    if      (score >= 50) { c = 'var(--red)';    label = 'CRITICAL'; }
    else if (score >= 20) { c = 'var(--orange)'; label = 'HIGH'; }
    else if (score >= 5)  { c = 'var(--amber)';  label = 'MEDIUM'; }
    else if (score >= 1)  { c = 'var(--cyan)';   label = 'LOW'; }
    else                  { c = 'var(--green)';  label = 'CLEAN'; }
    return `<span style="font-family:var(--font-mono);font-size:9px;font-weight:700;
            color:${c};padding:2px 6px;border-radius:3px;
            background:${c.replace('var(', 'rgba(').replace(')', ',0.12)')};
            ">${label} ${score}</span>`;
  }
  function sevPill(sev, count) {
    const map = {
      CRITICAL: ['var(--red)',    'C'],
      HIGH:     ['var(--orange)', 'H'],
      MEDIUM:   ['var(--amber)',  'M'],
      LOW:      ['var(--cyan)',   'L'],
    };
    const [c, label] = map[sev] || ['var(--t3)', '?'];
    return `<span style="font-family:var(--font-mono);font-size:10px;color:${c};margin-right:8px">
              ${label}:<b>${count || 0}</b>
            </span>`;
  }

  // ── panel discovery ──────────────────────────────────────────────────
  function findPanel() {
    return $('panel-sw-inventory')
        || $('panel-software-inventory')
        || $('panel-inventory')
        || $('panel-assets')                    // some builds put it under Assets
        || document.querySelector('[data-panel="sw-inventory"]')
        || document.querySelector('[data-panel="software-inventory"]');
  }

  // ── mount ────────────────────────────────────────────────────────────
  function mount(panel) {
    if (panel.dataset.swInvWired === '1') return;
    panel.dataset.swInvWired = '1';

    panel.insertAdjacentHTML('afterbegin', `
      <div class="card mb14" id="swi-kpis-card">
        <div class="card-head">
          <div>
            <div class="card-title">Software Inventory</div>
            <div class="card-sub">
              microservice <code style="color:var(--cyan);font-family:var(--font-mono)">${esc(API_BASE)}</code>
              · agent push (CSRF-exempt) · 35 curated CVE rules
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center">
            <span id="swi-health" class="mono-sm" style="color:var(--t3)">checking…</span>
          </div>
        </div>

        <div style="padding:14px;display:grid;grid-template-columns:repeat(5,1fr);gap:10px">
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--cyan);background:var(--bg3);border-radius:4px">
            <div class="kpi-label" style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Hosts</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--cyan)" id="swi-k-hosts">—</div>
            <div style="font-size:10px;color:var(--t3)" id="swi-k-stale">— stale &gt;24h</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--red);background:var(--bg3);border-radius:4px">
            <div class="kpi-label" style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">CVE Critical</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--red)" id="swi-k-crit">—</div>
            <div style="font-size:10px;color:var(--t3)">unpatched</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--orange);background:var(--bg3);border-radius:4px">
            <div class="kpi-label" style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">CVE High</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--orange)" id="swi-k-high">—</div>
            <div style="font-size:10px;color:var(--t3)">unpatched</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--amber);background:var(--bg3);border-radius:4px">
            <div class="kpi-label" style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">CVE Medium</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--amber)" id="swi-k-med">—</div>
            <div style="font-size:10px;color:var(--t3)">unpatched</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--green);background:var(--bg3);border-radius:4px">
            <div class="kpi-label" style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Packages</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--green)" id="swi-k-pkgs">—</div>
            <div style="font-size:10px;color:var(--t3)">tracked</div>
          </div>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Hosts</div>
            <div class="card-sub" id="swi-hosts-sub">loading…</div>
          </div>
          <div style="display:flex;gap:6px">
            <button class="btn btn-sm" id="swi-btn-rematch">↻ Re-match CVEs</button>
            <button class="btn btn-sm" id="swi-btn-export">⤓ CSV</button>
            <button class="btn btn-sm" id="swi-btn-refresh">⟳ Refresh</button>
          </div>
        </div>

        <div style="padding:12px 14px;display:grid;grid-template-columns:1fr 200px 140px;gap:8px">
          <input aria-label="Search hostname…" id="swi-search" class="form-ctrl" placeholder="Search hostname…"
                 style="font-size:12px">
          <select aria-label="Swi Os" id="swi-os" class="form-ctrl" style="font-size:12px">
            <option value="">All OS</option>
            <option value="ubuntu">Ubuntu</option>
            <option value="debian">Debian</option>
            <option value="alpine">Alpine</option>
            <option value="centos">CentOS</option>
            <option value="rhel">RHEL</option>
            <option value="amazon">Amazon Linux</option>
          </select>
          <select aria-label="Swi Min Risk" id="swi-min-risk" class="form-ctrl" style="font-size:12px">
            <option value="0">All risk</option>
            <option value="1">Risk ≥ 1</option>
            <option value="5">Risk ≥ 5 (medium+)</option>
            <option value="20">Risk ≥ 20 (high+)</option>
            <option value="50">Risk ≥ 50 (critical)</option>
          </select>
        </div>

        <div style="overflow:auto;max-height:60vh">
          <table class="data-table" style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="text-align:left;font-size:10px;color:var(--t3);text-transform:uppercase;
                         letter-spacing:0.06em;background:var(--bg3);border-bottom:1px solid var(--border);
                         position:sticky;top:0">
                <th style="padding:8px 12px">Hostname</th>
                <th style="padding:8px 12px">OS</th>
                <th style="padding:8px 12px">Pkgs</th>
                <th style="padding:8px 12px">CVEs (C/H/M/L)</th>
                <th style="padding:8px 12px">Risk</th>
                <th style="padding:8px 12px">Last seen</th>
                <th style="padding:8px 12px">Agent</th>
                <th style="padding:8px 12px"></th>
              </tr>
            </thead>
            <tbody id="swi-hosts-rows">
              <tr><td colspan="8" style="padding:24px;text-align:center;color:var(--t3)">
                  loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Audit feed</div>
            <div class="card-sub" id="swi-audit-sub">last 50 events, live</div>
          </div>
        </div>
        <div style="padding:0;max-height:280px;overflow:auto">
          <table style="width:100%;border-collapse:collapse;font-size:11px">
            <tbody id="swi-audit-rows">
              <tr><td style="padding:18px;text-align:center;color:var(--t3)">loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `);

    // detail modal (singleton)
    if (!document.getElementById('swi-detail-modal')) {
      const m = document.createElement('div');
      m.id = 'swi-detail-modal';
      m.className = 'modal-overlay';
      m.style.display = 'none';
      m.innerHTML = `
        <div class="modal" style="width:min(900px,95vw);max-height:90vh;display:flex;flex-direction:column">
          <div class="modal-head">
            <div>
              <div class="modal-title" id="swi-md-title">Host detail</div>
              <div class="modal-sub" id="swi-md-sub"></div>
            </div>
            <button class="modal-close" id="swi-md-close">✕</button>
          </div>
          <div class="modal-body" style="overflow:auto;flex:1">
            <div id="swi-md-meta" style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;
                 margin-bottom:14px;padding:10px;background:var(--bg3);border-radius:4px"></div>
            <div style="display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:10px">
              <button class="btn btn-sm swi-tab-btn" data-tab="packages" style="border-radius:0;border-bottom:2px solid var(--cyan)">Packages</button>
              <button class="btn btn-sm swi-tab-btn" data-tab="cves">CVEs</button>
              <button class="btn btn-sm swi-tab-btn" data-tab="audit">Audit</button>
            </div>
            <div id="swi-md-content"></div>
          </div>
          <div class="modal-footer">
            <button class="btn" id="swi-md-delete" style="color:var(--red)">Remove host</button>
            <button class="btn" id="swi-md-close-btn">Close</button>
          </div>
        </div>
      `;
      m.addEventListener('click', e => { if (e.target === m) m.style.display = 'none'; });
      document.body.appendChild(m);
      $('swi-md-close').addEventListener('click',     () => m.style.display = 'none');
      $('swi-md-close-btn').addEventListener('click', () => m.style.display = 'none');
    }

    // wire buttons
    $('swi-btn-refresh').addEventListener('click', refreshAll);
    $('swi-btn-rematch').addEventListener('click', async () => {
      $('swi-btn-rematch').disabled = true;
      try {
        const r = await api('/cve-match', { method: 'POST' });
        toast(`Re-matched: ${r.cve_matches} CVE matches across ${r.hosts} hosts`, 'success');
        refreshAll();
      } catch (e) { toast('Re-match failed: ' + e.message, 'error'); }
      finally { $('swi-btn-rematch').disabled = false; }
    });
    $('swi-btn-export').addEventListener('click', () => {
      window.open(API_BASE + '/export/csv', '_blank');
    });
    $('swi-search').addEventListener('input',  debounce(refreshHosts, 300));
    $('swi-os').addEventListener('change',     refreshHosts);
    $('swi-min-risk').addEventListener('change', refreshHosts);

    // initial load
    refreshAll();
    // polling
    setInterval(refreshStats, 15_000);
    setInterval(refreshAudit, 30_000);
  }

  function debounce(fn, ms) {
    let t;
    return function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  // ── refresh ──────────────────────────────────────────────────────────
  async function refreshAll() {
    healthCheck();
    refreshStats();
    refreshHosts();
    refreshAudit();
  }

  async function healthCheck() {
    const el = $('swi-health'); if (!el) return;
    try {
      const h = await api('/healthz');
      el.innerHTML = `<span style="color:var(--green)">●</span> healthy
        · ${h.hosts} hosts · ${h.cve_matches} CVE matches`;
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">●</span> unreachable
        — <span style="color:var(--t3)">is vsp-sw-inventory running on :8094?</span>`;
    }
  }

  async function refreshStats() {
    try {
      const s = await api('/stats');
      const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
      set('swi-k-hosts', s.hosts);
      set('swi-k-stale', `${s.hosts_stale_24h} stale >24h`);
      set('swi-k-crit',  s.cve_critical);
      set('swi-k-high',  s.cve_high);
      set('swi-k-med',   s.cve_medium);
      set('swi-k-pkgs',  s.packages);
    } catch (e) { /* keep last values */ }
  }

  async function refreshHosts() {
    const sub = $('swi-hosts-sub'); if (sub) sub.textContent = 'loading…';
    const rows = $('swi-hosts-rows');
    const search = encodeURIComponent($('swi-search').value || '');
    const osf = encodeURIComponent($('swi-os').value || '');
    const minr = encodeURIComponent($('swi-min-risk').value || '0');
    try {
      const j = await api(`/hosts?search=${search}&os=${osf}&min_risk=${minr}`);
      if (sub) sub.textContent = `${j.total} host${j.total === 1 ? '' : 's'}`;
      if (j.total === 0) {
        rows.innerHTML = `<tr><td colspan="8" style="padding:32px;text-align:center;color:var(--t3)">
          no hosts have reported yet — install the agent on a machine and run<br>
          <code style="color:var(--cyan);font-family:var(--font-mono)">vsp-sw-agent --once</code>
          </td></tr>`;
        return;
      }
      rows.innerHTML = j.hosts.map(h => `
        <tr style="border-bottom:1px solid var(--border);cursor:pointer"
            onmouseover="this.style.background='var(--bg4)'"
            onmouseout="this.style.background='transparent'"
            data-host="${esc(h.hostname)}">
          <td style="padding:8px 12px;font-family:var(--font-mono);font-size:11px">
              <b style="color:var(--t1)">${esc(h.hostname)}</b>
              <div style="font-size:9px;color:var(--t3)">${esc(h.ip_address || '')}</div>
          </td>
          <td style="padding:8px 12px;font-size:11px">
              ${esc(h.os || '—')} <span style="color:var(--t3)">${esc(h.os_version || '')}</span>
              <div style="font-size:9px;color:var(--t3);font-family:var(--font-mono)">${esc(h.kernel || '')}</div>
          </td>
          <td style="padding:8px 12px;font-family:var(--font-mono);font-size:11px;color:var(--cyan)">${h.package_count}</td>
          <td style="padding:8px 12px;font-size:11px">
              ${sevPill('CRITICAL', h.cve_critical)}${sevPill('HIGH', h.cve_high)}${sevPill('MEDIUM', h.cve_medium)}${sevPill('LOW', h.cve_low)}
          </td>
          <td style="padding:8px 12px">${riskPill(h.risk_score)}</td>
          <td style="padding:8px 12px;font-size:11px;color:var(--t3)">
              ${relTime(h.last_seen)}<br>
              <span style="font-size:9px">${esc(fmtTime(h.last_seen))}</span>
          </td>
          <td style="padding:8px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3)">${esc(h.agent_version || '—')}</td>
          <td style="padding:8px 12px;text-align:right">→</td>
        </tr>
      `).join('');
      // Wire click-to-detail
      rows.querySelectorAll('tr[data-host]').forEach(tr => {
        tr.addEventListener('click', () => showDetail(tr.dataset.host));
      });
    } catch (e) {
      if (sub) sub.textContent = 'error';
      rows.innerHTML = `<tr><td colspan="8" style="padding:24px;text-align:center;color:var(--red)">
        ✗ ${esc(e.message)}</td></tr>`;
    }
  }

  async function refreshAudit() {
    const rows = $('swi-audit-rows'); if (!rows) return;
    try {
      const j = await api('/audit?limit=50');
      if (j.total === 0) {
        rows.innerHTML = `<tr><td style="padding:18px;text-align:center;color:var(--t3)">no events yet</td></tr>`;
        return;
      }
      rows.innerHTML = j.events.map(ev => {
        const c = ev.status === 'accepted' || ev.status === 'ok' ? 'var(--green)'
                : ev.status === 'rejected' || ev.status === 'unauthorized' ? 'var(--red)'
                : 'var(--amber)';
        return `
          <tr style="border-bottom:1px solid var(--border)">
            <td style="padding:6px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3);width:180px">
                ${esc(fmtTime(ev.time))}</td>
            <td style="padding:6px 12px;font-family:var(--font-mono);font-size:10px;color:${c};width:100px">
                ${esc(ev.status.toUpperCase())}</td>
            <td style="padding:6px 12px;font-size:11px;color:var(--t1)">
                <b>${esc(ev.action)}</b>
                ${ev.hostname ? ` · <span style="color:var(--cyan)">${esc(ev.hostname)}</span>` : ''}
                ${ev.ip ? ` <span style="color:var(--t3)">from ${esc(ev.ip)}</span>` : ''}
                ${ev.detail ? `<div style="font-size:10px;color:var(--t3);margin-top:2px">${esc(ev.detail)}</div>` : ''}
            </td>
          </tr>`;
      }).join('');
    } catch (e) {
      rows.innerHTML = `<tr><td style="padding:14px;text-align:center;color:var(--red)">✗ ${esc(e.message)}</td></tr>`;
    }
  }

  // ── detail modal ─────────────────────────────────────────────────────
  let _currentHost = null;
  let _currentTab  = 'packages';

  async function showDetail(host) {
    _currentHost = host;
    _currentTab  = 'packages';
    const m = $('swi-detail-modal'); m.style.display = 'flex';
    $('swi-md-title').textContent = host;
    $('swi-md-sub').textContent   = 'loading…';
    $('swi-md-meta').innerHTML    = '';
    $('swi-md-content').innerHTML = '<div style="padding:24px;text-align:center;color:var(--t3)">loading…</div>';
    // Tab buttons
    document.querySelectorAll('.swi-tab-btn').forEach(b => {
      b.style.borderBottom = b.dataset.tab === _currentTab ? '2px solid var(--cyan)' : '2px solid transparent';
      b.onclick = () => { _currentTab = b.dataset.tab; refreshDetailTab();
        document.querySelectorAll('.swi-tab-btn').forEach(bb => {
          bb.style.borderBottom = bb.dataset.tab === _currentTab ? '2px solid var(--cyan)' : '2px solid transparent';
        });
      };
    });
    // Delete button
    $('swi-md-delete').onclick = async () => {
      if (!confirm('Remove host "' + host + '" from inventory? (Agent will re-create on next report.)')) return;
      try {
        await api('/hosts/' + encodeURIComponent(host), { method: 'DELETE' });
        toast('Host removed', 'success');
        $('swi-detail-modal').style.display = 'none';
        refreshAll();
      } catch (e) { toast('Delete failed: ' + e.message, 'error'); }
    };

    try {
      const h = await api('/hosts/' + encodeURIComponent(host));
      $('swi-md-sub').textContent = `${h.package_count} packages · ${h.cves.length} CVE matches · risk ${h.risk_score}`;
      $('swi-md-meta').innerHTML = `
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">OS</div>
             <div style="font-size:13px;color:var(--t1)">${esc(h.os || '—')} ${esc(h.os_version || '')}</div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">Kernel</div>
             <div style="font-size:11px;color:var(--t1);font-family:var(--font-mono)">${esc(h.kernel || '—')}</div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">IP</div>
             <div style="font-size:11px;color:var(--t1);font-family:var(--font-mono)">${esc(h.ip_address || '—')}</div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">Agent</div>
             <div style="font-size:11px;color:var(--t1);font-family:var(--font-mono)">${esc(h.agent_version || '—')}</div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">First seen</div>
             <div style="font-size:11px;color:var(--t1)">${esc(fmtTime(h.first_seen))}</div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">Last seen</div>
             <div style="font-size:11px;color:var(--t1)">${esc(fmtTime(h.last_seen))} <span style="color:var(--t3)">(${relTime(h.last_seen)})</span></div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">Reports</div>
             <div style="font-size:11px;color:var(--t1)">${h.report_count}</div></div>
        <div><div class="kpi-label" style="font-size:9px;color:var(--t3);text-transform:uppercase">Risk</div>
             <div style="margin-top:4px">${riskPill(h.risk_score)}</div></div>
      `;
      window.__swi_h = h;
      refreshDetailTab();
    } catch (e) {
      $('swi-md-content').innerHTML = `<div style="padding:24px;color:var(--red)">✗ ${esc(e.message)}</div>`;
    }
  }

  function refreshDetailTab() {
    const c = $('swi-md-content');
    const h = window.__swi_h;
    if (!h) return;
    if (_currentTab === 'packages') {
      const total = h.packages.length;
      c.innerHTML = `
        <div style="font-size:11px;color:var(--t3);margin-bottom:8px">${total} packages</div>
        <div style="max-height:60vh;overflow:auto;border:1px solid var(--border);border-radius:4px">
          <table style="width:100%;border-collapse:collapse;font-size:11px">
            <thead><tr style="background:var(--bg3)">
              <th style="padding:6px 10px;text-align:left">Name</th>
              <th style="padding:6px 10px;text-align:left">Version</th>
              <th style="padding:6px 10px;text-align:left">Source</th>
              <th style="padding:6px 10px;text-align:left">Arch</th>
            </tr></thead><tbody>
            ${h.packages.map(p => `
              <tr style="border-bottom:1px solid var(--border)">
                <td style="padding:5px 10px;font-family:var(--font-mono)">${esc(p.name)}</td>
                <td style="padding:5px 10px;font-family:var(--font-mono);color:var(--cyan)">${esc(p.version)}</td>
                <td style="padding:5px 10px;color:var(--t3);font-size:10px">${esc(p.source || '')}</td>
                <td style="padding:5px 10px;color:var(--t3);font-size:10px">${esc(p.arch || '')}</td>
              </tr>`).join('')}
          </tbody></table>
        </div>`;
    } else if (_currentTab === 'cves') {
      if (h.cves.length === 0) {
        c.innerHTML = `<div style="padding:24px;text-align:center;color:var(--green)">✓ no known CVEs match — host is clean against current ruleset</div>`;
        return;
      }
      c.innerHTML = `
        <div style="font-size:11px;color:var(--t3);margin-bottom:8px">${h.cves.length} CVE matches</div>
        <div style="max-height:60vh;overflow:auto">
          ${h.cves.map(cve => `
            <div style="padding:12px;border:1px solid var(--border);border-radius:4px;margin-bottom:8px;background:var(--bg3)">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <div>
                  <span style="font-family:var(--font-mono);font-size:13px;font-weight:700;color:var(--t1)">${esc(cve.cve)}</span>
                  ${sevPill(cve.severity, '')}<span style="color:var(--t3);font-size:11px">CVSS ${cve.cvss || '?'}</span>
                </div>
              </div>
              <div style="font-size:12px;color:var(--t1);margin-bottom:6px">${esc(cve.title || '')}</div>
              <div style="font-size:10px;color:var(--t3);font-family:var(--font-mono)">
                Affected: <span style="color:var(--amber)">${esc(cve.package)} @ ${esc(cve.version)}</span>
                ${cve.fixed_in ? ` &nbsp; → fixed in <span style="color:var(--green)">${esc(cve.fixed_in)}</span>` : ''}
              </div>
            </div>
          `).join('')}
        </div>`;
    } else if (_currentTab === 'audit') {
      c.innerHTML = '<div style="padding:14px;color:var(--t3)">loading…</div>';
      api('/audit?host=' + encodeURIComponent(_currentHost) + '&limit=200').then(j => {
        if (j.total === 0) {
          c.innerHTML = '<div style="padding:24px;text-align:center;color:var(--t3)">no events</div>';
          return;
        }
        c.innerHTML = `
          <div style="max-height:60vh;overflow:auto">
            <table style="width:100%;border-collapse:collapse;font-size:11px">
              ${j.events.map(ev => `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:6px 10px;font-family:var(--font-mono);font-size:10px;color:var(--t3);width:200px">${esc(fmtTime(ev.time))}</td>
                  <td style="padding:6px 10px;color:var(--t1)">
                      <b>${esc(ev.action)}</b> →
                      <span style="color:${ev.status === 'accepted' || ev.status === 'ok' ? 'var(--green)' : 'var(--red)'}">${esc(ev.status)}</span>
                      ${ev.detail ? `<div style="font-size:10px;color:var(--t3)">${esc(ev.detail)}</div>` : ''}
                  </td>
                </tr>`).join('')}
            </table>
          </div>`;
      }).catch(e => {
        c.innerHTML = `<div style="padding:14px;color:var(--red)">✗ ${esc(e.message)}</div>`;
      });
    }
  }

  // ── boot ─────────────────────────────────────────────────────────────
  function boot() {
    const p = findPanel();
    if (!p) { setTimeout(boot, 600); return; }
    mount(p);
    const obs = new MutationObserver(() => {
      const pp = findPanel();
      if (pp && pp.dataset.swInvWired !== '1') mount(pp);
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.VSPSWInventory = { refresh: refreshAll, api, apiBase: API_BASE };
  (window.VSP_DEBUG && console.log('[vsp-sw-inventory] panel wired — backend:', API_BASE));
})();
