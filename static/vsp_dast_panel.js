/* vsp_dast_panel.js — Phase 7D
 * ─────────────────────────────────────────────────────────────────────────
 * VSP DAST frontend panel.
 * Wires Scheduler-managed nuclei scans on port 8093.
 *
 * Endpoints:
 *   GET    /healthz / /tools/check
 *   POST   /scan              {target, profile}
 *   GET    /scans             list (without findings)
 *   GET    /scans/{id}        detail with findings
 *   GET    /scans/{id}/findings
 *   POST   /scans/{id}/cancel
 *   DELETE /scans/{id}
 *   GET    /stats
 * ───────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  const API_BASE = (window.VSP_DAST_API || 'http://127.0.0.1:8093').replace(/\/$/, '');
  const TIMEOUT  = 30_000;

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function toast(m, k) {
    if (typeof window.showToast === 'function') return window.showToast(m, k || 'info');
    (window.VSP_DEBUG && console.log('[dast]', k || 'info', m));
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
      if (!r.ok && typeof body === 'object') throw new Error(body.error || ('HTTP ' + r.status));
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return body;
    } finally { clearTimeout(t); }
  }
  function fmtTime(iso) {
    if (!iso || iso.startsWith('0001')) return '—';
    const d = new Date(iso); return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }
  function relTime(iso) {
    if (!iso || iso.startsWith('0001')) return '—';
    const ms = Date.now() - new Date(iso).getTime();
    if (ms < 60_000) return Math.floor(ms / 1000) + 's ago';
    if (ms < 3_600_000) return Math.floor(ms / 60_000) + 'm ago';
    if (ms < 86_400_000) return Math.floor(ms / 3_600_000) + 'h ago';
    return Math.floor(ms / 86_400_000) + 'd ago';
  }
  function fmtDuration(ms) {
    if (!ms) return '—';
    if (ms < 1000) return ms + 'ms';
    if (ms < 60_000) return (ms / 1000).toFixed(1) + 's';
    return Math.floor(ms / 60_000) + 'm ' + Math.floor((ms % 60_000) / 1000) + 's';
  }
  function statusPill(s) {
    const m = {
      queued:    ['var(--t3)',     '⏰ queued'],
      running:   ['var(--cyan)',   '▶ running'],
      done:      ['var(--green)',  '✓ done'],
      failed:    ['var(--red)',    '✗ failed'],
      cancelled: ['var(--amber)',  '⏹ cancelled'],
    };
    const [c, l] = m[s] || ['var(--t3)', s];
    return `<span style="font-family:var(--font-mono);font-size:10px;font-weight:700;
            color:${c};padding:2px 8px;border-radius:3px;
            background:${c.replace('var(', 'rgba(').replace(')', ',0.12)')}">${l}</span>`;
  }
  function sevPill(sev) {
    const m = {
      critical: ['var(--red)',     'CRIT'],
      high:     ['var(--orange)',  'HIGH'],
      medium:   ['var(--amber)',   'MED'],
      low:      ['var(--cyan)',    'LOW'],
      info:     ['var(--t3)',      'INFO'],
    };
    const [c, l] = m[(sev || '').toLowerCase()] || ['var(--t3)', sev];
    return `<span style="font-family:var(--font-mono);font-size:9px;font-weight:700;
            color:${c};padding:2px 6px;border-radius:3px;
            background:${c.replace('var(', 'rgba(').replace(')', ',0.12)')}">${l}</span>`;
  }
  function profileBadge(p) {
    const m = {
      quick:    ['var(--cyan)',   '⚡ quick'],
      standard: ['var(--purple)', '◐ standard'],
      deep:     ['var(--red)',    '◉ deep'],
    };
    const [c, l] = m[p] || ['var(--t3)', p];
    return `<span style="font-family:var(--font-mono);font-size:10px;color:${c}">${l}</span>`;
  }

  function findPanel() {
    return $('panel-dast') || $('panel-vulnerability-scan')
        || document.querySelector('[data-panel="dast"]')
        || document.querySelector('[data-panel="dast-scan"]');
  }

  function mount(panel) {
    if (panel.dataset.dastWired === '1') return;
    panel.dataset.dastWired = '1';

    panel.insertAdjacentHTML('afterbegin', `
      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">DAST — Dynamic Scan</div>
            <div class="card-sub">
              microservice <code style="color:var(--cyan);font-family:var(--font-mono)">${esc(API_BASE)}</code>
              · nuclei runner · 3 profiles
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center">
            <span id="dast-health" class="mono-sm" style="color:var(--t3)">checking…</span>
            <button class="btn btn-primary btn-sm" id="dast-btn-new">+ New scan</button>
          </div>
        </div>

        <div style="padding:14px;display:grid;grid-template-columns:repeat(5,1fr);gap:10px">
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--cyan);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Scans</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--cyan)" id="dast-k-scans">—</div>
            <div style="font-size:10px;color:var(--t3)" id="dast-k-running">— running</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--red);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Critical</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--red)" id="dast-k-crit">—</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--orange);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">High</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--orange)" id="dast-k-high">—</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--amber);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Medium</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--amber)" id="dast-k-med">—</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--purple);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Findings</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--purple)" id="dast-k-findings">—</div>
          </div>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Scans</div>
            <div class="card-sub" id="dast-scans-sub">loading…</div>
          </div>
          <button class="btn btn-sm" id="dast-btn-refresh">⟳</button>
        </div>
        <div style="overflow:auto;max-height:60vh">
          <table class="data-table" style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="text-align:left;font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.06em;
                         background:var(--bg3);border-bottom:1px solid var(--border);position:sticky;top:0">
                <th style="padding:8px 12px">Target</th>
                <th style="padding:8px 12px">Profile</th>
                <th style="padding:8px 12px">Status</th>
                <th style="padding:8px 12px">Findings</th>
                <th style="padding:8px 12px">Started</th>
                <th style="padding:8px 12px">Duration</th>
                <th style="padding:8px 12px;text-align:right"></th>
              </tr>
            </thead>
            <tbody id="dast-rows">
              <tr><td colspan="7" style="padding:24px;text-align:center;color:var(--t3)">loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `);

    ensureModals();
    $('dast-btn-refresh').addEventListener('click', refreshAll);
    $('dast-btn-new').addEventListener('click', openScanModal);

    refreshAll();
    setInterval(refreshAll, 5_000); // aggressive polling for live scan progress
  }

  // ── modals ───────────────────────────────────────────────────────────
  function ensureModals() {
    if (document.getElementById('dast-scan-modal')) return;

    // New scan modal
    const newModal = document.createElement('div');
    newModal.id = 'dast-scan-modal';
    newModal.className = 'modal-overlay';
    newModal.style.display = 'none';
    newModal.innerHTML = `
      <div class="modal" style="width:min(640px,95vw)">
        <div class="modal-head">
          <div>
            <div class="modal-title">New DAST scan</div>
            <div class="modal-sub">nuclei against an HTTP(S) target</div>
          </div>
          <button class="modal-close" id="dast-sm-close">✕</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label class="form-label" for="dast-sm-target">Target URL</label>
            <input id="dast-sm-target" class="form-ctrl"
                   placeholder="https://example.com"
                   style="font-family:var(--font-mono);font-size:12px">
            <div style="font-size:10px;color:var(--t3);margin-top:4px">
              Must include <code>http://</code> or <code>https://</code>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Profile</label>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:6px">
              <label style="display:block;padding:12px;background:var(--bg3);border-radius:4px;border:2px solid var(--cyan);cursor:pointer" id="dast-sm-p-quick">
                <input aria-label="Dast Profile" type="radio" name="dast-profile" value="quick" checked style="display:none">
                <div style="font-size:11px;font-weight:700;color:var(--cyan)">⚡ Quick</div>
                <div style="font-size:10px;color:var(--t3);margin-top:4px">~30s</div>
                <div style="font-size:10px;color:var(--t2);margin-top:4px">CVE templates only<br>severity: critical, high</div>
              </label>
              <label style="display:block;padding:12px;background:var(--bg3);border-radius:4px;border:2px solid var(--border);cursor:pointer" id="dast-sm-p-std">
                <input aria-label="Dast Profile" type="radio" name="dast-profile" value="standard" style="display:none">
                <div style="font-size:11px;font-weight:700;color:var(--purple)">◐ Standard</div>
                <div style="font-size:10px;color:var(--t3);margin-top:4px">~3min</div>
                <div style="font-size:10px;color:var(--t2);margin-top:4px">All templates<br>severity: critical, high, medium</div>
              </label>
              <label style="display:block;padding:12px;background:var(--bg3);border-radius:4px;border:2px solid var(--border);cursor:pointer" id="dast-sm-p-deep">
                <input aria-label="Dast Profile" type="radio" name="dast-profile" value="deep" style="display:none">
                <div style="font-size:11px;font-weight:700;color:var(--red)">◉ Deep</div>
                <div style="font-size:10px;color:var(--t3);margin-top:4px">~10min+</div>
                <div style="font-size:10px;color:var(--t2);margin-top:4px">Everything<br>all severities</div>
              </label>
            </div>
          </div>
          <div style="padding:10px;background:var(--bg3);border-radius:4px;font-size:11px;color:var(--t2);margin-top:14px;border-left:3px solid var(--amber)">
            <b style="color:var(--amber)">⚠ Authorization required:</b> only scan targets you own or have explicit permission to test. Scanning random sites without permission may be illegal.
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn" id="dast-sm-cancel">Cancel</button>
          <button class="btn btn-primary" id="dast-sm-start">Start scan</button>
        </div>
      </div>
    `;
    newModal.addEventListener('click', e => { if (e.target === newModal) newModal.style.display = 'none'; });
    document.body.appendChild(newModal);
    $('dast-sm-close').addEventListener('click',  () => newModal.style.display = 'none');
    $('dast-sm-cancel').addEventListener('click', () => newModal.style.display = 'none');
    $('dast-sm-start').addEventListener('click', startScan);

    // Profile picker visual selection
    document.querySelectorAll('input[name="dast-profile"]').forEach(r => {
      r.addEventListener('change', () => {
        document.querySelectorAll('input[name="dast-profile"]').forEach(rr => {
          rr.parentElement.style.borderColor = rr.checked ? 'var(--cyan)' : 'var(--border)';
        });
      });
    });

    // Detail modal
    const det = document.createElement('div');
    det.id = 'dast-detail-modal';
    det.className = 'modal-overlay';
    det.style.display = 'none';
    det.innerHTML = `
      <div class="modal" style="width:min(1100px,95vw);max-height:92vh;display:flex;flex-direction:column">
        <div class="modal-head">
          <div>
            <div class="modal-title" id="dast-md-title">Scan</div>
            <div class="modal-sub" id="dast-md-sub"></div>
          </div>
          <button class="modal-close" id="dast-md-close">✕</button>
        </div>
        <div class="modal-body" style="overflow:auto;flex:1" id="dast-md-body"></div>
        <div class="modal-footer">
          <button class="btn" id="dast-md-cancel" style="color:var(--amber);display:none">Cancel scan</button>
          <button class="btn" id="dast-md-delete" style="color:var(--red)">Delete</button>
          <button class="btn" id="dast-md-close-btn">Close</button>
        </div>
      </div>
    `;
    det.addEventListener('click', e => { if (e.target === det) det.style.display = 'none'; });
    document.body.appendChild(det);
    $('dast-md-close').addEventListener('click',     () => det.style.display = 'none');
    $('dast-md-close-btn').addEventListener('click', () => det.style.display = 'none');
  }

  function openScanModal() {
    $('dast-sm-target').value = '';
    document.querySelectorAll('input[name="dast-profile"]').forEach(r => {
      r.checked = r.value === 'quick';
      r.parentElement.style.borderColor = r.checked ? 'var(--cyan)' : 'var(--border)';
    });
    $('dast-scan-modal').style.display = 'flex';
  }

  async function startScan() {
    const target = $('dast-sm-target').value.trim();
    const profile = (document.querySelector('input[name="dast-profile"]:checked') || {}).value || 'quick';
    if (!target) { toast('Target URL required', 'warn'); return; }
    if (!target.match(/^https?:\/\//)) { toast('Must start with http:// or https://', 'warn'); return; }
    try {
      const r = await api('/scan', { method: 'POST', body: JSON.stringify({ target, profile }) });
      toast('Scan queued: ' + r.id, 'success');
      $('dast-scan-modal').style.display = 'none';
      refreshAll();
      // Auto-open detail to watch progress
      setTimeout(() => showDetail(r.id), 500);
    } catch (e) { toast('Failed to queue: ' + e.message, 'error'); }
  }

  // ── refresh ──────────────────────────────────────────────────────────
  async function refreshAll() {
    healthCheck(); refreshStats(); refreshScans();
  }

  async function healthCheck() {
    const el = $('dast-health'); if (!el) return;
    try {
      const h = await api('/healthz');
      const tool = (h.tools || [])[0];
      const nucleiOK = tool && tool.available;
      el.innerHTML = nucleiOK
        ? `<span style="color:var(--green)">●</span> nuclei OK · ${h.scans} scans, ${h.running} running`
        : `<span style="color:var(--red)">●</span> nuclei NOT installed — install: <code>go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest</code>`;
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">●</span> service unreachable`;
    }
  }

  async function refreshStats() {
    try {
      const s = await api('/stats');
      const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
      set('dast-k-scans', s.scans_total);
      set('dast-k-running', `${s.scans_running} running, ${s.scans_24h} (24h)`);
      set('dast-k-crit', s.by_severity.critical);
      set('dast-k-high', s.by_severity.high);
      set('dast-k-med',  s.by_severity.medium);
      set('dast-k-findings', s.findings);
    } catch (e) { /* keep last */ }
  }

  async function refreshScans() {
    const sub = $('dast-scans-sub'); const rows = $('dast-rows');
    if (sub) sub.textContent = 'loading…';
    try {
      const j = await api('/scans');
      if (sub) sub.textContent = `${j.total} scan${j.total === 1 ? '' : 's'}`;
      if (j.total === 0) {
        rows.innerHTML = `<tr><td colspan="7" style="padding:32px;text-align:center;color:var(--t3)">
          no scans yet — click <b>+ New scan</b> to start</td></tr>`;
        return;
      }
      rows.innerHTML = j.scans.map(s => {
        const bar = s.status === 'running'
          ? `<div style="width:100%;height:3px;background:var(--bg3);border-radius:2px;margin-top:4px;overflow:hidden">
               <div style="width:50%;height:100%;background:var(--cyan);animation:dast-pulse 1.5s ease-in-out infinite"></div>
             </div>`
          : '';
        return `
        <tr style="border-bottom:1px solid var(--border);cursor:pointer"
            onmouseover="this.style.background='var(--bg4)'" onmouseout="this.style.background='transparent'"
            data-id="${esc(s.id)}">
          <td style="padding:8px 12px;font-family:var(--font-mono);font-size:11px;color:var(--cyan)">${esc(s.target)}${bar}</td>
          <td style="padding:8px 12px">${profileBadge(s.profile)}</td>
          <td style="padding:8px 12px">${statusPill(s.status)}</td>
          <td style="padding:8px 12px;font-size:11px">
            ${s.stats ? `
              ${s.stats.critical ? sevPill('critical') + ' <b>'+s.stats.critical+'</b> ' : ''}
              ${s.stats.high     ? sevPill('high')     + ' <b>'+s.stats.high+'</b> '     : ''}
              ${s.stats.medium   ? sevPill('medium')   + ' <b>'+s.stats.medium+'</b> '   : ''}
              ${s.stats.low      ? sevPill('low')      + ' <b>'+s.stats.low+'</b> '      : ''}
              ${s.stats.info     ? sevPill('info')     + ' <b>'+s.stats.info+'</b>'      : ''}
              ${(!s.stats.total) ? '<span style="color:var(--t3)">—</span>' : ''}
            ` : '—'}
          </td>
          <td style="padding:8px 12px;font-size:11px;color:var(--t3)">
            ${esc(relTime(s.started_at))}<br>
            <span style="font-size:9px">${esc(fmtTime(s.started_at))}</span>
          </td>
          <td style="padding:8px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3)">${esc(fmtDuration(s.duration_ms))}</td>
          <td style="padding:8px 12px;text-align:right;color:var(--t3)">→</td>
        </tr>`;
      }).join('');
      rows.querySelectorAll('tr[data-id]').forEach(tr => {
        tr.addEventListener('click', () => showDetail(tr.dataset.id));
      });
    } catch (e) {
      if (sub) sub.textContent = 'error';
      rows.innerHTML = `<tr><td colspan="7" style="padding:18px;text-align:center;color:var(--red)">✗ ${esc(e.message)}</td></tr>`;
    }
  }

  // ── detail ───────────────────────────────────────────────────────────
  let _currentScan = null;
  let _detailInterval = null;

  async function showDetail(id) {
    _currentScan = null;
    const m = $('dast-detail-modal'); m.style.display = 'flex';
    $('dast-md-title').textContent = 'Loading…';
    $('dast-md-body').innerHTML = '<div style="padding:24px;text-align:center;color:var(--t3)">loading…</div>';
    $('dast-md-cancel').onclick = async () => {
      if (!_currentScan) return;
      try {
        await api('/scans/' + encodeURIComponent(_currentScan.id) + '/cancel', { method: 'POST' });
        toast('Cancel requested', 'info');
      } catch (e) { toast('Cancel failed: ' + e.message, 'error'); }
    };
    $('dast-md-delete').onclick = async () => {
      if (!_currentScan) return;
      if (!confirm('Delete scan record?')) return;
      try {
        await api('/scans/' + encodeURIComponent(_currentScan.id), { method: 'DELETE' });
        toast('Deleted', 'success');
        m.style.display = 'none';
        refreshAll();
      } catch (e) { toast('Delete failed: ' + e.message, 'error'); }
    };

    if (_detailInterval) clearInterval(_detailInterval);
    const load = async () => {
      try {
        _currentScan = await api('/scans/' + encodeURIComponent(id));
        renderDetail();
        if (_currentScan.status === 'running' || _currentScan.status === 'queued') {
          // Continue polling
        } else {
          if (_detailInterval) { clearInterval(_detailInterval); _detailInterval = null; }
        }
      } catch (e) {
        $('dast-md-body').innerHTML = `<div style="padding:24px;color:var(--red)">✗ ${esc(e.message)}</div>`;
        if (_detailInterval) { clearInterval(_detailInterval); _detailInterval = null; }
      }
    };
    await load();
    _detailInterval = setInterval(load, 2_000);
    // Stop polling when modal closes
    m.addEventListener('click', function clearOnClose(e) {
      if (e.target === m) {
        if (_detailInterval) { clearInterval(_detailInterval); _detailInterval = null; }
        m.removeEventListener('click', clearOnClose);
      }
    }, { once: false });
  }

  function renderDetail() {
    const s = _currentScan; if (!s) return;
    $('dast-md-title').innerHTML = `${esc(s.target)} ${statusPill(s.status)}`;
    $('dast-md-sub').innerHTML = `Profile: ${profileBadge(s.profile)} · Started ${fmtTime(s.started_at)} · Duration ${fmtDuration(s.duration_ms)}`;
    $('dast-md-cancel').style.display = (s.status === 'running' || s.status === 'queued') ? 'inline-block' : 'none';

    const findings = s.findings || [];
    let html = `
      <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:14px">
        <div style="padding:10px;background:var(--bg3);border-radius:4px;text-align:center">
          <div style="font-size:9px;color:var(--t3);text-transform:uppercase">Total</div>
          <div style="font-size:22px;font-weight:700;color:var(--t1);font-family:var(--display)">${s.stats?.total || 0}</div>
        </div>
        <div style="padding:10px;background:rgba(239,68,68,0.1);border-radius:4px;text-align:center">
          <div style="font-size:9px;color:var(--red);text-transform:uppercase">Critical</div>
          <div style="font-size:22px;font-weight:700;color:var(--red);font-family:var(--display)">${s.stats?.critical || 0}</div>
        </div>
        <div style="padding:10px;background:rgba(249,115,22,0.1);border-radius:4px;text-align:center">
          <div style="font-size:9px;color:var(--orange);text-transform:uppercase">High</div>
          <div style="font-size:22px;font-weight:700;color:var(--orange);font-family:var(--display)">${s.stats?.high || 0}</div>
        </div>
        <div style="padding:10px;background:rgba(245,158,11,0.1);border-radius:4px;text-align:center">
          <div style="font-size:9px;color:var(--amber);text-transform:uppercase">Medium</div>
          <div style="font-size:22px;font-weight:700;color:var(--amber);font-family:var(--display)">${s.stats?.medium || 0}</div>
        </div>
        <div style="padding:10px;background:rgba(6,182,212,0.1);border-radius:4px;text-align:center">
          <div style="font-size:9px;color:var(--cyan);text-transform:uppercase">Low+Info</div>
          <div style="font-size:22px;font-weight:700;color:var(--cyan);font-family:var(--display)">${(s.stats?.low || 0) + (s.stats?.info || 0)}</div>
        </div>
      </div>
    `;
    if (s.error) {
      html += `<div style="padding:12px;background:rgba(239,68,68,0.1);border-left:3px solid var(--red);
                   border-radius:4px;margin-bottom:14px;font-family:var(--font-mono);font-size:11px;color:var(--red)">
                 <b>Error:</b> ${esc(s.error)}
               </div>`;
    }
    if (s.status === 'running' || s.status === 'queued') {
      html += `<div style="padding:12px;background:var(--cyan2);border-radius:4px;margin-bottom:14px;color:var(--cyan);font-size:12px">
                 ▶ Scan in progress — polling every 2s. Findings appear live below as nuclei discovers them.
               </div>`;
    }

    if (findings.length === 0 && s.status === 'done') {
      html += `<div style="padding:24px;text-align:center;color:var(--green);background:var(--bg3);border-radius:4px">
                 <div style="font-size:32px">✓</div>
                 <div style="margin-top:8px">No findings — target is clean against the selected ruleset.</div>
               </div>`;
    } else if (findings.length > 0) {
      // Sort by severity desc, then CVSS desc
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const sorted = [...findings].sort((a, b) => {
        const oa = order[a.severity] ?? 5; const ob = order[b.severity] ?? 5;
        if (oa !== ob) return oa - ob;
        return (b.cvss || 0) - (a.cvss || 0);
      });
      html += `<div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px">${findings.length} findings</div>`;
      html += sorted.map(f => `
        <div style="padding:12px;border:1px solid var(--border);border-radius:4px;margin-bottom:8px;background:var(--bg3)">
          <div style="display:flex;justify-content:space-between;align-items:start;gap:10px">
            <div style="flex:1">
              <div style="font-size:13px;font-weight:600;color:var(--t1)">${esc(f.template_name || f.template_id)}</div>
              <div style="font-size:10px;color:var(--t3);font-family:var(--font-mono);margin-top:2px">${esc(f.template_id)}</div>
              ${f.description ? `<div style="font-size:11px;color:var(--t2);margin-top:6px">${esc(f.description)}</div>` : ''}
              <div style="font-size:10px;color:var(--cyan);font-family:var(--font-mono);margin-top:6px">${esc(f.matched || f.url)}</div>
              ${(f.cve || []).length ? `<div style="font-size:10px;margin-top:6px">${f.cve.map(c => `<span style="font-family:var(--font-mono);color:var(--amber);background:rgba(245,158,11,0.12);padding:1px 6px;border-radius:3px;margin-right:4px">${esc(c)}</span>`).join('')}</div>` : ''}
              ${(f.tags || []).length ? `<div style="font-size:9px;margin-top:4px;color:var(--t3)">${f.tags.map(t => `<span style="margin-right:8px">#${esc(t)}</span>`).join('')}</div>` : ''}
            </div>
            <div style="text-align:right;flex-shrink:0">
              ${sevPill(f.severity)}
              ${f.cvss ? `<div style="font-size:11px;font-family:var(--font-mono);color:var(--t2);margin-top:6px">CVSS ${f.cvss}</div>` : ''}
            </div>
          </div>
          ${(f.reference || []).length ? `
            <div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border);font-size:10px">
              ${f.reference.slice(0,3).map(r => `<a href="${esc(r)}" target="_blank" style="color:var(--cyan);font-family:var(--font-mono);margin-right:10px">${esc(r.length > 60 ? r.slice(0,60)+'…' : r)}</a>`).join('')}
            </div>` : ''}
        </div>
      `).join('');
    }

    if (s.raw_output) {
      html += `<details style="margin-top:14px">
                 <summary style="cursor:pointer;font-size:11px;color:var(--t3)">Raw nuclei output (debug)</summary>
                 <pre style="font-family:var(--font-mono);font-size:10px;background:var(--bg3);padding:10px;border-radius:4px;margin-top:6px;max-height:240px;overflow:auto">${esc(s.raw_output)}</pre>
               </details>`;
    }

    $('dast-md-body').innerHTML = html;
  }

  // ── boot + animations ────────────────────────────────────────────────
  if (!document.getElementById('dast-style')) {
    const style = document.createElement('style');
    style.id = 'dast-style';
    style.textContent = `
      @keyframes dast-pulse {
        0%   { transform: translateX(-100%); }
        100% { transform: translateX(200%); }
      }
    `;
    document.head.appendChild(style);
  }

  function boot() {
    const p = findPanel();
    if (!p) { setTimeout(boot, 600); return; }
    mount(p);
    const obs = new MutationObserver(() => {
      const pp = findPanel();
      if (pp && pp.dataset.dastWired !== '1') mount(pp);
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.VSPDast = { refresh: refreshAll, api, apiBase: API_BASE };
  (window.VSP_DEBUG && console.log('[vsp-dast] panel wired — backend:', API_BASE));
})();
