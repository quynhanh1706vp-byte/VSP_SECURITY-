/**
 * VSP Compliance Table Patch v1.0
 * Nâng cấp FedRAMP / CMMC controls table:
 *  - Badge PASS / WARN / FAIL rõ màu + icon
 *  - Search + filter by status / family
 *  - Phân trang (25 rows/page)
 *  - Row click → detail modal
 *  - Summary bar (pass/warn/fail count)
 *
 * Inject vào p4_compliance.html TRƯỚC </body>
 */

(function VSPComplianceTablePatch() {

  /* ─── 0. INJECT CSS ─────────────────────────────────────────────────── */
  const style = document.createElement('style');
  style.textContent = `
/* ── Controls table wrapper ─────────────────────────── */
#ctrl-table-wrap {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
  margin-top: 14px;
}

/* ── Toolbar ─────────────────────────────────────────── */
#ctrl-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
}
#ctrl-search {
  flex: 1;
  min-width: 160px;
  background: var(--bg3, #0b0c0f);
  border: 1px solid var(--border2);
  border-radius: 6px;
  color: var(--t1);
  font-family: var(--mono);
  font-size: 11px;
  padding: 6px 10px;
  outline: none;
  transition: border-color .15s;
}
#ctrl-search:focus { border-color: var(--cyan); }
#ctrl-search::placeholder { color: var(--t3); }

.ctrl-filter-btn {
  font-family: var(--mono);
  font-size: 11px;
  padding: 5px 11px;
  border-radius: 5px;
  cursor: pointer;
  border: 1px solid var(--border2);
  background: transparent;
  color: var(--t2);
  transition: all .15s;
}
.ctrl-filter-btn:hover  { background: var(--border); color: var(--t1); }
.ctrl-filter-btn.active { color: var(--t1); }
.ctrl-filter-btn.f-all.active  { background: rgba(255,255,255,.08); border-color: rgba(255,255,255,.2); }
.ctrl-filter-btn.f-pass.active { background: var(--green-d); border-color: rgba(0,255,163,.35); color: var(--green); }
.ctrl-filter-btn.f-warn.active { background: var(--amber-d); border-color: rgba(255,184,0,.35); color: var(--amber); }
.ctrl-filter-btn.f-fail.active { background: var(--red-d);   border-color: rgba(255,69,69,.35);  color: var(--red); }

#ctrl-family-select {
  background: var(--bg3, #0b0c0f);
  border: 1px solid var(--border2);
  border-radius: 6px;
  color: var(--t2);
  font-family: var(--mono);
  font-size: 11px;
  padding: 5px 8px;
  outline: none;
  cursor: pointer;
}
#ctrl-family-select:focus { border-color: var(--cyan); }

/* ── Summary bar ─────────────────────────────────────── */
#ctrl-summary-bar {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 11px;
}
.ctrl-sum-item { display: flex; align-items: center; gap: 6px; }
.ctrl-sum-dot  { width: 8px; height: 8px; border-radius: 50%; }
.ctrl-sum-num  { font-family: var(--mono); font-weight: 700; font-size: 13px; }
.ctrl-sum-lbl  { color: var(--t3); font-size: 10px; }
.ctrl-sum-pct  { margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--t3); }

/* ── Table ───────────────────────────────────────────── */
#ctrl-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
#ctrl-table thead th {
  text-align: left;
  padding: 8px 12px;
  font-size: 10px;
  color: var(--t3);
  font-family: var(--mono);
  letter-spacing: .06em;
  text-transform: uppercase;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  user-select: none;
  cursor: pointer;
}
#ctrl-table thead th:hover { color: var(--t1); }
#ctrl-table thead th .sort-icon { margin-left: 4px; opacity: .4; }
#ctrl-table thead th.sorted .sort-icon { opacity: 1; color: var(--cyan); }

#ctrl-table tbody tr {
  border-bottom: 1px solid var(--border);
  transition: background .1s;
  cursor: pointer;
}
#ctrl-table tbody tr:last-child { border-bottom: none; }
#ctrl-table tbody tr:hover { background: rgba(255,255,255,.03); }
#ctrl-table tbody td { padding: 9px 12px; vertical-align: middle; }

/* ── Status badges ───────────────────────────────────── */
.ctrl-status {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 700;
  padding: 3px 9px;
  border-radius: 4px;
  letter-spacing: .04em;
  white-space: nowrap;
}
.ctrl-status-pass { background: var(--green-d); color: var(--green); border: 1px solid rgba(0,255,163,.25); }
.ctrl-status-warn { background: var(--amber-d); color: var(--amber); border: 1px solid rgba(255,184,0,.25); }
.ctrl-status-fail { background: var(--red-d);   color: var(--red);   border: 1px solid rgba(255,69,69,.25); }
.ctrl-status-pass::before { content: '✓'; }
.ctrl-status-warn::before { content: '⚠'; }
.ctrl-status-fail::before { content: '✗'; }

/* ── Pagination ──────────────────────────────────────── */
#ctrl-pagination {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 10px 14px;
  border-top: 1px solid var(--border);
  justify-content: space-between;
}
.ctrl-page-info { font-size: 11px; color: var(--t3); font-family: var(--mono); }
.ctrl-page-btns { display: flex; gap: 4px; }
.ctrl-page-btn {
  font-family: var(--mono);
  font-size: 11px;
  padding: 4px 9px;
  border-radius: 5px;
  cursor: pointer;
  border: 1px solid var(--border2);
  background: transparent;
  color: var(--t2);
  transition: all .12s;
  min-width: 30px;
  text-align: center;
}
.ctrl-page-btn:hover    { background: var(--border); color: var(--t1); }
.ctrl-page-btn.active   { background: var(--cyan-d); color: var(--cyan); border-color: rgba(0,229,255,.35); }
.ctrl-page-btn:disabled { opacity: .3; cursor: default; }

/* ── Control detail modal ────────────────────────────── */
#ctrl-detail-overlay {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 9100;
  background: rgba(0,0,0,.75);
  backdrop-filter: blur(4px);
  align-items: center;
  justify-content: center;
  padding: 20px;
}
#ctrl-detail-overlay.open { display: flex; }
#ctrl-detail-box {
  background: var(--bg3, #0b0c0f);
  border: 1px solid var(--border2);
  border-radius: 12px;
  width: min(640px, 100%);
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 32px 80px rgba(0,0,0,.7);
}
#ctrl-detail-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
}
#ctrl-detail-body {
  padding: 18px 20px;
  overflow-y: auto;
  flex: 1;
}
.ctrl-detail-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  gap: 16px;
}
.ctrl-detail-row:last-child { border-bottom: none; }
.ctrl-detail-key {
  font-size: 10px;
  color: var(--t3);
  font-family: var(--mono);
  text-transform: uppercase;
  letter-spacing: .06em;
  flex-shrink: 0;
  min-width: 120px;
  padding-top: 1px;
}
.ctrl-detail-val {
  font-size: 12px;
  color: var(--t1);
  text-align: right;
  flex: 1;
}
.ctrl-detail-tools-list {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.ctrl-tool-tag {
  font-family: var(--mono);
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--purple-d);
  color: var(--purple);
  border: 1px solid rgba(157,111,255,.2);
}
#ctrl-detail-close {
  background: none;
  border: none;
  color: var(--t3);
  font-size: 16px;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: 4px;
  transition: color .12s;
  line-height: 1;
}
#ctrl-detail-close:hover { color: var(--t1); background: var(--border); }
`;
  document.head.appendChild(style);

  /* ─── 1. CREATE MODAL DOM ──────────────────────────────────────────── */
  const overlay = document.createElement('div');
  overlay.id = 'ctrl-detail-overlay';
  overlay.innerHTML = `
    <div id="ctrl-detail-box">
      <div id="ctrl-detail-head">
        <div>
          <div style="font-size:10px;color:var(--cyan);font-family:var(--mono);letter-spacing:.08em;margin-bottom:4px" id="ctrl-detail-fw">—</div>
          <div style="font-size:15px;font-weight:700;color:var(--t1)" id="ctrl-detail-title">—</div>
          <div style="font-size:11px;color:var(--t3);margin-top:2px" id="ctrl-detail-sub">—</div>
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <span id="ctrl-detail-badge" class="ctrl-status"></span>
          <button id="ctrl-detail-close" onclick="document.getElementById('ctrl-detail-overlay').classList.remove('open')">✕</button>
        </div>
      </div>
      <div id="ctrl-detail-body">
        <div id="ctrl-detail-rows"></div>
        <div style="margin-top:14px;display:flex;gap:8px;justify-content:flex-end">
          <button class="ctrl-filter-btn f-fail" onclick="document.getElementById('ctrl-detail-overlay').classList.remove('open')" style="font-size:11px">Close</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('open'); });

  /* ─── 2. PATCH renderTests (Pipeline tab) ─────────────────────────── */
  const _origRenderTests = window.renderTests;
  window.renderTests = function(tests) {
    if (_origRenderTests) _origRenderTests(tests);
  };

  /* ─── 3. INJECT FedRAMP / CMMC controls table into Overview tab ────── */
  // Intercept loadOverview to append the enhanced table after it runs
  const _origLoadOverview = window.loadOverview;
  window.loadOverview = async function() {
    if (_origLoadOverview) await _origLoadOverview();
    await injectControlsTable();
  };

  /* ─── 4. CONTROLS TABLE ENGINE ────────────────────────────────────── */
  let _ctrlData   = [];   // all rows
  let _ctrlFiltered = []; // after filter/search
  let _ctrlPage   = 1;
  const PAGE_SIZE  = 25;
  let _ctrlFilter  = 'all';
  let _ctrlFamily  = 'all';
  let _ctrlSort    = { col: 'id', dir: 1 };

  async function injectControlsTable() {
    // Find or create mount point after the Zero Trust pillars section
    let mount = document.getElementById('ctrl-table-mount');
    if (!mount) {
      const ovPanel = document.getElementById('tab-overview');
      if (!ovPanel) return;
      mount = document.createElement('div');
      mount.id = 'ctrl-table-mount';
      mount.style.marginTop = '20px';
      ovPanel.appendChild(mount);
    }

    mount.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <div style="font-size:11px;font-weight:700;color:var(--t2);letter-spacing:.08em;text-transform:uppercase">
          ▸ FedRAMP / CMMC — Controls Detail
        </div>
        <div style="display:flex;gap:6px">
          <button class="ctrl-filter-btn" onclick="window._ctrlRefresh && window._ctrlRefresh()" style="font-size:10px">↺ Reload</button>
        </div>
      </div>
      <div id="ctrl-table-wrap">
        <div id="ctrl-toolbar">
          <input id="ctrl-search" placeholder="Search ID, control, family…" oninput="window._ctrlSearch(this.value)">
          <button class="ctrl-filter-btn f-all active" onclick="window._ctrlSetFilter('all',this)">All</button>
          <button class="ctrl-filter-btn f-pass"       onclick="window._ctrlSetFilter('pass',this)">PASS</button>
          <button class="ctrl-filter-btn f-warn"       onclick="window._ctrlSetFilter('warn',this)">WARN</button>
          <button class="ctrl-filter-btn f-fail"       onclick="window._ctrlSetFilter('fail',this)">FAIL</button>
          <select id="ctrl-family-select" onchange="window._ctrlSetFamily(this.value)">
            <option value="all">All Families</option>
          </select>
        </div>
        <div id="ctrl-summary-bar">
          <div class="ctrl-sum-item">
            <div class="ctrl-sum-dot" style="background:var(--green)"></div>
            <span class="ctrl-sum-num" id="cs-pass" style="color:var(--green)">—</span>
            <span class="ctrl-sum-lbl">PASS</span>
          </div>
          <div class="ctrl-sum-item">
            <div class="ctrl-sum-dot" style="background:var(--amber)"></div>
            <span class="ctrl-sum-num" id="cs-warn" style="color:var(--amber)">—</span>
            <span class="ctrl-sum-lbl">WARN</span>
          </div>
          <div class="ctrl-sum-item">
            <div class="ctrl-sum-dot" style="background:var(--red)"></div>
            <span class="ctrl-sum-num" id="cs-fail" style="color:var(--red)">—</span>
            <span class="ctrl-sum-lbl">FAIL</span>
          </div>
          <div class="ctrl-sum-item">
            <div class="ctrl-sum-dot" style="background:var(--t3)"></div>
            <span class="ctrl-sum-num" id="cs-total" style="color:var(--t2)">—</span>
            <span class="ctrl-sum-lbl">TOTAL</span>
          </div>
          <div class="ctrl-sum-pct" id="cs-pct">—</div>
        </div>
        <div style="overflow-x:auto">
          <table id="ctrl-table">
            <thead>
              <tr>
                <th onclick="window._ctrlSortBy('id')"        data-col="id">ID <span class="sort-icon">↕</span></th>
                <th onclick="window._ctrlSortBy('family')"    data-col="family">Family <span class="sort-icon">↕</span></th>
                <th onclick="window._ctrlSortBy('control')"   data-col="control">Control <span class="sort-icon">↕</span></th>
                <th>Tools</th>
                <th onclick="window._ctrlSortBy('status')"    data-col="status">Status <span class="sort-icon">↕</span></th>
              </tr>
            </thead>
            <tbody id="ctrl-tbody">
              <tr><td colspan="5" style="text-align:center;padding:24px;color:var(--t3);font-size:11px">
                <span class="spinner"></span> Loading controls…
              </td></tr>
            </tbody>
          </table>
        </div>
        <div id="ctrl-pagination"></div>
      </div>`;

    // Wire up globals
    window._ctrlSetFilter = function(f, btn) {
      _ctrlFilter = f;
      document.querySelectorAll('.ctrl-filter-btn').forEach(b => {
        if (['f-all','f-pass','f-warn','f-fail'].some(c => b.classList.contains(c))) b.classList.remove('active');
      });
      if (btn) btn.classList.add('active');
      _ctrlPage = 1;
      _ctrlApplyAndRender();
    };
    window._ctrlSetFamily = function(v) { _ctrlFamily = v; _ctrlPage = 1; _ctrlApplyAndRender(); };
    window._ctrlSearch   = function(q)  { _ctrlPage = 1; _ctrlApplyAndRender(q); };
    window._ctrlSortBy   = function(col) {
      if (_ctrlSort.col === col) _ctrlSort.dir *= -1;
      else { _ctrlSort.col = col; _ctrlSort.dir = 1; }
      _ctrlApplyAndRender();
    };
    window._ctrlRefresh = loadControlsData;

    loadControlsData();
  }

  async function loadControlsData() {
    // Wait for token if not ready yet (up to 3s)
    if (!window.TOKEN && !localStorage.getItem('vsp_token')) {
      await new Promise(resolve => {
        let attempts = 0;
        const check = setInterval(() => {
          attempts++;
          if (window.TOKEN || localStorage.getItem('vsp_token') || attempts > 30) {
            clearInterval(check); resolve();
          }
        }, 100);
      });
    }
    // Try API first, fall back to demo data
    let rows = [];
    try {
      const apiBase = window.VSP_API_BASE || window.location.origin;
      const tok = window.TOKEN || localStorage.getItem('vsp_token') || '';
      const p4key = window.VSP_P4_API_KEY || '';
      const headers = tok ? {'Authorization': 'Bearer ' + tok}
                    : p4key ? {'X-API-Key': p4key} : {};
      const res = await fetch(apiBase + '/api/p4/pipeline/latest', { headers });
      if (res.ok) {
        const d = await res.json();
        if (d && d.tests && d.tests.length) {
          rows = d.tests.map(t => ({
            id:       t.control_id || t.id || '—',
            family:   familyFromID(t.control_id || ''),
            control:  t.name || '—',
            tools:    t.tools || toolsFromEvidence(t.evidence || ''),
            status:   (t.status || 'fail').toLowerCase(),
            score:    t.score || 0,
            evidence: t.evidence || '—',
            framework:t.framework || '—',
            autofix:  t.auto_fix_available || false,
          }));
        }
      }
    } catch(_) {}

    // Fallback demo data if API unavailable
    if (!rows.length) {
      rows = DEMO_CONTROLS;
    }

    _ctrlData = rows;
    populateFamilySelect(rows);
    _ctrlApplyAndRender();
  }

  function familyFromID(id) {
    const m = id.match(/^([A-Z]{1,3})/);
    if (!m) return '—';
    const map = {
      AC:'Access Control', AU:'Audit', CM:'Config Mgmt', IA:'Ident & Auth',
      IR:'Incident Resp', MA:'Maintenance', MP:'Media Prot', PE:'Physical',
      PL:'Planning', PS:'Personnel', RA:'Risk Assessment', SA:'Sys & Svc Acq',
      SC:'Sys & Comms', SI:'Sys & Info Integ', SR:'Supply Chain',
    };
    return map[m[1]] || m[1];
  }

  function toolsFromEvidence(ev) {
    const found = [];
    ['bandit','semgrep','gitleaks','checkov','trivy','grype','nuclei','kics','sonarqube','tfsec'].forEach(t => {
      if (ev.toLowerCase().includes(t)) found.push(t);
    });
    return found.length ? found : ['—'];
  }

  function populateFamilySelect(rows) {
    const sel = document.getElementById('ctrl-family-select');
    if (!sel) return;
    const families = [...new Set(rows.map(r => r.family).filter(f => f && f !== '—'))].sort();
    const current = sel.value;
    sel.innerHTML = '<option value="all">All Families</option>' +
      families.map(f => `<option value="${f}"${f===current?' selected':''}>${f}</option>`).join('');
  }

  function _ctrlApplyAndRender(searchQ) {
    const q = (searchQ !== undefined ? searchQ : (document.getElementById('ctrl-search')?.value || '')).toLowerCase();

    let rows = _ctrlData.slice();

    // Filter status
    if (_ctrlFilter !== 'all') rows = rows.filter(r => r.status === _ctrlFilter);

    // Filter family
    if (_ctrlFamily !== 'all') rows = rows.filter(r => r.family === _ctrlFamily);

    // Search
    if (q) rows = rows.filter(r =>
      (r.id + r.family + r.control + (r.tools||[]).join('')).toLowerCase().includes(q)
    );

    // Sort
    rows.sort((a, b) => {
      let va = a[_ctrlSort.col] || '', vb = b[_ctrlSort.col] || '';
      if (typeof va === 'number') return (va - vb) * _ctrlSort.dir;
      return String(va).localeCompare(String(vb)) * _ctrlSort.dir;
    });

    _ctrlFiltered = rows;

    // Update sort icons
    document.querySelectorAll('#ctrl-table thead th[data-col]').forEach(th => {
      th.classList.toggle('sorted', th.dataset.col === _ctrlSort.col);
      const icon = th.querySelector('.sort-icon');
      if (icon) icon.textContent = th.dataset.col === _ctrlSort.col ? (_ctrlSort.dir === 1 ? '↑' : '↓') : '↕';
    });

    updateSummaryBar();
    renderPage(_ctrlPage);
    renderPagination();
  }

  function updateSummaryBar() {
    const all   = _ctrlData;
    const pass  = all.filter(r => r.status === 'pass').length;
    const warn  = all.filter(r => r.status === 'warn').length;
    const fail  = all.filter(r => r.status === 'fail').length;
    const total = all.length;
    const pct   = total ? Math.round((pass / total) * 100) : 0;

    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('cs-pass',  pass);
    set('cs-warn',  warn);
    set('cs-fail',  fail);
    set('cs-total', total);
    set('cs-pct',   `${pct}% pass · ${_ctrlFiltered.length} shown`);
  }

  function renderPage(page) {
    _ctrlPage = page;
    const start = (page - 1) * PAGE_SIZE;
    const slice = _ctrlFiltered.slice(start, start + PAGE_SIZE);
    const tbody = document.getElementById('ctrl-tbody');
    if (!tbody) return;

    if (!slice.length) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--t3);font-size:11px">
        No controls match current filter</td></tr>`;
      return;
    }

    tbody.innerHTML = slice.map((r, i) => {
      const statusClass = r.status === 'pass' ? 'ctrl-status-pass' : r.status === 'warn' ? 'ctrl-status-warn' : 'ctrl-status-fail';
      const statusLabel = r.status.toUpperCase();
      const tools = Array.isArray(r.tools) ? r.tools : [r.tools || '—'];
      const toolsHtml = tools.filter(t => t && t !== '—').map(t =>
        `<span style="font-family:var(--mono);font-size:10px;color:var(--t3);background:rgba(255,255,255,.05);padding:1px 5px;border-radius:3px">${t}</span>`
      ).join(' ') || '<span style="color:var(--t3);font-size:11px">—</span>';

      return `<tr onclick="window._ctrlOpenDetail(${start + i})">
        <td style="font-family:var(--mono);font-size:11px;color:var(--cyan);white-space:nowrap">${r.id}</td>
        <td style="font-size:11px;color:var(--t3)">${r.family}</td>
        <td style="font-size:12px;max-width:280px">${r.control}</td>
        <td>${toolsHtml}</td>
        <td><span class="ctrl-status ${statusClass}">${statusLabel}</span></td>
      </tr>`;
    }).join('');
  }

  function renderPagination() {
    const total = _ctrlFiltered.length;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const el = document.getElementById('ctrl-pagination');
    if (!el) return;

    const start = (_ctrlPage - 1) * PAGE_SIZE + 1;
    const end   = Math.min(_ctrlPage * PAGE_SIZE, total);

    // Build page buttons (show max 7 around current)
    let btns = '';
    const range = 3;
    for (let p = 1; p <= pages; p++) {
      if (p === 1 || p === pages || (p >= _ctrlPage - range && p <= _ctrlPage + range)) {
        btns += `<button class="ctrl-page-btn${p === _ctrlPage ? ' active' : ''}" onclick="window._ctrlGoPage(${p})">${p}</button>`;
      } else if (p === _ctrlPage - range - 1 || p === _ctrlPage + range + 1) {
        btns += `<span style="font-size:11px;color:var(--t3);padding:4px 2px;align-self:center">…</span>`;
      }
    }

    el.innerHTML = `
      <div class="ctrl-page-info">${total === 0 ? 'No results' : `${start}–${end} of ${total}`}</div>
      <div class="ctrl-page-btns">
        <button class="ctrl-page-btn" onclick="window._ctrlGoPage(${_ctrlPage - 1})" ${_ctrlPage <= 1 ? 'disabled' : ''}>‹</button>
        ${btns}
        <button class="ctrl-page-btn" onclick="window._ctrlGoPage(${_ctrlPage + 1})" ${_ctrlPage >= pages ? 'disabled' : ''}>›</button>
      </div>`;
  }

  window._ctrlGoPage = function(p) {
    const pages = Math.ceil(_ctrlFiltered.length / PAGE_SIZE);
    if (p < 1 || p > pages) return;
    _ctrlPage = p;
    renderPage(_ctrlPage);
    renderPagination();
    document.getElementById('ctrl-table-wrap')?.scrollIntoView({ behavior:'smooth', block:'nearest' });
  };

  window._ctrlOpenDetail = function(idx) {
    const r = _ctrlFiltered[idx];
    if (!r) return;
    const overlay = document.getElementById('ctrl-detail-overlay');
    if (!overlay) return;

    const statusClass = r.status === 'pass' ? 'ctrl-status-pass' : r.status === 'warn' ? 'ctrl-status-warn' : 'ctrl-status-fail';
    document.getElementById('ctrl-detail-fw').textContent    = r.framework || 'FedRAMP / CMMC';
    document.getElementById('ctrl-detail-title').textContent = r.control   || '—';
    document.getElementById('ctrl-detail-sub').textContent   = r.id        || '—';

    const badge = document.getElementById('ctrl-detail-badge');
    badge.className = 'ctrl-status ' + statusClass;
    badge.textContent = r.status.toUpperCase();

    const tools = Array.isArray(r.tools) ? r.tools : [r.tools || '—'];
    const toolsHtml = tools.filter(t => t && t !== '—').map(t =>
      `<span class="ctrl-tool-tag">${t}</span>`
    ).join('') || '<span style="color:var(--t3)">—</span>';

    document.getElementById('ctrl-detail-rows').innerHTML = [
      ['Control ID',  `<span style="font-family:var(--mono);color:var(--cyan)">${r.id}</span>`],
      ['Family',       r.family || '—'],
      ['Framework',    r.framework || '—'],
      ['Status',       `<span class="ctrl-status ${statusClass}">${r.status.toUpperCase()}</span>`],
      ['Score',        r.score !== undefined ? `<span style="font-family:var(--mono);color:${r.score>=80?'var(--green)':r.score>=50?'var(--amber)':'var(--red)'}">${r.score}/100</span>` : '—'],
      ['Tools',        `<div class="ctrl-detail-tools-list">${toolsHtml}</div>`],
      ['Evidence',     `<span style="font-size:11px;color:var(--t2)">${r.evidence || '—'}</span>`],
      ['Auto-fix',     r.autofix ? '<span style="color:var(--cyan)">⚡ Available</span>' : '<span style="color:var(--t3)">Not available</span>'],
    ].map(([k, v]) => `
      <div class="ctrl-detail-row">
        <div class="ctrl-detail-key">${k}</div>
        <div class="ctrl-detail-val">${v}</div>
      </div>`).join('');

    overlay.classList.add('open');
  };

  /* ─── 5. ALSO PATCH renderTests for Pipeline tab ──────────────────── */
  window.renderTests = function(tests) {
    const el = document.getElementById('tests-list');
    if (!el) return;
    el.innerHTML = tests.map(t => {
      const st = (t.status || 'fail').toLowerCase();
      const sc = st === 'pass' ? 'ctrl-status-pass' : st === 'warn' ? 'ctrl-status-warn' : 'ctrl-status-fail';
      const tools = toolsFromEvidence(t.evidence || '');
      const toolsHtml = tools.filter(x => x !== '—').map(x =>
        `<span style="font-family:var(--mono);font-size:10px;color:var(--t3);background:rgba(255,255,255,.05);padding:1px 5px;border-radius:3px">${x}</span>`
      ).join(' ') || '';
      return `
        <div class="test-row" style="cursor:pointer" onclick="window._ctrlOpenDetailFromTest(${JSON.stringify(t).replace(/"/g,'&quot;')})">
          <span class="test-fw">${t.framework || '—'}</span>
          <span class="test-ctrl" style="font-family:var(--mono);color:var(--cyan)">${t.control_id || '—'}</span>
          <span class="test-name" style="flex:1">${t.name || '—'}</span>
          <span style="display:flex;gap:4px">${toolsHtml}</span>
          <span class="ctrl-status ${sc}">${st.toUpperCase()}</span>
          <span class="test-score" style="color:${t.score>=80?'var(--green)':t.score>=50?'var(--amber)':'var(--red)'};font-family:var(--mono)">${t.score}</span>
          ${t.auto_fix_available ? '<span style="font-size:10px;color:var(--cyan)">⚡</span>' : ''}
        </div>`;
    }).join('');
  };

  window._ctrlOpenDetailFromTest = function(t) {
    const r = {
      id:        t.control_id || t.id || '—',
      family:    familyFromID(t.control_id || ''),
      control:   t.name || '—',
      tools:     toolsFromEvidence(t.evidence || ''),
      status:    (t.status || 'fail').toLowerCase(),
      score:     t.score || 0,
      evidence:  t.evidence || '—',
      framework: t.framework || '—',
      autofix:   t.auto_fix_available || false,
    };
    _ctrlFiltered = [r];
    window._ctrlOpenDetail(0);
  };

  /* ─── 6. DEMO DATA (fallback khi không có API) ─────────────────────── */
  const DEMO_CONTROLS = [
    {id:'AC-2', family:'Access Control',  control:'Account Management',              tools:['bandit','semgrep'],  status:'warn', score:72, evidence:'bandit: 2 issues found', framework:'FedRAMP', autofix:false},
    {id:'AC-3', family:'Access Control',  control:'Access Enforcement',               tools:['bandit','semgrep'],  status:'warn', score:68, evidence:'semgrep: RBAC gaps',      framework:'FedRAMP', autofix:false},
    {id:'AC-6', family:'Access Control',  control:'Least Privilege',                  tools:['checkov','kics'],   status:'fail', score:35, evidence:'checkov: overprivileged IAM roles', framework:'FedRAMP', autofix:true},
    {id:'AC-12',family:'Access Control',  control:'Session Termination',              tools:['semgrep','bandit'], status:'warn', score:65, evidence:'semgrep: no session expiry', framework:'FedRAMP', autofix:false},
    {id:'AC-17',family:'Access Control',  control:'Remote Access',                    tools:['nuclei','kics'],    status:'fail', score:42, evidence:'nuclei: VPN not enforced',  framework:'FedRAMP', autofix:false},
    {id:'AC-18',family:'Access Control',  control:'Wireless Access',                  tools:['kics','checkov'],   status:'fail', score:30, evidence:'checkov: open wireless policy',framework:'FedRAMP', autofix:true},
    {id:'AC-19',family:'Access Control',  control:'Access Control for Mobile',        tools:['kics'],             status:'fail', score:25, evidence:'kics: MDM not configured',  framework:'FedRAMP', autofix:false},
    {id:'AC-20',family:'Access Control',  control:'External Systems',                 tools:['kics','checkov'],   status:'fail', score:38, evidence:'checkov: external access uncontrolled',framework:'FedRAMP', autofix:false},
    {id:'AC-22',family:'Access Control',  control:'Publicly Accessible Content',      tools:['nuclei','semgrep'], status:'fail', score:45, evidence:'nuclei: public S3 bucket detected',framework:'FedRAMP', autofix:true},
    {id:'AU-2', family:'Audit',           control:'Event Logging',                    tools:['bandit','semgrep'], status:'warn', score:78, evidence:'bandit: logging incomplete', framework:'FedRAMP', autofix:false},
    {id:'AU-3', family:'Audit',           control:'Content of Audit Records',         tools:['bandit'],           status:'warn', score:70, evidence:'bandit: missing audit fields',framework:'FedRAMP', autofix:false},
    {id:'AU-6', family:'Audit',           control:'Audit Record Review',              tools:['bandit','semgrep'], status:'warn', score:74, evidence:'semgrep: review not automated',framework:'FedRAMP', autofix:false},
    {id:'AU-9', family:'Audit',           control:'Protection of Audit Info',         tools:['bandit','gitleaks'],status:'fail', score:40, evidence:'gitleaks: log file writable by all',framework:'FedRAMP', autofix:false},
    {id:'AU-11',family:'Audit',           control:'Audit Record Retention',           tools:['kics','checkov'],   status:'fail', score:28, evidence:'checkov: retention < 90 days', framework:'FedRAMP', autofix:true},
    {id:'AU-12',family:'Audit',           control:'Audit Record Generation',          tools:['bandit','semgrep'], status:'warn', score:76, evidence:'semgrep: partial audit hooks',  framework:'FedRAMP', autofix:false},
    {id:'CM-2', family:'Config Mgmt',     control:'Baseline Configuration',           tools:['kics','checkov'],   status:'fail', score:44, evidence:'kics: no baseline documented',  framework:'FedRAMP', autofix:false},
    {id:'CM-3', family:'Config Mgmt',     control:'Configuration Change Control',     tools:['kics','checkov'],   status:'fail', score:50, evidence:'checkov: change process missing', framework:'FedRAMP', autofix:false},
    {id:'CM-4', family:'Config Mgmt',     control:'Impact Analysis',                  tools:['kics','semgrep'],   status:'fail', score:32, evidence:'semgrep: no impact analysis gate',framework:'FedRAMP', autofix:false},
    {id:'CM-5', family:'Config Mgmt',     control:'Access Restriction for Change',    tools:['kics','checkov'],   status:'fail', score:29, evidence:'checkov: unrestricted push to main',framework:'FedRAMP', autofix:true},
    {id:'CM-6', family:'Config Mgmt',     control:'Configuration Settings',           tools:['kics','checkov'],   status:'fail', score:48, evidence:'kics: insecure defaults',       framework:'FedRAMP', autofix:true},
    {id:'CM-7', family:'Config Mgmt',     control:'Least Functionality',              tools:['kics','checkov','nuclei'],status:'fail',score:35,evidence:'nuclei: unnecessary services',framework:'FedRAMP', autofix:false},
    {id:'CM-8', family:'Config Mgmt',     control:'System Component Inventory',       tools:['grype','trivy'],    status:'fail', score:42, evidence:'trivy: 18 untracked images',    framework:'FedRAMP', autofix:false},
    {id:'IA-2', family:'Ident & Auth',    control:'Identification & Auth (Users)',    tools:['bandit','semgrep'], status:'warn', score:80, evidence:'semgrep: MFA not enforced on all', framework:'FedRAMP', autofix:false},
    {id:'IA-3', family:'Ident & Auth',    control:'Device Identification',            tools:['kics'],             status:'fail', score:33, evidence:'kics: cert-based auth missing',  framework:'FedRAMP', autofix:false},
    {id:'IA-4', family:'Ident & Auth',    control:'Identifier Management',            tools:['bandit','semgrep'], status:'warn', score:72, evidence:'bandit: shared account detected',framework:'FedRAMP', autofix:false},
    {id:'IA-5', family:'Ident & Auth',    control:'Authenticator Management',         tools:['gitleaks','secretcheck'],status:'fail',score:20,evidence:'gitleaks: hardcoded credentials',framework:'FedRAMP', autofix:true},
    {id:'RA-5', family:'Risk Assessment', control:'Vulnerability Monitoring & Scan',  tools:['trivy','grype'],    status:'pass', score:92, evidence:'trivy: scan complete, 0 critical', framework:'FedRAMP', autofix:false},
    {id:'SA-3', family:'Sys & Svc Acq',  control:'System Development Life Cycle',    tools:['semgrep','bandit'], status:'pass', score:88, evidence:'semgrep: SDLC gates enforced',  framework:'FedRAMP', autofix:false},
    {id:'SC-7', family:'Sys & Comms',    control:'Boundary Protection',              tools:['checkov','nuclei'], status:'pass', score:95, evidence:'nuclei: firewall rules verified',  framework:'FedRAMP', autofix:false},
    {id:'SC-8', family:'Sys & Comms',    control:'Transmission Confidentiality',     tools:['nuclei','semgrep'], status:'pass', score:90, evidence:'nuclei: TLS 1.3 enforced',       framework:'FedRAMP', autofix:false},
    {id:'SC-28',family:'Sys & Comms',    control:'Protection of Info at Rest',       tools:['checkov','trivy'],  status:'pass', score:85, evidence:'checkov: encryption enabled',    framework:'FedRAMP', autofix:false},
    {id:'SI-2', family:'Sys & Info Integ',control:'Flaw Remediation',               tools:['trivy','grype'],    status:'pass', score:88, evidence:'trivy: patches current',          framework:'FedRAMP', autofix:false},
    {id:'SI-3', family:'Sys & Info Integ',control:'Malicious Code Protection',       tools:['bandit','semgrep'], status:'pass', score:82, evidence:'bandit: no malicious patterns',  framework:'FedRAMP', autofix:false},
    {id:'SI-10',family:'Sys & Info Integ',control:'Information Input Validation',    tools:['bandit','semgrep'], status:'pass', score:91, evidence:'semgrep: input validation rules', framework:'FedRAMP', autofix:false},
    {id:'MP-6', family:'Media Prot',     control:'Media Sanitization',               tools:['checkov'],          status:'warn', score:66, evidence:'checkov: media wipe policy gap',  framework:'CMMC', autofix:false},
    {id:'PE-2', family:'Physical',       control:'Physical Access Authorizations',   tools:['kics'],             status:'pass', score:85, evidence:'kics: PAM configured',            framework:'CMMC', autofix:false},
    {id:'IR-2', family:'Incident Resp',  control:'Incident Response Training',       tools:['semgrep'],          status:'pass', score:80, evidence:'semgrep: IRP documented',        framework:'CMMC', autofix:false},
    {id:'PS-3', family:'Personnel',      control:'Personnel Screening',              tools:['bandit'],           status:'pass', score:88, evidence:'bandit: screening policy enforced',framework:'CMMC', autofix:false},
    {id:'SR-3', family:'Supply Chain',   control:'SCRM Plan',                        tools:['trivy','grype'],    status:'warn', score:71, evidence:'trivy: 3 deps unverified origin', framework:'CMMC', autofix:false},
    {id:'SR-11',family:'Supply Chain',   control:'Component Authenticity',           tools:['trivy'],            status:'warn', score:68, evidence:'trivy: SBOM attestation missing', framework:'CMMC', autofix:false},
  ];

  console.log('[VSP ComplianceTable Patch v1.0] Loaded ✓');

})();
