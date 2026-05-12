/* vsp_scheduler_panel.js — Phase 7B
 * ─────────────────────────────────────────────────────────────────────────
 * VSP Scheduler frontend panel.
 *
 * Wires the Scheduler tab to backend microservice on :8092.
 *
 * Endpoints consumed:
 *   GET    /healthz
 *   GET    /jobs                  (list with computed next_run + last_status)
 *   GET    /jobs/{id}             (detail)
 *   POST   /jobs                  (create)
 *   PUT    /jobs/{id}             (update)
 *   DELETE /jobs/{id}             (delete)
 *   POST   /jobs/{id}/run         (trigger immediately)
 *   POST   /jobs/{id}/toggle      (enable/disable)
 *   GET    /jobs/{id}/runs        (run history)
 *   GET    /runs?since=...        (live activity feed)
 *   GET    /runs/{id}             (single run detail)
 *   GET    /preview?expr=...      (cron preview)
 *   GET    /stats                 (KPIs)
 *
 * Layout: KPI strip → activity heatmap → filters → jobs table → run feed.
 * Click row → detail modal w/ tabs (Overview, Cron preview, Run history, Output).
 * Cron picker: hybrid — preset modes + raw advanced.
 * ───────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  const API_BASE = (window.VSP_SCHEDULER_API || 'http://127.0.0.1:8092').replace(/\/$/, '');
  const TIMEOUT  = 30_000;

  // ── helpers ──────────────────────────────────────────────────────────
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function toast(m, k) {
    if (typeof window.showToast === 'function') return window.showToast(m, k || 'info');
    (window.VSP_DEBUG && console.log('[scheduler]', k || 'info', m));
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
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }
  function relTime(iso) {
    if (!iso || iso.startsWith('0001')) return '—';
    const d = new Date(iso);
    const ms = Date.now() - d.getTime();
    const a = Math.abs(ms);
    let s, suffix;
    if (ms >= 0) { s = a; suffix = 'ago'; }
    else         { s = a; suffix = 'from now'; }
    let n;
    if      (s < 60_000)        n = Math.floor(s / 1000)        + 's';
    else if (s < 3_600_000)     n = Math.floor(s / 60_000)      + 'm';
    else if (s < 86_400_000)    n = Math.floor(s / 3_600_000)   + 'h';
    else                        n = Math.floor(s / 86_400_000)  + 'd';
    return n + ' ' + suffix;
  }
  function fmtDuration(ms) {
    if (!ms) return '—';
    if (ms < 1000)    return ms + 'ms';
    if (ms < 60_000)  return (ms / 1000).toFixed(1) + 's';
    return Math.floor(ms / 60_000) + 'm ' + Math.floor((ms % 60_000) / 1000) + 's';
  }
  function statusPill(status) {
    const map = {
      pass:    ['var(--green)',  '✓ pass'],
      fail:    ['var(--red)',    '✗ fail'],
      warn:    ['var(--amber)',  '⚠ warn'],
      running: ['var(--cyan)',   '▶ running'],
      skipped: ['var(--t3)',     '· skipped'],
    };
    const [c, label] = map[status] || ['var(--t3)', '— ' + (status || '?')];
    return `<span style="font-family:var(--font-mono);font-size:10px;font-weight:700;
            color:${c};padding:2px 8px;border-radius:3px;
            background:${c.replace('var(', 'rgba(').replace(')', ',0.12)')};">${label}</span>`;
  }
  function typeIcon(type) {
    const map = {
      scan_image:   '🔍', sign_image:    '✍',
      verify_image: '✓',  attest_image:  '📜',
      cve_recheck:  '↻',  sbom_export:   '📦',
      webhook:      '🔗',
    };
    return map[type] || '•';
  }

  // ── panel discovery ──────────────────────────────────────────────────
  function findPanel() {
    return $('panel-scheduler')
        || $('panel-schedule')
        || $('panel-jobs')
        || document.querySelector('[data-panel="scheduler"]')
        || document.querySelector('[data-panel="schedule"]');
  }

  // ── mount ────────────────────────────────────────────────────────────
  function mount(panel) {
    if (panel.dataset.schedWired === '1') return;
    panel.dataset.schedWired = '1';

    panel.insertAdjacentHTML('afterbegin', `
      <div class="card mb14" id="sch-kpis-card">
        <div class="card-head">
          <div>
            <div class="card-title">Scheduler</div>
            <div class="card-sub">
              microservice <code style="color:var(--cyan);font-family:var(--font-mono)">${esc(API_BASE)}</code>
              · cron engine · auto-dispatch to Trivy/Cosign/SW-Inv
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center">
            <span id="sch-health" class="mono-sm" style="color:var(--t3)">checking…</span>
            <button class="btn btn-primary btn-sm" id="sch-btn-new">+ New job</button>
            <button class="btn btn-sm" id="sch-btn-refresh">⟳</button>
          </div>
        </div>

        <div style="padding:14px;display:grid;grid-template-columns:repeat(5,1fr);gap:10px">
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--cyan);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Jobs</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--cyan)" id="sch-k-jobs">—</div>
            <div style="font-size:10px;color:var(--t3)" id="sch-k-enabled">— enabled</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--green);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Pass rate 24h</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--green)" id="sch-k-rate">—</div>
            <div style="font-size:10px;color:var(--t3)" id="sch-k-rate-sub">— pass / — total</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--green);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Pass 24h</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--green)" id="sch-k-pass">—</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--red);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Fail 24h</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--red)" id="sch-k-fail">—</div>
          </div>
          <div class="kpi-card" style="padding:12px;border-left:3px solid var(--purple);background:var(--bg3);border-radius:4px">
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">Total runs</div>
            <div style="font-family:var(--display);font-size:28px;font-weight:800;color:var(--purple)" id="sch-k-runs">—</div>
          </div>
        </div>

        <div style="padding:0 14px 14px">
          <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">
            Activity — last 24h
          </div>
          <div id="sch-heatmap" style="display:flex;gap:1px;height:24px;background:var(--bg3);border-radius:3px;padding:2px"></div>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Jobs</div>
            <div class="card-sub" id="sch-jobs-sub">loading…</div>
          </div>
        </div>
        <div style="padding:12px 14px;display:grid;grid-template-columns:1fr 200px 160px;gap:8px">
          <input aria-label="Search job name…" id="sch-search" class="form-ctrl" placeholder="Search job name…" style="font-size:12px">
          <select aria-label="Sch Type" id="sch-type" class="form-ctrl" style="font-size:12px">
            <option value="">All types</option>
            <option value="scan_image">Scan image</option>
            <option value="sign_image">Sign image</option>
            <option value="verify_image">Verify image</option>
            <option value="attest_image">Attest image</option>
            <option value="cve_recheck">CVE re-match</option>
            <option value="sbom_export">SBOM export</option>
            <option value="webhook">Webhook</option>
          </select>
          <select aria-label="Sch State" id="sch-state" class="form-ctrl" style="font-size:12px">
            <option value="">All states</option>
            <option value="enabled">Enabled only</option>
            <option value="disabled">Disabled only</option>
            <option value="failing">Failing</option>
          </select>
        </div>
        <div style="overflow:auto;max-height:65vh">
          <table class="data-table" style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="text-align:left;font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.06em;
                         background:var(--bg3);border-bottom:1px solid var(--border);position:sticky;top:0">
                <th style="padding:8px 12px;width:28px"></th>
                <th style="padding:8px 12px">Name</th>
                <th style="padding:8px 12px">Schedule</th>
                <th style="padding:8px 12px">Next</th>
                <th style="padding:8px 12px">Last run</th>
                <th style="padding:8px 12px">Stats</th>
                <th style="padding:8px 12px;text-align:right">Actions</th>
              </tr>
            </thead>
            <tbody id="sch-jobs-rows">
              <tr><td colspan="7" style="padding:24px;text-align:center;color:var(--t3)">loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Run feed</div>
            <div class="card-sub" id="sch-feed-sub">live, last 50</div>
          </div>
        </div>
        <div style="padding:0;max-height:280px;overflow:auto">
          <table style="width:100%;border-collapse:collapse;font-size:11px">
            <tbody id="sch-feed-rows">
              <tr><td style="padding:18px;text-align:center;color:var(--t3)">loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `);

    ensureModals();
    wireButtons();

    refreshAll();
    setInterval(refreshStats, 15_000);
    setInterval(refreshFeed, 10_000);
    setInterval(refreshHeatmap, 30_000);
    setInterval(updateCountdowns, 1_000);
  }

  function wireButtons() {
    $('sch-btn-refresh').addEventListener('click', refreshAll);
    $('sch-btn-new').addEventListener('click', () => openEditor(null));
    $('sch-search').addEventListener('input', debounce(refreshJobs, 250));
    $('sch-type').addEventListener('change', refreshJobs);
    $('sch-state').addEventListener('change', refreshJobs);
  }

  function debounce(fn, ms) {
    let t;
    return function (...a) { clearTimeout(t); t = setTimeout(() => fn.apply(this, a), ms); };
  }

  // ── modals ───────────────────────────────────────────────────────────
  function ensureModals() {
    if (document.getElementById('sch-detail-modal')) return;

    const detail = document.createElement('div');
    detail.id = 'sch-detail-modal';
    detail.className = 'modal-overlay';
    detail.style.display = 'none';
    detail.innerHTML = `
      <div class="modal" style="width:min(960px,95vw);max-height:90vh;display:flex;flex-direction:column">
        <div class="modal-head">
          <div>
            <div class="modal-title" id="sch-md-title">Job</div>
            <div class="modal-sub" id="sch-md-sub"></div>
          </div>
          <button class="modal-close" id="sch-md-close">✕</button>
        </div>
        <div class="modal-body" style="overflow:auto;flex:1">
          <div style="display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:10px">
            <button class="btn btn-sm sch-tab" data-tab="overview" style="border-radius:0;border-bottom:2px solid var(--cyan)">Overview</button>
            <button class="btn btn-sm sch-tab" data-tab="schedule">Schedule</button>
            <button class="btn btn-sm sch-tab" data-tab="history">History</button>
          </div>
          <div id="sch-md-content"></div>
        </div>
        <div class="modal-footer">
          <button class="btn" id="sch-md-delete" style="color:var(--red)">Delete</button>
          <button class="btn" id="sch-md-edit">Edit</button>
          <button class="btn btn-primary" id="sch-md-run">▶ Run now</button>
          <button class="btn" id="sch-md-close-btn">Close</button>
        </div>
      </div>
    `;
    detail.addEventListener('click', e => { if (e.target === detail) detail.style.display = 'none'; });
    document.body.appendChild(detail);
    $('sch-md-close').addEventListener('click',     () => detail.style.display = 'none');
    $('sch-md-close-btn').addEventListener('click', () => detail.style.display = 'none');

    // Editor modal
    const editor = document.createElement('div');
    editor.id = 'sch-editor-modal';
    editor.className = 'modal-overlay';
    editor.style.display = 'none';
    editor.innerHTML = `
      <div class="modal" style="width:min(720px,95vw);max-height:92vh;display:flex;flex-direction:column">
        <div class="modal-head">
          <div>
            <div class="modal-title" id="sch-ed-title">New job</div>
            <div class="modal-sub">Configure schedule and dispatch target</div>
          </div>
          <button class="modal-close" id="sch-ed-close">✕</button>
        </div>
        <div class="modal-body" style="overflow:auto;flex:1">
          <div class="form-group">
            <label class="form-label" for="sch-f-name">Name</label>
            <input class="form-ctrl" id="sch-f-name" placeholder="e.g. Nightly Trivy scan">
          </div>
          <div class="form-group">
            <label class="form-label" for="sch-f-type">Job type</label>
            <select class="form-ctrl" id="sch-f-type">
              <option value="scan_image">🔍 Scan image (Trivy)</option>
              <option value="sign_image">✍ Sign image (Cosign)</option>
              <option value="verify_image">✓ Verify image (Cosign)</option>
              <option value="attest_image">📜 Attest image SLSA (Cosign)</option>
              <option value="cve_recheck">↻ CVE re-match (SW Inventory)</option>
              <option value="sbom_export">📦 SBOM export</option>
              <option value="webhook">🔗 Webhook (POST URL)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label" for="sch-f-target">Target</label>
            <input class="form-ctrl" id="sch-f-target"
                   placeholder="image:tag, URL, or 'all' depending on type"
                   style="font-family:var(--font-mono);font-size:11px">
            <div style="font-size:10px;color:var(--t3);margin-top:4px" id="sch-f-target-hint"></div>
          </div>

          <div class="form-group">
            <label class="form-label" style="display:flex;align-items:center;justify-content:space-between">
              <span>Schedule</span>
              <span style="font-size:10px;color:var(--t3)">
                <a href="#" id="sch-toggle-advanced" style="color:var(--cyan);text-decoration:none">[Advanced]</a>
              </span>
            </label>

            <div id="sch-picker" style="background:var(--bg3);padding:12px;border-radius:4px;margin-bottom:8px">
              <div style="display:grid;grid-template-columns:auto 1fr;gap:8px;align-items:center;font-size:12px">
                <input type="radio" name="sch-mode" id="sch-m-min" value="minutes">
                <label for="sch-m-min">Every <input aria-label="Sch M Min N" id="sch-m-min-n" type="number" min="1" max="59" value="15" style="width:50px;background:var(--bg2);border:1px solid var(--border);color:var(--t1);padding:2px 4px;border-radius:3px"> minutes</label>

                <input type="radio" name="sch-mode" id="sch-m-hour" value="hours">
                <label for="sch-m-hour">Every <input aria-label="Sch M Hour N" id="sch-m-hour-n" type="number" min="1" max="23" value="2" style="width:50px;background:var(--bg2);border:1px solid var(--border);color:var(--t1);padding:2px 4px;border-radius:3px"> hours</label>

                <input type="radio" name="sch-mode" id="sch-m-daily" value="daily" checked>
                <label for="sch-m-daily">Daily at <input aria-label="Sch M Daily T" id="sch-m-daily-t" type="time" value="02:00" style="background:var(--bg2);border:1px solid var(--border);color:var(--t1);padding:2px 4px;border-radius:3px"></label>

                <input type="radio" name="sch-mode" id="sch-m-weekly" value="weekly">
                <label for="sch-m-weekly">Weekly on
                  <span id="sch-m-weekly-d" style="display:inline-flex;gap:3px;margin:0 4px">
                    ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map((d,i)=>`
                      <label style="font-size:10px;cursor:pointer;padding:2px 6px;border:1px solid var(--border);border-radius:3px;background:var(--bg2)">
                        <input aria-label="Dow" type="checkbox" data-dow="${i}" ${i===1?'checked':''} style="display:none">${d}
                      </label>
                    `).join('')}
                  </span>
                  at <input aria-label="Sch M Weekly T" id="sch-m-weekly-t" type="time" value="02:00" style="background:var(--bg2);border:1px solid var(--border);color:var(--t1);padding:2px 4px;border-radius:3px">
                </label>

                <input type="radio" name="sch-mode" id="sch-m-monthly" value="monthly">
                <label for="sch-m-monthly">Monthly on day <input aria-label="Sch M Monthly D" id="sch-m-monthly-d" type="number" min="1" max="31" value="1" style="width:50px;background:var(--bg2);border:1px solid var(--border);color:var(--t1);padding:2px 4px;border-radius:3px"> at <input aria-label="Sch M Monthly T" id="sch-m-monthly-t" type="time" value="02:00" style="background:var(--bg2);border:1px solid var(--border);color:var(--t1);padding:2px 4px;border-radius:3px"></label>
              </div>
            </div>

            <div id="sch-raw" style="display:none;background:var(--bg3);padding:12px;border-radius:4px;margin-bottom:8px">
              <input aria-label="0 2 * * *  (minute hour dom month dow)" class="form-ctrl" id="sch-f-cron"
                     placeholder="0 2 * * *  (minute hour dom month dow)"
                     style="font-family:var(--font-mono);font-size:13px">
              <div style="font-size:10px;color:var(--t3);margin-top:6px">
                Examples:
                <code style="color:var(--cyan)">0 2 * * *</code> daily 02:00 ·
                <code style="color:var(--cyan)">*/15 * * * *</code> every 15 min ·
                <code style="color:var(--cyan)">0 9-17 * * 1-5</code> hourly 9-17, Mon-Fri
              </div>
            </div>

            <div id="sch-preview" style="background:var(--bg2);padding:10px;border-radius:4px;border-left:3px solid var(--cyan);font-size:11px;min-height:48px">
              <div style="color:var(--t3);font-size:10px;text-transform:uppercase;letter-spacing:0.05em">Cron preview</div>
              <div id="sch-preview-content" style="margin-top:4px">—</div>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="sch-f-notes">Notes (optional)</label>
            <input class="form-ctrl" id="sch-f-notes" placeholder="Free-form note">
          </div>

          <div class="form-group" style="display:flex;align-items:center;gap:8px">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
              <input aria-label="Sch F Enabled" type="checkbox" id="sch-f-enabled" checked>
              <span>Enabled (start scheduling immediately)</span>
            </label>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn" id="sch-ed-cancel">Cancel</button>
          <button class="btn btn-primary" id="sch-ed-save">Save</button>
        </div>
      </div>
    `;
    editor.addEventListener('click', e => { if (e.target === editor) editor.style.display = 'none'; });
    document.body.appendChild(editor);
    $('sch-ed-close').addEventListener('click',  () => editor.style.display = 'none');
    $('sch-ed-cancel').addEventListener('click', () => editor.style.display = 'none');
    $('sch-ed-save').addEventListener('click', saveJob);

    // Picker reactivity
    $('sch-toggle-advanced').addEventListener('click', e => {
      e.preventDefault();
      const adv = $('sch-raw'); const pick = $('sch-picker');
      const isAdv = adv.style.display !== 'none';
      adv.style.display  = isAdv ? 'none'  : 'block';
      pick.style.display = isAdv ? 'block' : 'none';
      e.target.textContent = isAdv ? '[Advanced]' : '[Simple]';
      updatePreview();
    });

    // All inputs trigger preview
    ['sch-m-min','sch-m-hour','sch-m-daily','sch-m-weekly','sch-m-monthly',
     'sch-m-min-n','sch-m-hour-n','sch-m-daily-t','sch-m-weekly-t',
     'sch-m-monthly-d','sch-m-monthly-t','sch-f-cron'].forEach(id => {
      const el = $(id);
      if (el) el.addEventListener('input',  updatePreview);
      if (el) el.addEventListener('change', updatePreview);
    });
    document.querySelectorAll('input[data-dow]').forEach(cb => {
      cb.addEventListener('change', e => {
        const lbl = e.target.parentNode;
        lbl.style.background = e.target.checked ? 'var(--cyan2)' : 'var(--bg2)';
        lbl.style.borderColor = e.target.checked ? 'var(--cyan)' : 'var(--border)';
        updatePreview();
      });
      // Init checked state visual
      if (cb.checked) {
        cb.parentNode.style.background = 'var(--cyan2)';
        cb.parentNode.style.borderColor = 'var(--cyan)';
      }
    });
    $('sch-f-type').addEventListener('change', updateTargetHint);
  }

  function buildCronFromPicker() {
    const mode = document.querySelector('input[name="sch-mode"]:checked')?.value || 'daily';
    if (mode === 'minutes') {
      const n = parseInt($('sch-m-min-n').value, 10) || 15;
      return `*/${n} * * * *`;
    }
    if (mode === 'hours') {
      const n = parseInt($('sch-m-hour-n').value, 10) || 2;
      return `0 */${n} * * *`;
    }
    if (mode === 'daily') {
      const [h, m] = ($('sch-m-daily-t').value || '02:00').split(':');
      return `${parseInt(m, 10)} ${parseInt(h, 10)} * * *`;
    }
    if (mode === 'weekly') {
      const dows = Array.from(document.querySelectorAll('input[data-dow]:checked'))
                        .map(c => c.dataset.dow);
      const [h, m] = ($('sch-m-weekly-t').value || '02:00').split(':');
      return `${parseInt(m, 10)} ${parseInt(h, 10)} * * ${dows.length ? dows.join(',') : '*'}`;
    }
    if (mode === 'monthly') {
      const d = parseInt($('sch-m-monthly-d').value, 10) || 1;
      const [h, m] = ($('sch-m-monthly-t').value || '02:00').split(':');
      return `${parseInt(m, 10)} ${parseInt(h, 10)} ${d} * *`;
    }
    return '0 2 * * *';
  }

  function getCurrentCron() {
    const advancedOpen = $('sch-raw').style.display !== 'none';
    return advancedOpen ? ($('sch-f-cron').value || '').trim() : buildCronFromPicker();
  }

  let _previewTimer = null;
  function updatePreview() {
    if (_previewTimer) clearTimeout(_previewTimer);
    _previewTimer = setTimeout(async () => {
      const expr = getCurrentCron();
      const c = $('sch-preview-content');
      if (!expr) { c.innerHTML = '—'; return; }
      try {
        const j = await api('/preview?expr=' + encodeURIComponent(expr) + '&n=5');
        c.innerHTML = `
          <div style="margin-bottom:6px"><b style="color:var(--t1);font-family:var(--font-mono)">${esc(j.expr)}</b>
              <span style="color:var(--cyan)"> · ${esc(j.describe)}</span></div>
          <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:3px">Next 5 runs</div>
          ${j.next.map(n => `
            <div style="font-size:10px;font-family:var(--font-mono);color:var(--t2)">
              ${esc(n.weekday)} · ${esc(fmtTime(n.time))} <span style="color:var(--t3)">(in ${esc(n.in)})</span>
            </div>`).join('')}
        `;
      } catch (e) {
        c.innerHTML = `<span style="color:var(--red)">✗ ${esc(e.message)}</span>`;
      }
    }, 200);
  }

  function updateTargetHint() {
    const t = $('sch-f-type').value;
    const hints = {
      scan_image:   'Image ref to scan, e.g. <code>nginx:1.25-alpine</code>',
      sign_image:   'Image to sign, e.g. <code>localhost:5000/vsp/api:v1</code>',
      verify_image: 'Image to verify (must already be signed)',
      attest_image: 'Image to attach SLSA provenance to',
      cve_recheck:  'Leave empty — re-matches all hosts in inventory',
      sbom_export:  'Image name or <code>all</code> for combined export',
      webhook:      'Full URL: <code>https://hooks.example.com/notify</code>',
    };
    $('sch-f-target-hint').innerHTML = hints[t] || '';
  }

  let _editingJob = null;
  function openEditor(job) {
    _editingJob = job;
    $('sch-ed-title').textContent = job ? 'Edit: ' + job.name : 'New job';
    $('sch-f-name').value     = job?.name || '';
    $('sch-f-type').value     = job?.type || 'scan_image';
    $('sch-f-target').value   = job?.target || '';
    $('sch-f-notes').value    = job?.notes || '';
    $('sch-f-enabled').checked = job ? job.enabled : true;
    if (job?.cron_expr) {
      // Open in advanced mode pre-filled
      $('sch-raw').style.display    = 'block';
      $('sch-picker').style.display = 'none';
      $('sch-f-cron').value         = job.cron_expr;
      $('sch-toggle-advanced').textContent = '[Simple]';
    } else {
      $('sch-raw').style.display    = 'none';
      $('sch-picker').style.display = 'block';
      $('sch-toggle-advanced').textContent = '[Advanced]';
    }
    updateTargetHint();
    updatePreview();
    $('sch-editor-modal').style.display = 'flex';
  }

  async function saveJob() {
    const expr = getCurrentCron();
    const payload = {
      name:      $('sch-f-name').value.trim(),
      type:      $('sch-f-type').value,
      cron_expr: expr,
      target:    $('sch-f-target').value.trim(),
      notes:     $('sch-f-notes').value.trim(),
      enabled:   $('sch-f-enabled').checked,
    };
    if (!payload.name) { toast('Name required', 'warn'); return; }

    try {
      if (_editingJob) {
        await api('/jobs/' + encodeURIComponent(_editingJob.id), {
          method: 'PUT', body: JSON.stringify(payload),
        });
        toast('Job updated', 'success');
      } else {
        await api('/jobs', { method: 'POST', body: JSON.stringify(payload) });
        toast('Job created', 'success');
      }
      $('sch-editor-modal').style.display = 'none';
      refreshAll();
    } catch (e) {
      toast('Save failed: ' + e.message, 'error');
    }
  }

  // ── refresh ──────────────────────────────────────────────────────────
  async function refreshAll() {
    healthCheck(); refreshStats(); refreshJobs(); refreshFeed(); refreshHeatmap();
  }

  async function healthCheck() {
    const el = $('sch-health'); if (!el) return;
    try {
      const h = await api('/healthz');
      el.innerHTML = `<span style="color:var(--green)">●</span> healthy
        · ${h.jobs} jobs · ${h.runs} runs · engine <b>${h.engine ? 'ON' : 'OFF'}</b>`;
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">●</span> unreachable`;
    }
  }

  async function refreshStats() {
    try {
      const s = await api('/stats');
      const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
      set('sch-k-jobs', s.jobs);
      set('sch-k-enabled', `${s.enabled} enabled`);
      set('sch-k-rate', s.runs_24h ? Math.round(s.pass_rate) + '%' : '—');
      set('sch-k-rate-sub', `${s.pass_24h} pass / ${s.runs_24h} total`);
      set('sch-k-pass', s.pass_24h);
      set('sch-k-fail', s.fail_24h);
      set('sch-k-runs', s.runs);
    } catch (e) { /* keep last */ }
  }

  let _jobsCache = [];
  async function refreshJobs() {
    const sub = $('sch-jobs-sub'); const rows = $('sch-jobs-rows');
    if (sub) sub.textContent = 'loading…';
    try {
      const j = await api('/jobs');
      _jobsCache = j.jobs || [];
      const search = ($('sch-search').value || '').toLowerCase();
      const tFilter = $('sch-type').value;
      const sFilter = $('sch-state').value;
      const visible = _jobsCache.filter(jb => {
        if (search && !jb.name.toLowerCase().includes(search)) return false;
        if (tFilter && jb.type !== tFilter) return false;
        if (sFilter === 'enabled'  && !jb.enabled) return false;
        if (sFilter === 'disabled' &&  jb.enabled) return false;
        if (sFilter === 'failing'  && jb.last_status !== 'fail') return false;
        return true;
      });
      if (sub) sub.textContent = `${visible.length} of ${_jobsCache.length} jobs`;
      if (visible.length === 0) {
        rows.innerHTML = `<tr><td colspan="7" style="padding:32px;text-align:center;color:var(--t3)">
          no jobs match — adjust filters or click <b>+ New job</b></td></tr>`;
        return;
      }
      rows.innerHTML = visible.map(jb => {
        const lastFail = jb.last_status === 'fail';
        return `
        <tr style="border-bottom:1px solid var(--border);cursor:pointer;
                   ${lastFail ? 'box-shadow: inset 3px 0 0 var(--red);' : ''}"
            onmouseover="this.style.background='var(--bg4)'"
            onmouseout="this.style.background='transparent'"
            data-id="${esc(jb.id)}">
          <td style="padding:8px 12px">
            <span style="display:inline-block;width:10px;height:10px;border-radius:50%;
                  background:${jb.enabled ? 'var(--green)' : 'var(--t3)'}"
                  title="${jb.enabled ? 'enabled' : 'disabled'}"></span>
          </td>
          <td style="padding:8px 12px">
            <div style="font-weight:600;color:var(--t1)">${typeIcon(jb.type)} ${esc(jb.name)}</div>
            <div style="font-size:10px;color:var(--t3);font-family:var(--font-mono)">${esc(jb.target || '—')}</div>
          </td>
          <td style="padding:8px 12px;font-size:11px">
            <code style="font-family:var(--font-mono);color:var(--cyan);font-size:11px">${esc(jb.cron_expr)}</code>
            <div style="font-size:10px;color:var(--t3)">${esc(jb.cron_describe)}</div>
          </td>
          <td style="padding:8px 12px;font-size:11px;color:var(--t3)">
            <span class="sch-countdown" data-time="${esc(jb.next_run)}">
              ${jb.enabled ? relTime(jb.next_run) : '—'}
            </span>
          </td>
          <td style="padding:8px 12px;font-size:11px">
            ${jb.last_status ? statusPill(jb.last_status) : '<span style="color:var(--t3)">never run</span>'}
            ${jb.last_run_at && !jb.last_run_at.startsWith('0001') ? `
              <div style="font-size:10px;color:var(--t3);margin-top:2px">
                ${esc(relTime(jb.last_run_at))}${jb.last_duration ? ' · ' + esc(jb.last_duration) : ''}
              </div>` : ''}
          </td>
          <td style="padding:8px 12px;font-size:10px;font-family:var(--font-mono);color:var(--t3)">
            ${jb.run_count} runs<br>
            <span style="color:${jb.success_rate >= 95 ? 'var(--green)' : jb.success_rate >= 80 ? 'var(--amber)' : 'var(--red)'}">
              ${jb.run_count > 0 ? Math.round(jb.success_rate) + '%' : '—'}
            </span>
          </td>
          <td style="padding:8px 12px;text-align:right">
            <button class="btn btn-sm" onclick="event.stopPropagation();window.VSPScheduler.runNow('${esc(jb.id)}')">▶</button>
            <button class="btn btn-sm" onclick="event.stopPropagation();window.VSPScheduler.toggle('${esc(jb.id)}')">${jb.enabled ? '⏸' : '▶'}</button>
          </td>
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

  async function refreshFeed() {
    const rows = $('sch-feed-rows'); if (!rows) return;
    try {
      const j = await api('/runs?limit=50');
      if (!j.runs || j.runs.length === 0) {
        rows.innerHTML = `<tr><td style="padding:18px;text-align:center;color:var(--t3)">no runs yet</td></tr>`;
        return;
      }
      rows.innerHTML = j.runs.map(r => `
        <tr style="border-bottom:1px solid var(--border);cursor:pointer" data-runid="${esc(r.id)}"
            onmouseover="this.style.background='var(--bg4)'" onmouseout="this.style.background='transparent'">
          <td style="padding:6px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3);width:170px">${esc(fmtTime(r.started_at))}</td>
          <td style="padding:6px 12px;width:120px">${statusPill(r.status)}</td>
          <td style="padding:6px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3);width:80px">${esc(fmtDuration(r.duration_ms))}</td>
          <td style="padding:6px 12px;font-size:11px;color:var(--t1)">
            ${typeIcon(r.job_type)} ${esc(r.job_name)}
            <span style="color:var(--t3);font-size:10px"> · ${esc(r.triggered)}</span>
            ${r.error ? `<div style="font-size:10px;color:var(--red);font-family:var(--font-mono)">${esc(r.error.slice(0,120))}</div>` : ''}
          </td>
        </tr>`).join('');
      rows.querySelectorAll('tr[data-runid]').forEach(tr => {
        tr.addEventListener('click', () => showRunDetail(tr.dataset.runid));
      });
    } catch (e) {
      rows.innerHTML = `<tr><td style="padding:14px;text-align:center;color:var(--red)">✗ ${esc(e.message)}</td></tr>`;
    }
  }

  async function refreshHeatmap() {
    const el = $('sch-heatmap'); if (!el) return;
    try {
      const since = new Date(Date.now() - 24 * 3_600_000).toISOString();
      const j = await api('/runs?since=' + encodeURIComponent(since) + '&limit=2000');
      // Bucket into 48 half-hour cells
      const cells = new Array(48).fill(null).map(() => ({ pass: 0, fail: 0, warn: 0 }));
      const bucketStart = Date.now() - 24 * 3_600_000;
      (j.runs || []).forEach(r => {
        const t = new Date(r.started_at).getTime();
        const idx = Math.floor((t - bucketStart) / (30 * 60_000));
        if (idx < 0 || idx >= 48) return;
        if (r.status === 'pass') cells[idx].pass++;
        else if (r.status === 'fail') cells[idx].fail++;
        else cells[idx].warn++;
      });
      el.innerHTML = cells.map((c, i) => {
        let color = 'var(--bg4)';
        let title = 'no runs';
        const total = c.pass + c.fail + c.warn;
        if (c.fail > 0)      { color = 'var(--red)';   title = `${c.fail} fail / ${total} total`; }
        else if (c.warn > 0) { color = 'var(--amber)'; title = `${c.warn} warn / ${total} total`; }
        else if (c.pass > 0) { color = 'var(--green)'; title = `${c.pass} pass`; }
        const t0 = new Date(bucketStart + i * 30 * 60_000);
        return `<div style="flex:1;background:${color};border-radius:1px;min-height:20px"
                     title="${t0.toLocaleTimeString()}: ${title}"></div>`;
      }).join('');
    } catch (e) { /* leave skeleton */ }
  }

  function updateCountdowns() {
    document.querySelectorAll('.sch-countdown[data-time]').forEach(el => {
      el.textContent = relTime(el.dataset.time);
    });
  }

  // ── detail modal ─────────────────────────────────────────────────────
  let _currentJob = null;
  let _currentTab = 'overview';

  async function showDetail(id) {
    _currentJob = null; _currentTab = 'overview';
    const m = $('sch-detail-modal'); m.style.display = 'flex';
    $('sch-md-title').textContent = 'Loading…';
    $('sch-md-content').innerHTML = '<div style="padding:24px;text-align:center;color:var(--t3)">loading…</div>';
    document.querySelectorAll('.sch-tab').forEach(b => {
      b.style.borderBottom = b.dataset.tab === 'overview' ? '2px solid var(--cyan)' : '2px solid transparent';
      b.onclick = () => { _currentTab = b.dataset.tab; renderDetailTab();
        document.querySelectorAll('.sch-tab').forEach(bb => {
          bb.style.borderBottom = bb.dataset.tab === _currentTab ? '2px solid var(--cyan)' : '2px solid transparent';
        });
      };
    });
    $('sch-md-run').onclick = () => _currentJob && runNow(_currentJob.id);
    $('sch-md-edit').onclick = () => { m.style.display = 'none'; openEditor(_currentJob); };
    $('sch-md-delete').onclick = async () => {
      if (!_currentJob) return;
      if (!confirm('Delete job "' + _currentJob.name + '"?')) return;
      try {
        await api('/jobs/' + encodeURIComponent(_currentJob.id), { method: 'DELETE' });
        toast('Deleted', 'success');
        m.style.display = 'none'; refreshAll();
      } catch (e) { toast('Delete failed: ' + e.message, 'error'); }
    };

    try {
      _currentJob = await api('/jobs/' + encodeURIComponent(id));
      $('sch-md-title').textContent = _currentJob.name;
      $('sch-md-sub').textContent = `${_currentJob.type} · ${_currentJob.cron_describe}`;
      renderDetailTab();
    } catch (e) {
      $('sch-md-content').innerHTML = `<div style="padding:24px;color:var(--red)">✗ ${esc(e.message)}</div>`;
    }
  }

  async function renderDetailTab() {
    if (!_currentJob) return;
    const c = $('sch-md-content');
    if (_currentTab === 'overview') {
      c.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px">
          ${kvCard('Type',     typeIcon(_currentJob.type) + ' ' + _currentJob.type)}
          ${kvCard('Target',   _currentJob.target || '—', true)}
          ${kvCard('Schedule', '<code style="font-family:var(--font-mono);color:var(--cyan)">' + esc(_currentJob.cron_expr) + '</code>', true)}
          ${kvCard('Describe', _currentJob.cron_describe, true)}
          ${kvCard('State',    _currentJob.enabled ? '<span style="color:var(--green)">● enabled</span>' : '<span style="color:var(--t3)">○ disabled</span>', true)}
          ${kvCard('Last',     (_currentJob.last_status ? statusPill(_currentJob.last_status) + ' ' : '') + (_currentJob.last_duration || ''), true)}
          ${kvCard('Next run', fmtTime(_currentJob.next_run), true)}
          ${kvCard('Stats',    `${_currentJob.run_count} runs · ${Math.round(_currentJob.success_rate)}% pass`, true)}
        </div>
        ${_currentJob.notes ? `<div style="padding:10px;background:var(--bg3);border-radius:4px;font-size:11px;color:var(--t2)"><b>Notes:</b> ${esc(_currentJob.notes)}</div>` : ''}
      `;
    } else if (_currentTab === 'schedule') {
      c.innerHTML = '<div style="padding:14px;color:var(--t3)">loading preview…</div>';
      try {
        const p = await api('/preview?expr=' + encodeURIComponent(_currentJob.cron_expr) + '&n=10');
        c.innerHTML = `
          <div style="padding:12px;background:var(--bg3);border-radius:4px;margin-bottom:14px">
            <div style="font-family:var(--font-mono);font-size:14px;color:var(--t1)">
              <b>${esc(p.expr)}</b>
            </div>
            <div style="color:var(--cyan);margin-top:4px">${esc(p.describe)}</div>
          </div>
          <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">Next 10 fire times</div>
          <table style="width:100%;border-collapse:collapse;font-size:11px">
            ${p.next.map(n => `
              <tr style="border-bottom:1px solid var(--border)">
                <td style="padding:6px 10px;font-family:var(--font-mono);color:var(--t1)">${esc(n.weekday)}</td>
                <td style="padding:6px 10px;font-family:var(--font-mono);color:var(--cyan)">${esc(fmtTime(n.time))}</td>
                <td style="padding:6px 10px;color:var(--t3)">in ${esc(n.in)}</td>
              </tr>`).join('')}
          </table>`;
      } catch (e) {
        c.innerHTML = `<div style="padding:14px;color:var(--red)">✗ ${esc(e.message)}</div>`;
      }
    } else if (_currentTab === 'history') {
      c.innerHTML = '<div style="padding:14px;color:var(--t3)">loading runs…</div>';
      try {
        const r = await api('/jobs/' + encodeURIComponent(_currentJob.id) + '/runs?limit=100');
        if (!r.runs || r.runs.length === 0) {
          c.innerHTML = '<div style="padding:24px;text-align:center;color:var(--t3)">no run history yet</div>';
          return;
        }
        c.innerHTML = `
          <table style="width:100%;border-collapse:collapse;font-size:11px">
            <thead><tr style="background:var(--bg3)">
              <th style="padding:6px 10px;text-align:left">Started</th>
              <th style="padding:6px 10px;text-align:left">Status</th>
              <th style="padding:6px 10px;text-align:left">Duration</th>
              <th style="padding:6px 10px;text-align:left">Trigger</th>
              <th style="padding:6px 10px;text-align:left">Output preview</th>
            </tr></thead><tbody>
              ${r.runs.map(rr => `
                <tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="window.VSPScheduler.showRun('${esc(rr.id)}')">
                  <td style="padding:6px 10px;font-family:var(--font-mono)">${esc(fmtTime(rr.started_at))}</td>
                  <td style="padding:6px 10px">${statusPill(rr.status)}</td>
                  <td style="padding:6px 10px;font-family:var(--font-mono);color:var(--t3)">${esc(fmtDuration(rr.duration_ms))}</td>
                  <td style="padding:6px 10px;color:var(--t3);font-size:10px">${esc(rr.triggered)}</td>
                  <td style="padding:6px 10px;color:var(--t3);font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                      ${esc((rr.error || rr.output || '').slice(0, 80))}
                  </td>
                </tr>`).join('')}
          </tbody></table>`;
      } catch (e) {
        c.innerHTML = `<div style="padding:14px;color:var(--red)">✗ ${esc(e.message)}</div>`;
      }
    }
  }

  function kvCard(label, value, html) {
    return `<div style="padding:10px;background:var(--bg3);border-radius:4px">
      <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em">${esc(label)}</div>
      <div style="font-size:13px;color:var(--t1);margin-top:3px">${html ? value : esc(value)}</div>
    </div>`;
  }

  async function showRunDetail(id) {
    try {
      const r = await api('/runs/' + encodeURIComponent(id));
      const w = window.open('', '_blank', 'width=900,height=700');
      if (!w) {
        // Inline fallback
        alert('Run ' + r.id + ':\n\n' + (r.output || r.error || '(no output)'));
        return;
      }
      w.document.body.style.cssText = 'background:#0d1421;color:#cbd5e1;font-family:monospace;padding:20px';
      w.document.title = 'Run ' + r.id;
      w.document.body.innerHTML = `
        <h2 style="color:#06b6d4">${r.job_name} — ${r.status}</h2>
        <p>Run ID: ${r.id} · Started: ${fmtTime(r.started_at)} · Duration: ${fmtDuration(r.duration_ms)}</p>
        ${r.error ? `<h3 style="color:#ef4444">Error</h3><pre style="background:#162035;padding:12px;border-radius:4px;white-space:pre-wrap">${esc(r.error)}</pre>` : ''}
        <h3>Output</h3>
        <pre style="background:#162035;padding:12px;border-radius:4px;white-space:pre-wrap">${esc(r.output || '(no output)')}</pre>
      `;
    } catch (e) { toast('Failed: ' + e.message, 'error'); }
  }

  // ── action API exposed globally ──────────────────────────────────────
  async function runNow(id) {
    try {
      await api('/jobs/' + encodeURIComponent(id) + '/run', { method: 'POST' });
      toast('Run triggered', 'success');
      setTimeout(refreshFeed, 800);
      setTimeout(refreshJobs, 1500);
    } catch (e) { toast('Run failed: ' + e.message, 'error'); }
  }

  async function toggle(id) {
    try {
      await api('/jobs/' + encodeURIComponent(id) + '/toggle', { method: 'POST' });
      refreshJobs();
    } catch (e) { toast('Toggle failed: ' + e.message, 'error'); }
  }

  // ── boot ─────────────────────────────────────────────────────────────
  function boot() {
    const p = findPanel();
    if (!p) { setTimeout(boot, 600); return; }
    mount(p);
    const obs = new MutationObserver(() => {
      const pp = findPanel();
      if (pp && pp.dataset.schedWired !== '1') mount(pp);
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.VSPScheduler = {
    runNow, toggle, showRun: showRunDetail,
    refresh: refreshAll, api, apiBase: API_BASE,
  };
  (window.VSP_DEBUG && console.log('[vsp-scheduler] panel wired — backend:', API_BASE));
})();
