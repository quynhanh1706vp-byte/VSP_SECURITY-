/* vsp_email_panel.js — Phase 7C
 * ─────────────────────────────────────────────────────────────────────────
 * VSP Email/SMTP frontend panel.
 *
 * Endpoints consumed (port 8095):
 *   GET    /healthz
 *   GET    /config              (password masked)
 *   POST   /config              update SMTP
 *   GET    /config/health       TCP-test SMTP server
 *   POST   /test                send test email to address
 *   POST   /send                send templated/raw email
 *   GET    /templates           list
 *   POST   /templates/{name}    upsert template
 *   DELETE /templates/{name}    remove
 *   GET    /history             send log
 *
 * Layout: SMTP config card · Templates list/edit · Send history feed
 * ───────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  const API_BASE = (window.VSP_EMAIL_API || 'http://127.0.0.1:8095').replace(/\/$/, '');
  const TIMEOUT  = 30_000;

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function toast(m, k) {
    if (typeof window.showToast === 'function') return window.showToast(m, k || 'info');
    (window.VSP_DEBUG && console.log('[email]', k || 'info', m));
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
  function statusPill(s) {
    const m = { sent: ['var(--green)', '✓ sent'], failed: ['var(--red)', '✗ failed'] };
    const [c, l] = m[s] || ['var(--t3)', s];
    return `<span style="font-family:var(--font-mono);font-size:10px;font-weight:700;
            color:${c};padding:2px 8px;border-radius:3px;
            background:${c.replace('var(', 'rgba(').replace(')', ',0.12)')}">${l}</span>`;
  }

  function findPanel() {
    return $('panel-email') || $('panel-smtp') || $('panel-notifications')
        || document.querySelector('[data-panel="email"]')
        || document.querySelector('[data-panel="smtp"]');
  }

  function mount(panel) {
    if (panel.dataset.emailWired === '1') return;
    panel.dataset.emailWired = '1';

    panel.insertAdjacentHTML('afterbegin', `
      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Email / SMTP</div>
            <div class="card-sub">
              microservice <code style="color:var(--cyan);font-family:var(--font-mono)">${esc(API_BASE)}</code>
              · stdlib net/smtp · 5 templates pre-seeded
            </div>
          </div>
          <span id="em-health" class="mono-sm" style="color:var(--t3)">checking…</span>
        </div>

        <div style="padding:14px;display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div>
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px">SMTP server</div>
            <div style="display:grid;grid-template-columns:120px 1fr;gap:6px 10px;align-items:center;font-size:12px">
              <label style="color:var(--t3)" for="em-f-host">Host</label>
              <input id="em-f-host" class="form-ctrl" placeholder="127.0.0.1" style="font-family:var(--font-mono);font-size:11px">

              <label style="color:var(--t3)" for="em-f-port">Port</label>
              <input id="em-f-port" type="number" class="form-ctrl" placeholder="1025" style="font-family:var(--font-mono);font-size:11px">

              <label style="color:var(--t3)" for="em-f-user">Username</label>
              <input id="em-f-user" class="form-ctrl" placeholder="(blank for anon)" style="font-family:var(--font-mono);font-size:11px">

              <label style="color:var(--t3)" for="em-f-pass">Password</label>
              <input id="em-f-pass" type="password" class="form-ctrl" placeholder="********" style="font-family:var(--font-mono);font-size:11px">

              <label style="color:var(--t3)" for="em-f-from">From</label>
              <input id="em-f-from" class="form-ctrl" placeholder="vsp@vsp.local" style="font-family:var(--font-mono);font-size:11px">

              <label style="color:var(--t3)" for="em-f-fromname">From name</label>
              <input id="em-f-fromname" class="form-ctrl" placeholder="VSP DevSecOps">

              <label style="color:var(--t3)" for="em-f-enc">Encryption</label>
              <select id="em-f-enc" class="form-ctrl" style="font-size:11px">
                <option value="none">None (plain SMTP)</option>
                <option value="starttls">STARTTLS (port 587)</option>
                <option value="tls">Implicit TLS (port 465)</option>
              </select>
            </div>

            <div style="margin-top:14px;display:flex;gap:6px">
              <button class="btn btn-primary btn-sm" id="em-btn-save">Save</button>
              <button class="btn btn-sm" id="em-btn-ping">Ping SMTP</button>
            </div>
            <div id="em-ping-result" style="margin-top:8px;font-size:11px;font-family:var(--font-mono);min-height:16px"></div>
          </div>

          <div>
            <div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px">Send test email</div>
            <div style="display:grid;grid-template-columns:120px 1fr;gap:6px 10px;align-items:center;font-size:12px">
              <label style="color:var(--t3)" for="em-test-to">To</label>
              <input id="em-test-to" class="form-ctrl" placeholder="you@example.com" style="font-family:var(--font-mono);font-size:11px">
            </div>
            <div style="margin-top:14px;display:flex;gap:6px">
              <button class="btn btn-primary btn-sm" id="em-btn-test">Send test</button>
            </div>
            <div id="em-test-result" style="margin-top:8px;font-size:11px;font-family:var(--font-mono);min-height:16px"></div>

            <div style="margin-top:18px;padding:10px;background:var(--bg3);border-radius:4px;border-left:3px solid var(--cyan);font-size:11px;color:var(--t2)">
              <b style="color:var(--cyan)">Default: Mailhog @ 127.0.0.1:1025</b><br>
              View captured emails at <a href="http://127.0.0.1:8025" target="_blank" style="color:var(--cyan)">http://127.0.0.1:8025</a>
              (Mailhog web UI). Plain SMTP, no auth — perfect for dev.
            </div>
          </div>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Templates</div>
            <div class="card-sub" id="em-tmpl-sub">loading…</div>
          </div>
          <button class="btn btn-sm" id="em-btn-new-tmpl">+ New template</button>
        </div>
        <div id="em-tmpl-list" style="padding:0;max-height:400px;overflow:auto"></div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Send history</div>
            <div class="card-sub" id="em-hist-sub">last 50</div>
          </div>
          <button class="btn btn-sm" id="em-btn-refresh">⟳</button>
        </div>
        <div style="max-height:280px;overflow:auto">
          <table style="width:100%;border-collapse:collapse;font-size:11px">
            <tbody id="em-hist-rows">
              <tr><td style="padding:14px;text-align:center;color:var(--t3)">loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `);

    ensureTemplateModal();
    wire();
    refreshAll();
    setInterval(refreshHistory, 15_000);
    setInterval(refreshHealth, 30_000);
  }

  function wire() {
    $('em-btn-save').addEventListener('click', saveConfig);
    $('em-btn-ping').addEventListener('click', pingSMTP);
    $('em-btn-test').addEventListener('click', sendTest);
    $('em-btn-refresh').addEventListener('click', refreshHistory);
    $('em-btn-new-tmpl').addEventListener('click', () => openTmplEditor(null));
  }

  async function refreshAll() {
    refreshHealth();
    loadConfig();
    refreshTemplates();
    refreshHistory();
  }

  async function refreshHealth() {
    const el = $('em-health'); if (!el) return;
    try {
      const h = await api('/healthz');
      el.innerHTML = `<span style="color:var(--green)">●</span> healthy
        · ${esc(h.smtp_host)}:${h.smtp_port} · ${h.templates} tmpls · ${h.history} sends`;
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">●</span> unreachable`;
    }
  }

  async function loadConfig() {
    try {
      const c = await api('/config');
      $('em-f-host').value     = c.host || '';
      $('em-f-port').value     = c.port || 1025;
      $('em-f-user').value     = c.username || '';
      $('em-f-pass').value     = c.password || ''; // shows "********" if set server-side
      $('em-f-from').value     = c.from || '';
      $('em-f-fromname').value = c.from_name || '';
      $('em-f-enc').value      = c.use_tls ? 'tls' : (c.use_starttls ? 'starttls' : 'none');
    } catch (e) { /* ignore */ }
  }

  async function saveConfig() {
    const enc = $('em-f-enc').value;
    const payload = {
      host: $('em-f-host').value.trim(),
      port: parseInt($('em-f-port').value, 10) || 25,
      username: $('em-f-user').value.trim(),
      password: $('em-f-pass').value,
      from: $('em-f-from').value.trim(),
      from_name: $('em-f-fromname').value.trim(),
      use_tls:      enc === 'tls',
      use_starttls: enc === 'starttls',
    };
    try {
      await api('/config', { method: 'POST', body: JSON.stringify(payload) });
      toast('SMTP config saved', 'success');
      refreshHealth();
    } catch (e) { toast('Save failed: ' + e.message, 'error'); }
  }

  async function pingSMTP() {
    const el = $('em-ping-result');
    el.innerHTML = '⏳ pinging…';
    el.style.color = 'var(--amber)';
    try {
      const r = await api('/config/health');
      if (r.reachable) {
        el.innerHTML = `<span style="color:var(--green)">✓ ${esc(r.addr)} reachable</span>`;
      } else {
        el.innerHTML = `<span style="color:var(--red)">✗ unreachable: ${esc(r.error || '')}</span>`;
      }
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">✗ ${esc(e.message)}</span>`;
    }
  }

  async function sendTest() {
    const to = $('em-test-to').value.trim();
    if (!to) { toast('To address required', 'warn'); return; }
    const el = $('em-test-result');
    el.innerHTML = '⏳ sending…';
    el.style.color = 'var(--amber)';
    try {
      const r = await api('/test', { method: 'POST', body: JSON.stringify({ to }) });
      if (r.status === 'sent') {
        el.innerHTML = `<span style="color:var(--green)">✓ sent in ${r.duration_ms}ms — id ${esc(r.id)}</span>`;
        toast('Test email sent', 'success');
      } else {
        el.innerHTML = `<span style="color:var(--red)">✗ ${esc(r.error || 'unknown')}</span>`;
        toast('Test failed: ' + (r.error || ''), 'error');
      }
      refreshHistory();
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">✗ ${esc(e.message)}</span>`;
    }
  }

  async function refreshTemplates() {
    const sub  = $('em-tmpl-sub');
    const list = $('em-tmpl-list');
    if (sub) sub.textContent = 'loading…';
    try {
      const j = await api('/templates');
      if (sub) sub.textContent = `${j.total} templates`;
      list.innerHTML = j.templates.map(t => `
        <div style="border-bottom:1px solid var(--border);padding:10px 14px;cursor:pointer"
             onmouseover="this.style.background='var(--bg4)'" onmouseout="this.style.background='transparent'"
             data-name="${esc(t.name)}">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div style="font-family:var(--font-mono);font-size:12px;color:var(--cyan)">${esc(t.name)}</div>
              <div style="font-size:11px;color:var(--t1);margin-top:2px">${esc(t.subject)}</div>
            </div>
            <div style="font-size:10px;color:var(--t3);font-family:var(--font-mono)">
              ${esc(fmtTime(t.updated_at))}
              ${t.is_html ? ' · <span style="color:var(--purple)">HTML</span>' : ' · text'}
            </div>
          </div>
        </div>
      `).join('');
      list.querySelectorAll('div[data-name]').forEach(el => {
        el.addEventListener('click', async () => {
          const t = await api('/templates/' + encodeURIComponent(el.dataset.name));
          openTmplEditor(t);
        });
      });
    } catch (e) {
      list.innerHTML = `<div style="padding:14px;text-align:center;color:var(--red)">✗ ${esc(e.message)}</div>`;
    }
  }

  async function refreshHistory() {
    const rows = $('em-hist-rows'); if (!rows) return;
    try {
      const j = await api('/history?limit=50');
      if (!j.history || j.history.length === 0) {
        rows.innerHTML = `<tr><td style="padding:14px;text-align:center;color:var(--t3)">no sends yet</td></tr>`;
        return;
      }
      rows.innerHTML = j.history.map(r => `
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:6px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3);width:170px">${esc(fmtTime(r.started_at))}</td>
          <td style="padding:6px 12px;width:90px">${statusPill(r.status)}</td>
          <td style="padding:6px 12px;width:60px;font-family:var(--font-mono);font-size:10px;color:var(--t3)">${r.duration_ms}ms</td>
          <td style="padding:6px 12px;font-size:11px">
            <span style="color:var(--cyan);font-family:var(--font-mono)">${esc((r.to || []).join(', '))}</span><br>
            <span style="color:var(--t2)">${esc(r.subject)}</span>
            ${r.error ? `<div style="color:var(--red);font-size:10px;font-family:var(--font-mono);margin-top:2px">${esc(r.error)}</div>` : ''}
          </td>
        </tr>`).join('');
    } catch (e) {
      rows.innerHTML = `<tr><td style="padding:14px;text-align:center;color:var(--red)">✗ ${esc(e.message)}</td></tr>`;
    }
  }

  // ── template editor ──────────────────────────────────────────────────
  function ensureTemplateModal() {
    if (document.getElementById('em-tmpl-modal')) return;
    const m = document.createElement('div');
    m.id = 'em-tmpl-modal';
    m.className = 'modal-overlay';
    m.style.display = 'none';
    m.innerHTML = `
      <div class="modal" style="width:min(820px,95vw);max-height:90vh;display:flex;flex-direction:column">
        <div class="modal-head">
          <div>
            <div class="modal-title" id="em-tm-title">Edit template</div>
            <div class="modal-sub">Use <code style="color:var(--cyan)">{{var}}</code> placeholders for substitution</div>
          </div>
          <button class="modal-close" id="em-tm-close">✕</button>
        </div>
        <div class="modal-body" style="overflow:auto;flex:1">
          <div class="form-group">
            <label class="form-label" for="em-tm-name">Name (snake_case, used in /send body)</label>
            <input id="em-tm-name" class="form-ctrl" style="font-family:var(--font-mono);font-size:12px">
          </div>
          <div class="form-group">
            <label class="form-label" for="em-tm-subject">Subject</label>
            <input id="em-tm-subject" class="form-ctrl" style="font-family:var(--font-mono);font-size:12px">
          </div>
          <div class="form-group">
            <label class="form-label" for="em-tm-body">Body</label>
            <textarea id="em-tm-body" class="form-ctrl" rows="12"
                      style="font-family:var(--font-mono);font-size:11px;white-space:pre"></textarea>
          </div>
          <div class="form-group" style="display:flex;align-items:center;gap:8px">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px">
              <input aria-label="Em Tm Html" type="checkbox" id="em-tm-html"> HTML body (use Content-Type text/html)
            </label>
          </div>
          <div style="padding:10px;background:var(--bg3);border-radius:4px;font-size:11px;color:var(--t2)">
            <b style="color:var(--cyan)">Available variables (auto-injected when empty):</b><br>
            <code>{{time}}</code> ISO timestamp ·
            <code>{{hostname}}</code> server hostname ·
            <code>{{vsp_host}}</code> VSP UI host
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn" id="em-tm-delete" style="color:var(--red)">Delete</button>
          <button class="btn" id="em-tm-cancel">Cancel</button>
          <button class="btn btn-primary" id="em-tm-save">Save</button>
        </div>
      </div>
    `;
    m.addEventListener('click', e => { if (e.target === m) m.style.display = 'none'; });
    document.body.appendChild(m);
    $('em-tm-close').addEventListener('click',  () => m.style.display = 'none');
    $('em-tm-cancel').addEventListener('click', () => m.style.display = 'none');
    $('em-tm-save').addEventListener('click', saveTemplate);
    $('em-tm-delete').addEventListener('click', deleteTemplate);
  }

  let _editingTmpl = null;
  function openTmplEditor(t) {
    _editingTmpl = t;
    $('em-tm-title').textContent = t ? 'Edit: ' + t.name : 'New template';
    $('em-tm-name').value     = t?.name || '';
    $('em-tm-name').disabled  = !!t;
    $('em-tm-subject').value  = t?.subject || '';
    $('em-tm-body').value     = t?.body || '';
    $('em-tm-html').checked   = !!t?.is_html;
    $('em-tm-delete').style.display = t ? 'inline-block' : 'none';
    $('em-tmpl-modal').style.display = 'flex';
  }

  async function saveTemplate() {
    const name    = $('em-tm-name').value.trim();
    const subject = $('em-tm-subject').value.trim();
    const body    = $('em-tm-body').value;
    const isHTML  = $('em-tm-html').checked;
    if (!name || !subject || !body) {
      toast('All fields required', 'warn');
      return;
    }
    try {
      await api('/templates/' + encodeURIComponent(name), {
        method: 'POST',
        body: JSON.stringify({ name, subject, body, is_html: isHTML }),
      });
      toast('Template saved', 'success');
      $('em-tmpl-modal').style.display = 'none';
      refreshTemplates();
    } catch (e) { toast('Save failed: ' + e.message, 'error'); }
  }

  async function deleteTemplate() {
    if (!_editingTmpl) return;
    if (!confirm('Delete template "' + _editingTmpl.name + '"?')) return;
    try {
      await api('/templates/' + encodeURIComponent(_editingTmpl.name), { method: 'DELETE' });
      toast('Deleted', 'success');
      $('em-tmpl-modal').style.display = 'none';
      refreshTemplates();
    } catch (e) { toast('Delete failed: ' + e.message, 'error'); }
  }

  // ── boot ────────────────────────────────────────────────────────────
  function boot() {
    const p = findPanel();
    if (!p) { setTimeout(boot, 600); return; }
    mount(p);
    const obs = new MutationObserver(() => {
      const pp = findPanel();
      if (pp && pp.dataset.emailWired !== '1') mount(pp);
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.VSPEmail = { refresh: refreshAll, api, apiBase: API_BASE };
  (window.VSP_DEBUG && console.log('[vsp-email] panel wired — backend:', API_BASE));
})();
