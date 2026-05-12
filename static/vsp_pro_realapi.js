/* VSP PRO — realapi companion for cspm / secrets_vault / tenants / observe.

   Wires those 4 sidebar panels to the new PRO endpoints
   (cspm/*, soar/secrets/*, tenants/quota, observability/config) and adds:
     - 402 PaymentRequired upgrade overlay
     - Themed modal forms (replacing browser prompt/confirm)
     - Editable Configure sub-panel per feature
     - Audit sub-panel (no alert boxes)

   Drop-in: load AFTER vsp_pro_100.js. Override semantics:
     - On API success → render real data
     - On 402         → render "Upgrade to PRO" overlay + Contact-Sales button
     - On other error → fall back to original mock + small red error banner */
(function(){
'use strict';
if (!window.VSP_PRO || !window.VSP_PRO.modules){
  console.warn('[VSP-PRO-REALAPI] VSP_PRO not loaded — realapi patch skipped');
  return;
}
var PRO = window.VSP_PRO;

/* ── global fetch wrapper: auto-inject X-CSRF-Token ─────────────────────────
   The gateway's CSRF middleware (CSRFProtect) accepts any of:
     1. Authorization: Bearer <non-empty>
     2. X-Agent-Key
     3. X-CSRF-Token header == vsp_csrf cookie  (double-submit pattern)
   The existing auth wrapper in vsp_upgrade_v100.js injects (1) only when
   a JWT is present. Cookie-session callers with no JWT in localStorage —
   like the "Seed 4 demo images" button — fall through to CSRF check and
   get 403 because the JS never copies the cookie into a header.
   This wrapper closes that gap by setting (3) on every same-origin
   non-safe request, so cookie-auth users can POST/PUT/DELETE again. */
(function(){
  if (window.__VSP_CSRF_AUTOWRAP__) return;
  window.__VSP_CSRF_AUTOWRAP__ = true;
  var ORIG = window.fetch.bind(window);
  function csrfFromCookie(){
    var m = document.cookie.match(/(?:^|;\s*)vsp_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }
  window.fetch = function(input, init){
    try {
      var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
      if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS'){
        var url = (typeof input === 'string') ? input : (input && input.url) || '';
        var sameOrigin = url.charAt(0) === '/' ||
                         url.indexOf(location.origin) === 0;
        if (sameOrigin){
          var hasCSRF = false;
          if (init && init.headers){
            if (init.headers instanceof Headers) hasCSRF = init.headers.has('X-CSRF-Token');
            else if (typeof init.headers === 'object') hasCSRF = !!(init.headers['X-CSRF-Token'] || init.headers['x-csrf-token']);
          }
          if (!hasCSRF){
            var tok = csrfFromCookie();
            if (tok){
              init = init || {};
              init.headers = Object.assign({}, init.headers || {}, { 'X-CSRF-Token': tok });
              if (!init.credentials) init.credentials = 'same-origin';
            }
          }
        }
      }
    } catch (_e) {}
    return ORIG(input, init);
  };
  (window.VSP_DEBUG && console.log('[VSP-PRO-REALAPI v2] CSRF auto-wrapper armed (X-CSRF-Token from vsp_csrf cookie)'));
})();

/* ── inject modal CSS once ──────────────────────────────────────────────── */
(function injectCSS(){
  if (document.getElementById('vsp-pro-realapi-css')) return;
  var s = document.createElement('style');
  s.id = 'vsp-pro-realapi-css';
  s.textContent = [
    '.vspm-back{display:flex;align-items:center;gap:14px;margin-bottom:14px}',
    '.vspm-overlay{position:fixed;inset:0;z-index:99999;background:rgba(2,6,23,.74);',
    '  display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)}',
    '.vspm-modal{background:#0b1220;border:1px solid rgba(34,211,238,.2);border-radius:10px;',
    '  width:min(520px,90vw);max-height:85vh;overflow:auto;',
    '  box-shadow:0 20px 60px rgba(0,0,0,.6);color:#cbd5e1;font-size:12px}',
    '.vspm-modal h3{margin:0 0 4px 0;color:#e2e8f0;font-size:15px;font-weight:600}',
    '.vspm-modal .sub{color:#94a3b8;font-size:11px;margin-bottom:18px}',
    '.vspm-modal-body{padding:22px 24px}',
    '.vspm-modal-footer{padding:14px 24px;border-top:1px solid rgba(255,255,255,.06);',
    '  display:flex;justify-content:flex-end;gap:8px;background:rgba(0,0,0,.18)}',
    '.vspm-field{margin-bottom:14px}',
    '.vspm-field label{display:block;color:#94a3b8;font-size:11px;letter-spacing:.5px;',
    '  text-transform:uppercase;margin-bottom:6px}',
    '.vspm-field .hint{color:#64748b;font-size:10px;margin-top:4px}',
    '.vspm-input,.vspm-select,.vspm-textarea{',
    '  width:100%;background:#0f172a;border:1px solid rgba(255,255,255,.08);',
    '  color:#e2e8f0;border-radius:6px;padding:8px 10px;font-size:12px;',
    '  font-family:inherit;outline:none;transition:border-color .12s}',
    '.vspm-input:focus,.vspm-select:focus,.vspm-textarea:focus{border-color:#22d3ee}',
    '.vspm-textarea{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;min-height:90px}',
    '.vspm-checkbox-row{display:flex;align-items:center;gap:8px}',
    '.vspm-checkbox-row input{margin:0;width:16px;height:16px}',
    '.vspm-checkbox-row label{margin:0;text-transform:none;letter-spacing:0;color:#cbd5e1;font-size:12px}',
    '.vspm-multiselect{display:flex;flex-wrap:wrap;gap:6px}',
    '.vspm-multiselect label{display:inline-flex;align-items:center;gap:6px;',
    '  background:#0f172a;border:1px solid rgba(255,255,255,.08);border-radius:14px;',
    '  padding:5px 11px;cursor:pointer;color:#cbd5e1;font-size:11px;',
    '  text-transform:none;letter-spacing:0;margin:0}',
    '.vspm-multiselect input{margin:0}',
    '.vspm-multiselect input:checked + span{color:#22d3ee}',
    '.vspm-error{color:#fca5a5;font-size:11px;margin-bottom:10px;',
    '  background:#3f1d1d;border-left:3px solid #ef4444;padding:6px 10px;border-radius:4px}',
    '.vspm-toolbar{display:flex;gap:8px;align-items:center;margin-bottom:14px}',
    '.vspm-toolbar .spacer{flex:1}',
    '.vspm-empty{padding:28px;text-align:center;border:1px dashed rgba(255,255,255,.1);',
    '  border-radius:8px;color:#94a3b8}',
    '.vspm-empty .lead{font-size:13px;margin-bottom:10px;color:#cbd5e1}',
    /* CWPP realapi (vsp_pro_cwpp_realapi.js) emits .pro-kpi-row / .pro-kpi
       which were never styled in the platform CSS — they fall back to plain
       block text. Mirror the .pro-card look so the Container security panel
       renders KPIs as cards in a row, matching every other PRO panel. */
    '.pro-kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));',
    '  gap:12px;margin-bottom:18px}',
    '.pro-kpi{background:rgba(15,23,42,.55);border:1px solid rgba(255,255,255,.08);',
    '  border-radius:8px;padding:14px 16px}',
    '.pro-kpi-l{font-size:10px;letter-spacing:.5px;color:#94a3b8;',
    '  text-transform:uppercase;margin-bottom:6px}',
    '.pro-kpi-v{font-size:22px;color:#e2e8f0;font-weight:600;line-height:1.1}',
    /* Numeric column right-align used by the same panel. */
    '.pro-table th.num,.pro-table td.num{text-align:right}',
    /* Severity pills used by Trivy CVE table. */
    '.pill.red{background:rgba(239,68,68,.18);color:#fca5a5;border:1px solid rgba(239,68,68,.35);',
    '  padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}',
    '.pill.amber{background:rgba(251,191,36,.18);color:#fde68a;border:1px solid rgba(251,191,36,.35);',
    '  padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}',
    '.pill.ok{background:rgba(34,197,94,.18);color:#86efac;border:1px solid rgba(34,197,94,.35);',
    '  padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}',
    '.pill.info{background:rgba(34,211,238,.18);color:#67e8f9;border:1px solid rgba(34,211,238,.35);',
    '  padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}',
    '.pill.muted{background:rgba(148,163,184,.12);color:#94a3b8;border:1px solid rgba(148,163,184,.25);',
    '  padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}',
    /* Keep the system sidebar (.sidebar, 220px wide) visible & clickable even
       when a PRO panel is open. The pro-overlay used to cover everything
       (inset:0) — now it starts after the sidebar on viewports wide enough
       for it to be expanded (≥ 900px). Below that, sidebar collapses to 48px
       and we let the overlay take the full width as before. */
    '@media (min-width: 900px) {',
    '  #pro-overlay { left: 220px !important; width: calc(100% - 220px) !important; }',
    '}',
    /* Search filter input used in CSPM/secrets/audit tables. */
    '.vspm-search{display:flex;align-items:center;gap:8px;margin-bottom:10px}',
    '.vspm-search input{flex:1;background:#0f172a;border:1px solid rgba(255,255,255,.08);',
    '  color:#e2e8f0;border-radius:6px;padding:7px 10px;font-size:12px;outline:none}',
    '.vspm-search input:focus{border-color:#22d3ee}',
    '.vspm-search .count{color:#94a3b8;font-size:11px;white-space:nowrap}',
    /* Pagination footer */
    '.vspm-pager{display:flex;justify-content:flex-end;align-items:center;gap:10px;',
    '  margin-top:10px;color:#94a3b8;font-size:11px}',
    '.vspm-pager select{background:#0f172a;border:1px solid rgba(255,255,255,.08);',
    '  color:#e2e8f0;border-radius:4px;padding:3px 6px;font-size:11px}',
    '.vspm-pager button:disabled{opacity:.4;cursor:not-allowed}',
    /* Bulk action bar */
    '.vspm-bulk{display:flex;align-items:center;gap:10px;padding:8px 12px;',
    '  background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.25);',
    '  border-radius:6px;margin-bottom:10px;color:#cbd5e1;font-size:12px}',
    '.vspm-bulk .spacer{flex:1}',
    '.vspm-bulk-checkbox{width:14px;height:14px;cursor:pointer}'
  ].join('\n');
  document.head.appendChild(s);
})();

/* ── core: auth-aware fetch + 402 detection ─────────────────────────────── */
function tokenHeader(){
  var t = localStorage.getItem('TOKEN') ||
          localStorage.getItem('vsp_token') ||
          window.TOKEN || '';
  return t ? { 'Authorization': 'Bearer ' + t } : {};
}

function proFetch(path, opts){
  opts = opts || {};
  var headers = Object.assign({ 'Accept': 'application/json' }, tokenHeader(), opts.headers || {});
  if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  return fetch(path, {
    method: opts.method || 'GET',
    headers: headers,
    credentials: 'same-origin',
    body: opts.body
  }).then(function(r){
    if (r.status === 402){
      return r.json().then(function(j){
        throw { is402: true, required: j.required_plan || 'pro', current: j.current_plan || 'starter', error: j.error };
      }, function(){
        throw { is402: true, required: 'pro', current: 'starter', error: 'Plan upgrade required' };
      });
    }
    if (!r.ok){
      // Try to extract structured error body
      return r.text().then(function(t){
        var msg = 'HTTP ' + r.status;
        try { var j = JSON.parse(t); if (j && j.error) msg = j.error; } catch (_e) {}
        throw new Error(msg);
      });
    }
    return r.status === 204 ? null : r.json();
  });
}
PRO.api = { fetch: proFetch };

/* ── modal + confirm helpers ────────────────────────────────────────────── */
function escAttr(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
  });
}
var esc = escAttr;

function openModal(opts){
  // opts: { title, sub, body (HTMLElement|string), submitLabel, cancelLabel,
  //         danger, onSubmit (returns Promise|undefined), wide }
  return new Promise(function(resolve){
    var ov = document.createElement('div');
    ov.className = 'vspm-overlay';
    ov.innerHTML =
      '<div class="vspm-modal" role="dialog" aria-modal="true" style="' +
        (opts.wide ? 'width:min(720px,90vw)' : '') + '">' +
        '<div class="vspm-modal-body">' +
          '<h3>' + esc(opts.title || '') + '</h3>' +
          (opts.sub ? '<div class="sub">' + esc(opts.sub) + '</div>' : '') +
          '<div class="vspm-error" style="display:none"></div>' +
          '<div class="vspm-content"></div>' +
        '</div>' +
        '<div class="vspm-modal-footer">' +
          '<button class="pro-btn ghost" data-vspm-cancel>' + esc(opts.cancelLabel || 'Cancel') + '</button>' +
          '<button class="pro-btn' + (opts.danger ? ' danger' : '') + '" data-vspm-submit>' +
            esc(opts.submitLabel || 'Save') + '</button>' +
        '</div>' +
      '</div>';
    var content = ov.querySelector('.vspm-content');
    var errBox  = ov.querySelector('.vspm-error');
    if (typeof opts.body === 'string') content.innerHTML = opts.body;
    else if (opts.body) content.appendChild(opts.body);

    document.body.appendChild(ov);
    var firstFocusable = ov.querySelector('input, select, textarea, button');
    if (firstFocusable && firstFocusable.tagName !== 'BUTTON') firstFocusable.focus();

    function close(val){ if (ov.parentNode) ov.parentNode.removeChild(ov); resolve(val); }
    function showErr(msg){ errBox.textContent = msg; errBox.style.display = 'block'; }

    ov.addEventListener('click', function(e){ if (e.target === ov) close(null); });
    ov.querySelector('[data-vspm-cancel]').addEventListener('click', function(){ close(null); });
    ov.querySelector('[data-vspm-submit]').addEventListener('click', function(){
      if (typeof opts.onSubmit !== 'function'){ close(true); return; }
      Promise.resolve(opts.onSubmit(content, showErr)).then(function(result){
        if (result === false) return; // validation rejected
        close(result == null ? true : result);
      }).catch(function(e){ showErr(e && e.message ? e.message : String(e)); });
    });
    // Enter to submit (only if focus is in a single-line input)
    ov.addEventListener('keydown', function(e){
      if (e.key === 'Escape'){ close(null); return; }
      if (e.key === 'Enter' && e.target && e.target.tagName === 'INPUT' && e.target.type !== 'textarea'){
        e.preventDefault();
        ov.querySelector('[data-vspm-submit]').click();
      }
    });
  });
}

// Form modal: fields = [{ id, label, type, value, placeholder, options, required, hint }]
// type ∈ 'text','password','number','select','textarea','checkbox','multiselect','readonly'
function formModal(opts){
  var body = document.createElement('div');
  (opts.fields || []).forEach(function(f){
    var w = document.createElement('div');
    w.className = 'vspm-field';
    var labelHTML = '<label for="vspm-f-' + esc(f.id) + '">' + esc(f.label || f.id) + '</label>';
    var inputHTML = '';
    if (f.type === 'select'){
      inputHTML = '<select id="vspm-f-' + esc(f.id) + '" class="vspm-select">' +
        (f.options || []).map(function(opt){
          var v = typeof opt === 'string' ? opt : opt.value;
          var lbl = typeof opt === 'string' ? opt : (opt.label || opt.value);
          var sel = String(v) === String(f.value || '') ? ' selected' : '';
          return '<option value="' + esc(v) + '"' + sel + '>' + esc(lbl) + '</option>';
        }).join('') +
        '</select>';
    } else if (f.type === 'textarea'){
      inputHTML = '<textarea id="vspm-f-' + esc(f.id) + '" class="vspm-textarea" placeholder="' +
        esc(f.placeholder || '') + '">' + esc(f.value || '') + '</textarea>';
    } else if (f.type === 'checkbox'){
      labelHTML = ''; // we render label inside the row
      inputHTML = '<div class="vspm-checkbox-row">' +
        '<input type="checkbox" id="vspm-f-' + esc(f.id) + '"' + (f.value ? ' checked' : '') + ' />' +
        '<label for="vspm-f-' + esc(f.id) + '">' + esc(f.label || f.id) + '</label></div>';
    } else if (f.type === 'multiselect'){
      var current = Array.isArray(f.value) ? f.value : [];
      inputHTML = '<div class="vspm-multiselect" data-vspm-multi="' + esc(f.id) + '">' +
        (f.options || []).map(function(o){
          var v = typeof o === 'string' ? o : o.value;
          var lbl = typeof o === 'string' ? o : (o.label || o.value);
          var checked = current.indexOf(v) >= 0 ? ' checked' : '';
          return '<label><input name="toggle-option" aria-label="Toggle option" type="checkbox" value="' + esc(v) + '"' + checked + ' /><span>' + esc(lbl) + '</span></label>';
        }).join('') +
        '</div>';
    } else if (f.type === 'readonly'){
      inputHTML = '<input id="vspm-f-' + esc(f.id) + '" class="vspm-input" readonly value="' +
        esc(f.value || '') + '" style="opacity:.7;cursor:not-allowed" />';
    } else {
      inputHTML = '<input id="vspm-f-' + esc(f.id) + '" type="' + esc(f.type || 'text') +
        '" class="vspm-input" value="' + esc(f.value || '') +
        '" placeholder="' + esc(f.placeholder || '') + '" />';
    }
    w.innerHTML = labelHTML + inputHTML +
      (f.hint ? '<div class="hint">' + esc(f.hint) + '</div>' : '');
    body.appendChild(w);
  });

  return openModal({
    title: opts.title, sub: opts.sub,
    submitLabel: opts.submitLabel, cancelLabel: opts.cancelLabel,
    danger: opts.danger, wide: opts.wide,
    body: body,
    onSubmit: function(content, showErr){
      var values = {};
      var bad = null;
      (opts.fields || []).forEach(function(f){
        if (bad) return;
        if (f.type === 'multiselect'){
          var cont = content.querySelector('[data-vspm-multi="' + f.id + '"]');
          values[f.id] = Array.prototype.map.call(
            cont.querySelectorAll('input:checked'), function(i){ return i.value; });
        } else {
          var node = content.querySelector('#vspm-f-' + f.id);
          if (!node) return;
          if (f.type === 'checkbox') values[f.id] = node.checked;
          else if (f.type === 'number') values[f.id] = node.value === '' ? null : Number(node.value);
          else values[f.id] = node.value;
        }
        if (f.required){
          var v = values[f.id];
          if (v == null || (typeof v === 'string' && v.trim() === '') ||
              (Array.isArray(v) && v.length === 0)){
            bad = (f.label || f.id) + ' is required';
          }
        }
      });
      if (bad){ showErr(bad); return false; }
      if (typeof opts.validate === 'function'){
        var msg = opts.validate(values);
        if (msg){ showErr(msg); return false; }
      }
      if (typeof opts.commit === 'function'){
        return opts.commit(values).then(function(r){ return r == null ? values : r; });
      }
      return values;
    }
  });
}

function confirmModal(opts){
  var body = document.createElement('div');
  body.style.color = '#cbd5e1';
  body.style.fontSize = '12px';
  body.innerHTML = esc(opts.message || 'Are you sure?');
  return openModal({
    title: opts.title || 'Confirm',
    body: body,
    submitLabel: opts.dangerLabel || 'Confirm',
    cancelLabel: opts.cancelLabel || 'Cancel',
    danger: !!opts.danger
  }).then(function(v){ return v === true; });
}

PRO.ui = { modal: openModal, form: formModal, confirm: confirmModal };
// Expose formModal for same-origin iframes (SIEM panel companion). Cross-frame
// access works because iframes under /panels/* share this origin.
window.VSP_PRO_FORM_MODAL = formModal;
window.VSP_PRO_OPEN_MODAL = openModal;

/* ── upgrade overlay ────────────────────────────────────────────────────── */
function upgradeOverlayHTML(featureLabel, required, current){
  var req = (required || 'pro').toUpperCase();
  var cur = (current || 'starter');
  return '' +
  '<div style="padding:48px 32px;text-align:center;background:linear-gradient(180deg,rgba(34,211,238,0.08),transparent);border:1px solid rgba(34,211,238,0.25);border-radius:10px">' +
    '<div style="font-size:11px;letter-spacing:2px;color:#22d3ee;margin-bottom:8px">' + req + ' FEATURE</div>' +
    '<div style="font-size:20px;color:#e2e8f0;margin-bottom:6px;font-weight:600">' + esc(featureLabel) + '</div>' +
    '<div style="font-size:12px;color:#94a3b8;margin-bottom:24px">' +
      'Your tenant is on the <code style="color:#fbbf24">' + esc(cur) + '</code> plan. ' +
      'Upgrade to <code style="color:#22d3ee">' + esc(req.toLowerCase()) + '</code> to enable this module.' +
    '</div>' +
    '<button class="pro-btn" onclick="VSP_PRO.upgradeContact()">Contact sales →</button>' +
    '<button class="pro-btn ghost" style="margin-left:8px" onclick="VSP_PRO.upgradeOpenBilling()">Open billing</button>' +
    '<div style="margin-top:24px;font-size:10px;color:#64748b">Backend returned HTTP 402 PaymentRequired</div>' +
  '</div>';
}

PRO.upgradeContact = function(){
  if (typeof window.toast === 'function') window.toast('Sales notified — expect a follow-up within 1 business day','info');
  else openModal({ title: 'Contact sales', body: 'Sales has been notified. They will reach out within 1 business day.', submitLabel: 'OK', cancelLabel: '' });
};
PRO.upgradeOpenBilling = function(){
  try { window.location.hash = '#billing'; } catch (_e) {}
};

/* ── shared render helpers ──────────────────────────────────────────────── */
function loading(root, msg){
  root.innerHTML = '<div style="padding:40px;text-align:center;color:#7d8aa0;font-size:11px;letter-spacing:1px">' +
    (msg || 'LOADING…') + '</div>';
}
function errorBanner(msg){
  return '<div style="padding:8px 14px;background:#3f1d1d;border-left:3px solid #ef4444;' +
         'color:#fca5a5;font-size:11px;margin-bottom:12px;border-radius:4px">' +
         esc(msg) + '</div>';
}
function backButton(featureID){
  return '<button class="pro-btn ghost" onclick="VSP_PRO.openPanel(\'' + featureID + '\')">← Back to panel</button>';
}
function configureBtn(featureID){
  return '<button class="pro-btn ghost" style="font-size:10px" ' +
         'onclick="VSP_PRO.openConfig(\'' + featureID + '\')">⚙ Configure</button>';
}
function kpiCard(label, val, sub, color){
  return '<div class="pro-card">' +
         '<div class="lbl">' + esc(label) + '</div>' +
         '<div class="val" style="color:' + color + '">' + esc(String(val)) + '</div>' +
         '<div class="sub">' + esc(sub) + '</div></div>';
}
function refreshPanel(id){
  var body = document.getElementById('pro-body');
  if (body && PRO.modules[id]) PRO.modules[id].render(body);
}
function renderInPanelBody(html){
  var body = document.getElementById('pro-body');
  if (body) body.innerHTML = html;
  return body;
}

/* ════════════════════════════════════════════════════════════════════════
   MODULE: CSPM
   ════════════════════════════════════════════════════════════════════════ */
var origCSPM = PRO.modules.cspm.render;
PRO.modules.cspm.render = function(root){
  loading(root, 'FETCHING POSTURE FROM /api/v1/cspm/posture …');
  Promise.all([
    proFetch('/api/v1/cspm/accounts'),
    proFetch('/api/v1/cspm/posture'),
    proFetch('/api/v1/cspm/findings?limit=50')
  ]).then(function(results){
    renderCSPMReal(root, results[0], results[1], results[2]);
  }).catch(function(err){
    if (err && err.is402){
      root.innerHTML = upgradeOverlayHTML('Cloud posture (CSPM)', err.required, err.current);
      return;
    }
    console.warn('[VSP-PRO-REALAPI] cspm fallback:', err.message || err);
    origCSPM.call(PRO.modules.cspm, root);
    root.insertAdjacentHTML('afterbegin', errorBanner('CSPM API offline — showing mock data: ' + (err.message || err)));
  });
};

function renderCSPMReal(root, accountsResp, postureResp, findingsResp){
  var accounts = (accountsResp && accountsResp.accounts) || [];
  var posture  = (postureResp && postureResp.posture) || [];
  var findings = (findingsResp && findingsResp.findings) || [];

  var totalCrit = 0, totalHigh = 0, totalOpen = 0, avgScore = 0;
  posture.forEach(function(p){
    totalCrit += (p.critical||0); totalHigh += (p.high||0);
    totalOpen += (p.open_findings||0); avgScore += (p.score||0);
  });
  if (posture.length) avgScore = Math.round(avgScore / posture.length);
  var postColor = avgScore >= 80 ? '#22c55e' : avgScore >= 60 ? '#fbbf24' : '#ef4444';

  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn" onclick="VSP_PRO.cspmAddAccount()">+ Connect account</button>' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.cspmRefresh()">↻ Refresh</button>' +
            '<div class="spacer"></div>' + configureBtn('cspm') +
          '</div>';

  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('Accounts',        accounts.length,             'multi-cloud',     '#22d3ee') +
    kpiCard('Open findings',   totalOpen,                   'across providers','#fbbf24') +
    kpiCard('CRITICAL',        totalCrit,                   'immediate action','#ef4444') +
    kpiCard('Avg posture',     (avgScore || 100)+'/100',    'CIS benchmark',   postColor) +
    '</div>';

  if (accounts.length === 0){
    html += '<div class="vspm-empty">' +
            '<div class="lead">No cloud accounts connected yet</div>' +
            '<button class="pro-btn" onclick="VSP_PRO.cspmAddAccount()">+ Connect AWS / Azure / GCP</button>' +
            '</div>';
  } else {
    html += '<div class="pro-section-h">Connected accounts</div>';
    html += '<table class="pro-table"><thead><tr>' +
            '<th>Provider</th><th>Name</th><th>External ID</th><th>Status</th><th>Last sync</th><th>Action</th>' +
            '</tr></thead><tbody>';
    accounts.forEach(function(a){
      var stPill = a.status === 'active' ? '<span class="pro-pill ok">active</span>' :
                   a.status === 'pending' ? '<span class="pro-pill info">pending</span>' :
                   a.status === 'error' ? '<span class="pro-pill err">error</span>' :
                   '<span class="pro-pill muted">' + esc(a.status) + '</span>';
      var when = a.last_sync_at ? new Date(a.last_sync_at).toLocaleString() : '—';
      html += '<tr><td><span class="pro-pill info">' + esc(a.provider) + '</span></td>' +
              '<td>' + esc(a.name) + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(a.external_id) + '</td>' +
              '<td>' + stPill + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(when) + '</td>' +
              '<td><button class="pro-btn ghost" onclick="VSP_PRO.cspmSync(\'' + esc(a.id) + '\')">Sync</button> ' +
                  '<button class="pro-btn ghost" onclick="VSP_PRO.cspmDelAccount(\'' + esc(a.id) + '\',\'' + esc(a.name) + '\')">Remove</button></td></tr>';
    });
    html += '</tbody></table>';
  }

  if (findings.length > 0){
    html += '<div class="pro-section-h" style="margin-top:18px">Recent findings (' + findings.length + ')</div>';
    html += '<table class="pro-table"><thead><tr>' +
            '<th>Severity</th><th>Resource</th><th>Rule</th><th>Status</th><th>Detected</th>' +
            '</tr></thead><tbody>';
    findings.slice(0, 25).forEach(function(f){
      var sevC = f.severity === 'critical' ? 'err' : f.severity === 'high' ? 'warn' : 'info';
      var stC  = f.status === 'open' ? 'warn' : f.status === 'resolved' ? 'ok' : 'muted';
      html += '<tr><td><span class="pro-pill ' + sevC + '">' + esc(f.severity.toUpperCase()) + '</span></td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(f.resource) + '</td>' +
              '<td>' + esc(f.rule_name || f.rule_id) + '</td>' +
              '<td><span class="pro-pill ' + stC + '">' + esc(f.status) + '</span></td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(new Date(f.detected_at).toLocaleString()) + '</td></tr>';
    });
    html += '</tbody></table>';
  }
  root.innerHTML = html;
}

PRO.cspmRefresh = function(){ refreshPanel('cspm'); };
PRO.cspmAddAccount = function(){
  formModal({
    title: 'Connect cloud account',
    sub: 'Register a cloud subscription so the CSPM scanner can ingest its findings.',
    submitLabel: 'Connect',
    fields: [
      { id: 'provider', label: 'Provider', type: 'select', value: 'aws', required: true,
        options: ['aws', 'azure', 'gcp', 'kubernetes', 'other'] },
      { id: 'name', label: 'Display name', type: 'text', placeholder: 'e.g. Production AWS', required: true },
      { id: 'external_id', label: 'External ID', type: 'text',
        placeholder: 'AWS account number / Azure subscription ID / GCP project', required: true,
        hint: 'How the provider identifies this account in its own console.' }
    ],
    commit: function(v){
      return proFetch('/api/v1/cspm/accounts', {
        method: 'POST',
        body: JSON.stringify({ provider: v.provider, name: v.name.trim(), external_id: v.external_id.trim() })
      });
    }
  }).then(function(v){ if (v) refreshPanel('cspm'); })
    .catch(function(e){ console.error(e); });
};
PRO.cspmSync = function(id){
  proFetch('/api/v1/cspm/accounts/' + encodeURIComponent(id) + '/sync', { method: 'POST' })
    .then(function(){
      if (typeof window.toast === 'function') window.toast('Resync queued — connector will run within 60s', 'success');
      refreshPanel('cspm');
    })
    .catch(function(e){ openModal({ title: 'Sync failed', body: esc(e.error || e.message || e), submitLabel: 'OK', cancelLabel: '' }); });
};
PRO.cspmDelAccount = function(id, name){
  confirmModal({
    title: 'Remove cloud account',
    message: 'Remove "' + (name || id) + '" and ALL its findings? This cannot be undone.',
    danger: true, dangerLabel: 'Remove account'
  }).then(function(yes){
    if (!yes) return;
    return proFetch('/api/v1/cspm/accounts/' + encodeURIComponent(id), { method: 'DELETE' })
      .then(function(){ refreshPanel('cspm'); });
  }).catch(function(e){ openModal({ title: 'Delete failed', body: esc(e.error || e.message || e), submitLabel: 'OK', cancelLabel: '' }); });
};

/* ════════════════════════════════════════════════════════════════════════
   MODULE: SECRET VAULT
   ════════════════════════════════════════════════════════════════════════ */
var origSecrets = PRO.modules.secrets_vault.render;
PRO.modules.secrets_vault.render = function(root){
  loading(root, 'LOADING SECRETS FROM /api/v1/soar/secrets …');
  Promise.all([
    proFetch('/api/v1/soar/secrets'),
    proFetch('/api/v1/soar/secrets/summary')
  ]).then(function(results){
    renderSecretsReal(root, results[0], results[1]);
  }).catch(function(err){
    if (err && err.is402){
      root.innerHTML = upgradeOverlayHTML('Secret vault', err.required, err.current);
      return;
    }
    console.warn('[VSP-PRO-REALAPI] secrets_vault fallback:', err.message || err);
    origSecrets.call(PRO.modules.secrets_vault, root);
    root.insertAdjacentHTML('afterbegin', errorBanner('Vault API offline — showing mock data: ' + (err.message || err)));
  });
};

function renderSecretsReal(root, listResp, summaryResp){
  var secrets = (listResp && listResp.secrets) || [];
  var sum = summaryResp || { total: 0, stale_count: 0, overdue_count: 0, rotation_days: 90 };

  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn" onclick="VSP_PRO.secretAdd()">+ Add secret</button>' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.secretAuditAll()">View audit log</button>' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.secretRefresh()">↻ Refresh</button>' +
            '<div class="spacer"></div>' + configureBtn('secrets_vault') +
          '</div>';

  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('Total',         sum.total,           'stored secrets',  '#22d3ee') +
    kpiCard('Stale (30d)',   sum.stale_count,     'unused recently', sum.stale_count ? '#fbbf24' : '#22c55e') +
    kpiCard('Overdue',       sum.overdue_count,   'past rotation',   sum.overdue_count ? '#ef4444' : '#22c55e') +
    kpiCard('Rotation',      sum.rotation_days + 'd', 'policy',      '#94a3b8') +
    '</div>';

  if (secrets.length === 0){
    html += '<div class="vspm-empty">' +
            '<div class="lead">No secrets yet — values are encrypted with VSP_REPO_KEY before storage</div>' +
            '<button class="pro-btn" onclick="VSP_PRO.secretAdd()">+ Add first secret</button>' +
            '</div>';
  } else {
    html += '<div class="pro-section-h">Stored secrets (values never exposed)</div>';
    html += '<table class="pro-table"><thead><tr>' +
            '<th>Name</th><th>Description</th><th>Created by</th><th>Created</th><th>Last used</th><th>Used #</th><th>Action</th>' +
            '</tr></thead><tbody>';
    secrets.forEach(function(s){
      html += '<tr><td><strong>' + esc(s.name) + '</strong></td>' +
              '<td>' + esc(s.description || '') + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(s.created_by || '') + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(new Date(s.created_at).toLocaleDateString()) + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + (s.last_used_at ? esc(new Date(s.last_used_at).toLocaleString()) : '—') + '</td>' +
              '<td class="pro-mono">' + (s.use_count || 0) + '</td>' +
              '<td><button class="pro-btn ghost" onclick="VSP_PRO.secretRotate(\'' + esc(s.name) + '\')">Rotate</button> ' +
                  '<button class="pro-btn ghost" onclick="VSP_PRO.secretAudit(\'' + esc(s.name) + '\')">Audit</button> ' +
                  '<button class="pro-btn ghost" onclick="VSP_PRO.secretDelete(\'' + esc(s.name) + '\')">Delete</button></td></tr>';
    });
    html += '</tbody></table>';
  }
  root.innerHTML = html;
}

PRO.secretRefresh = function(){ refreshPanel('secrets_vault'); };
PRO.secretAdd = function(){
  formModal({
    title: 'Add secret to vault',
    sub: 'Stored encrypted with VSP_REPO_KEY. The plaintext value is never returned by any API.',
    submitLabel: 'Store',
    fields: [
      { id: 'name', label: 'Name', type: 'text', required: true,
        placeholder: 'e.g. github_pat or stripe_api_key',
        hint: 'Allowed: a-z, A-Z, 0-9, _, -. Max 64 chars.' },
      { id: 'value', label: 'Value', type: 'password', required: true,
        placeholder: 'paste secret value', hint: 'Encrypted on the server. Never displayed back.' },
      { id: 'description', label: 'Description', type: 'text',
        placeholder: 'optional — what is this for?' }
    ],
    validate: function(v){
      if (!/^[a-zA-Z0-9_\-]{1,64}$/.test(v.name)) return 'Name must be 1–64 chars [a-zA-Z0-9_-]';
      return null;
    },
    commit: function(v){
      return proFetch('/api/v1/soar/secrets', { method: 'POST',
        body: JSON.stringify({ name: v.name, value: v.value, description: v.description }) });
    }
  }).then(function(v){ if (v) refreshPanel('secrets_vault'); })
    .catch(function(e){ console.error(e); });
};
PRO.secretRotate = function(name){
  formModal({
    title: 'Rotate "' + name + '"',
    sub: 'The new ciphertext replaces the existing one atomically. The "rotate" event is added to the audit log.',
    submitLabel: 'Rotate now', danger: true,
    fields: [
      { id: 'name', label: 'Secret', type: 'readonly', value: name },
      { id: 'value', label: 'New value', type: 'password', required: true,
        placeholder: 'paste new secret value' }
    ],
    commit: function(v){
      return proFetch('/api/v1/soar/secrets/' + encodeURIComponent(name) + '/rotate',
        { method: 'POST', body: JSON.stringify({ value: v.value }) });
    }
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('Rotated "' + name + '" — old ciphertext invalidated','success');
    if (v) refreshPanel('secrets_vault');
  }).catch(function(e){ console.error(e); });
};
PRO.secretDelete = function(name){
  confirmModal({
    title: 'Delete secret',
    message: 'Delete "' + name + '"? Anything that resolves this name at runtime will fail. This cannot be undone.',
    danger: true, dangerLabel: 'Delete secret'
  }).then(function(yes){
    if (!yes) return;
    return proFetch('/api/v1/soar/secrets/' + encodeURIComponent(name), { method: 'DELETE' })
      .then(function(){ refreshPanel('secrets_vault'); });
  }).catch(function(e){ openModal({ title: 'Delete failed', body: esc(e.error || e.message || e), submitLabel: 'OK', cancelLabel: '' }); });
};
PRO.secretAudit = function(name){ openSecretAuditPanel(name); };
PRO.secretAuditAll = function(){ openSecretAuditPanel(null); };

function openSecretAuditPanel(name){
  var body = document.getElementById('pro-body');
  if (!body) return;
  loading(body, 'LOADING AUDIT LOG …');
  var url = '/api/v1/soar/secrets/audit?limit=200' + (name ? '&name=' + encodeURIComponent(name) : '');
  proFetch(url).then(function(resp){
    var entries = (resp && resp.entries) || [];
    var html = '<div class="vspm-back">' + backButton('secrets_vault') +
               '<div style="color:#94a3b8;font-size:11px">' +
                 (name ? 'Audit for <strong style="color:#cbd5e1">' + esc(name) + '</strong>' : 'All secret access events') +
               '</div></div>';
    // Summary stats above the table — gives the page real "data" feel
    // even when many rows have empty run_id (admin-driven mutations).
    var counts = { access: 0, create: 0, rotate: 0, delete: 0, other: 0 };
    var actors = {};
    entries.forEach(function(e){
      counts[e.action] = (counts[e.action] || 0) + 1;
      if (e.actor) actors[e.actor] = (actors[e.actor] || 0) + 1;
    });
    html += '<div class="pro-grid c4" style="margin-bottom:16px">' +
      kpiCard('Access',  counts.access  || 0, 'reads at runtime', '#22d3ee') +
      kpiCard('Rotate',  counts.rotate  || 0, 'value updated',    counts.rotate ? '#fbbf24' : '#94a3b8') +
      kpiCard('Create',  counts.create  || 0, 'new secrets',      '#22c55e') +
      kpiCard('Delete',  counts.delete  || 0, 'removed',          counts.delete ? '#ef4444' : '#94a3b8') +
      '</div>';

    html += '<div class="pro-section-h">Audit log — ' + entries.length + ' events (newest first)</div>';
    if (entries.length === 0){
      html += '<div class="vspm-empty">No audit events recorded yet.</div>';
    } else {
      html += '<table class="pro-table"><thead><tr>' +
              '<th>When</th><th>Action</th><th>Secret</th><th>Actor</th><th>Context</th>' +
              '</tr></thead><tbody>';
      entries.forEach(function(e){
        var actC = e.action === 'access' ? 'info' : e.action === 'rotate' ? 'warn' :
                   e.action === 'delete' ? 'err' : e.action === 'create' ? 'ok' : 'muted';
        // Audit rows without run_id mean the action came from a UI/API call
        // (admin), not from a playbook run. Show that explicitly so the
        // column doesn't look "missing".
        var ctx;
        if (e.run_id){
          ctx = '<span class="pro-pill info" title="' + esc(e.run_id) + '">run ' + esc(e.run_id.substring(0, 8)) + '…</span>';
        } else if (e.action === 'access'){
          ctx = '<span class="pro-pill muted">runtime</span>';
        } else {
          ctx = '<span class="pro-pill muted">manual (UI/API)</span>';
        }
        // Show short actor for UUIDs (truncate to first 8 chars + …)
        var actor = e.actor || '';
        var actorDisplay = actor.length === 36 ? actor.substring(0, 8) + '…' : actor;
        var actorAttr = actor ? ' title="' + esc(actor) + '"' : '';
        html += '<tr><td class="pro-mono" style="font-size:10px">' + esc(new Date(e.accessed_at).toLocaleString()) + '</td>' +
                '<td><span class="pro-pill ' + actC + '">' + esc(e.action) + '</span></td>' +
                '<td><strong>' + esc(e.secret_name) + '</strong></td>' +
                '<td class="pro-mono" style="font-size:10px"' + actorAttr + '>' + esc(actorDisplay || '—') + '</td>' +
                '<td>' + ctx + '</td></tr>';
      });
      html += '</tbody></table>';
    }
    body.innerHTML = html;
  }).catch(function(err){
    if (err && err.is402){ body.innerHTML = upgradeOverlayHTML('Secret audit log', err.required, err.current); return; }
    body.innerHTML = errorBanner('Audit fetch failed: ' + (err.error || err.message || err));
  });
}

/* ════════════════════════════════════════════════════════════════════════
   MODULE: TENANTS
   ════════════════════════════════════════════════════════════════════════ */
var origTenants = PRO.modules.tenants.render;
PRO.modules.tenants.render = function(root){
  loading(root, 'LOADING TENANT DATA …');
  Promise.all([
    proFetch('/api/v1/tenants').catch(function(){ return null; }),
    proFetch('/api/v1/tenants/quota')
  ]).then(function(results){
    renderTenantsReal(root, results[0], results[1]);
  }).catch(function(err){
    if (err && err.is402){
      root.innerHTML = upgradeOverlayHTML('Tenants — quota & usage', err.required, err.current);
      return;
    }
    console.warn('[VSP-PRO-REALAPI] tenants fallback:', err.message || err);
    origTenants.call(PRO.modules.tenants, root);
    root.insertAdjacentHTML('afterbegin', errorBanner('Tenant API offline — showing mock data: ' + (err.message || err)));
  });
};

function renderTenantsReal(root, listResp, quota){
  var tenants = (listResp && listResp.tenants) || [];
  quota = quota || {};

  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.tenantsRefresh()">↻ Refresh</button>' +
            '<div class="spacer"></div>' +
          '</div>';
  html += '<div class="pro-section-h">Current tenant — usage</div>';
  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('Plan',          (quota.plan || '—').toUpperCase(), 'billing tier',  quota.plan === 'pro' || quota.plan === 'enterprise' ? '#22c55e' : '#fbbf24') +
    kpiCard('Scans',         quota.scans || 0,                  'total runs',    '#22d3ee') +
    kpiCard('Open findings', quota.open_findings || 0,          'unresolved',    '#fbbf24') +
    kpiCard('Secrets',       quota.secrets || 0,                'in vault',      '#94a3b8') +
    '</div>';
  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('CSPM accounts', quota.cspm_accounts || 0, 'cloud connected', '#22d3ee') +
    kpiCard('Repos',         quota.repos || 0,         'PR-bot enabled',  '#22d3ee') +
    '<div></div><div></div>' +
    '</div>';

  // Admin-only plan switcher: gives ops the ability to comp tenants up to PRO
  // for trials / support / pilot programs without going through Stripe. Each
  // change writes a TENANT_PLAN_UPDATE entry to audit_log per FedRAMP AU-2.
  var role = '';
  try { role = (window.parent && window.parent.VSPClaims && window.parent.VSPClaims.role) || ''; } catch(e){}
  if (!role) {
    try {
      var tk = window.parent.TOKEN || localStorage.getItem('vsp_token') || '';
      if (tk) {
        var payload = JSON.parse(atob(tk.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
        role = payload.role || '';
      }
    } catch(e){}
  }
  var isAdmin = role === 'admin';

  if (tenants.length){
    html += '<div class="pro-section-h">All tenants' + (isAdmin ? ' <span style="font-size:10px;color:var(--t3);font-weight:normal">— click plan to change</span>' : '') + '</div>';
    html += '<table class="pro-table"><thead><tr><th>Slug</th><th>Name</th><th>Plan</th><th>Created</th></tr></thead><tbody>';
    tenants.forEach(function(t){
      var planCell;
      if (isAdmin) {
        var opts = ['starter','pro','enterprise','free'].map(function(p){
          return '<option value="'+p+'"'+(p === (t.plan || 'starter') ? ' selected' : '')+'>'+p+'</option>';
        }).join('');
        // aria-label + name carry the tenant slug so screen readers / form
        // tooling can disambiguate the dropdown row. Pre-fix the label was
        // "Tid" (derived blindly from data-tid by an aria-sweep) and the
        // element had no id/name at all — Chrome flagged both.
        var slugLbl = esc(t.slug || t.id);
        planCell = '<select aria-label="Plan for tenant '+slugLbl+'" name="plan-'+slugLbl+'" '
          + 'class="pro-plan-select" data-tid="'+esc(t.id)+'" data-prev="'+esc(t.plan||'starter')+'" '
          + 'style="background:var(--bg2);border:1px solid var(--bd);color:var(--t1);padding:2px 6px;font-size:11px;border-radius:3px">'
          + opts + '</select>';
      } else {
        planCell = '<span class="pro-pill ' + (t.plan === 'pro' || t.plan === 'enterprise' ? 'ok' : 'muted') + '">' + esc(t.plan || 'starter') + '</span>';
      }
      // Store underlying data as data-* attrs so the row-click handler
      // (vsp_pro_realapi.js:2104) reads actual DB values instead of
      // .textContent. Admin's <select name="select-option" aria-label="Select option"> cell would otherwise concat all
      // four option labels into "STARTERPROENTERPRISEFREE", and an empty
      // created_at would surface as a literal "" in the modal.
      html += '<tr ' +
              'data-tenant-slug="' + esc(t.slug || t.id) + '" ' +
              'data-tenant-name="' + esc(t.name || '') + '" ' +
              'data-tenant-plan="' + esc(t.plan || 'starter') + '" ' +
              'data-tenant-created="' + esc(t.created_at || '') + '">' +
              '<td class="pro-mono">' + esc(t.slug || t.id) + '</td>' +
              '<td>' + esc(t.name || '') + '</td>' +
              '<td>' + planCell + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(t.created_at ? new Date(t.created_at).toLocaleDateString() : '') + '</td></tr>';
    });
    html += '</tbody></table>';
  }
  root.innerHTML = html;

  // Wire plan-change handler after innerHTML is committed
  if (isAdmin) {
    root.querySelectorAll('.pro-plan-select').forEach(function(sel){
      sel.addEventListener('change', function(){
        var tid = sel.getAttribute('data-tid');
        var prev = sel.getAttribute('data-prev');
        var next = sel.value;
        if (next === prev) return;
        proFetch('/api/v1/admin/tenants/'+encodeURIComponent(tid)+'/plan', {
          method: 'PUT', body: JSON.stringify({ plan: next })
        }).then(function(){
          sel.setAttribute('data-prev', next);
          if (typeof window.toast === 'function') window.toast('Plan changed to '+next, 'success');
          // Refresh quota panel so the current-tenant card reflects new plan
          if (tid) PRO.tenantsRefresh();
        }).catch(function(err){
          sel.value = prev;  // rollback UI
          if (typeof window.toast === 'function') window.toast('Plan change failed: '+(err.message||err), 'error');
        });
      });
    });
  }
}
PRO.tenantsRefresh = function(){ refreshPanel('tenants'); };

/* ════════════════════════════════════════════════════════════════════════
   MODULE: OBSERVABILITY
   ════════════════════════════════════════════════════════════════════════ */
var origObs = PRO.modules.observe.render;
PRO.modules.observe.render = function(root){
  loading(root, 'LOADING OBSERVABILITY CONFIG …');
  proFetch('/api/v1/observability/config').then(function(cfg){
    renderObsReal(root, cfg);
  }).catch(function(err){
    if (err && err.is402){
      root.innerHTML = upgradeOverlayHTML('Observability', err.required, err.current);
      return;
    }
    console.warn('[VSP-PRO-REALAPI] observe fallback:', err.message || err);
    origObs.call(PRO.modules.observe, root);
    root.insertAdjacentHTML('afterbegin', errorBanner('Observability API offline — showing mock data: ' + (err.message || err)));
  });
};

function renderObsReal(root, cfg){
  cfg = cfg || {};
  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn" onclick="VSP_PRO.observeEdit()">⚙ Edit thresholds</button>' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.observeRefresh()">↻ Refresh</button>' +
          '</div>';
  html += '<div class="pro-section-h">Tenant observability config</div>';
  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('CRIT alert ≥',   cfg.alert_critical_threshold || 0, 'findings',   '#ef4444') +
    kpiCard('HIGH alert ≥',   cfg.alert_high_threshold || 0,     'findings',   '#fbbf24') +
    kpiCard('Burn-rate',      cfg.burn_rate_alert_enabled ? 'on' : 'off', 'SLO breach', cfg.burn_rate_alert_enabled ? '#22c55e' : '#94a3b8') +
    kpiCard('Retention',      (cfg.metrics_retention_days || 30) + 'd', 'metrics',  '#22d3ee') +
    '</div>';
  html += '<div style="color:#94a3b8;font-size:11px;padding:8px 0">' +
          'Last updated: ' + (cfg.updated_at ? esc(new Date(cfg.updated_at).toLocaleString()) : '—') +
          '</div>';
  root.innerHTML = html;
}
PRO.observeRefresh = function(){ refreshPanel('observe'); };
PRO.observeEdit = function(){
  proFetch('/api/v1/observability/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'Edit observability thresholds',
      sub: 'These values gate alerts for the calling tenant only. Other tenants are unaffected.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'alert_critical_threshold', label: 'CRITICAL alert threshold', type: 'number',
          value: cfg.alert_critical_threshold || 1, required: true,
          hint: 'Page on-call when ≥ N open CRITICAL findings.' },
        { id: 'alert_high_threshold', label: 'HIGH alert threshold', type: 'number',
          value: cfg.alert_high_threshold || 10, required: true,
          hint: 'Notify (no page) when ≥ N open HIGH findings.' },
        { id: 'metrics_retention_days', label: 'Metrics retention (days)', type: 'number',
          value: cfg.metrics_retention_days || 30, required: true,
          hint: '1–365. Older metrics are aggregated then dropped.' },
        { id: 'burn_rate_alert_enabled', label: 'Enable SLO burn-rate alerts', type: 'checkbox',
          value: !!cfg.burn_rate_alert_enabled }
      ],
      validate: function(v){
        if (v.alert_critical_threshold < 0 || v.alert_critical_threshold > 10000) return 'CRIT threshold 0–10000';
        if (v.alert_high_threshold < 0 || v.alert_high_threshold > 10000) return 'HIGH threshold 0–10000';
        if (v.metrics_retention_days < 1 || v.metrics_retention_days > 365) return 'Retention 1–365 days';
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/observability/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('Observability config saved','success');
    if (v) refreshPanel('observe');
  }).catch(function(e){ console.error(e); });
};

/* ════════════════════════════════════════════════════════════════════════
   Configure sub-panel — proper EDIT FORM per feature
   ════════════════════════════════════════════════════════════════════════ */
PRO.openConfig = function(featureID){
  if (featureID === 'cspm')          return openCspmConfig();
  if (featureID === 'secrets_vault') return openVaultConfig();
  if (featureID === 'observe')       return PRO.observeEdit();
  return PRO.openPanel(featureID);
};

function openCspmConfig(){
  proFetch('/api/v1/cspm/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'CSPM — tenant configuration',
      sub: 'Sync schedule, retention and alerting policy for cloud posture findings.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'sync_interval_min', label: 'Sync interval (minutes)', type: 'number',
          value: cfg.sync_interval_min || 60, required: true,
          hint: '5–1440. How often the connector polls AWS/Azure/GCP.' },
        { id: 'retention_days', label: 'Findings retention (days)', type: 'number',
          value: cfg.retention_days || 90, required: true,
          hint: '7–730. Resolved findings older than this are deleted.' },
        { id: 'auto_fix_enabled', label: 'Enable auto-fix runner', type: 'checkbox',
          value: !!cfg.auto_fix_enabled,
          hint: 'When supported by the rule, applies the remediation without a human step.' },
        { id: 'notify_severities', label: 'Notify on severities', type: 'multiselect',
          value: cfg.notify_severities || ['critical','high'],
          options: [
            { value: 'critical', label: 'CRITICAL' },
            { value: 'high',     label: 'HIGH' },
            { value: 'medium',   label: 'MEDIUM' },
            { value: 'low',      label: 'LOW' },
            { value: 'info',     label: 'INFO' }
          ] }
      ],
      validate: function(v){
        if (v.sync_interval_min < 5 || v.sync_interval_min > 1440) return 'Sync interval 5–1440 min';
        if (v.retention_days < 7 || v.retention_days > 730) return 'Retention 7–730 days';
        if (!v.notify_severities || v.notify_severities.length === 0) return 'Pick at least one severity to notify on';
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/cspm/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('CSPM config saved','success');
    if (v) refreshPanel('cspm');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('CSPM config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

function openVaultConfig(){
  proFetch('/api/v1/soar/secrets/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'Secret vault — tenant configuration',
      sub: 'Rotation policy, audit retention and which providers may be referenced.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'rotation_days', label: 'Rotation policy (days)', type: 'number',
          value: cfg.rotation_days || 90, required: true,
          hint: '1–730. Secrets older than this are flagged "overdue" in the dashboard.' },
        { id: 'audit_retention_days', label: 'Audit log retention (days)', type: 'number',
          value: cfg.audit_retention_days || 365, required: true,
          hint: '7–2555. Compliance baseline is typically 365 (1 year).' },
        { id: 'require_approval', label: 'Require approval for rotate / delete', type: 'checkbox',
          value: !!cfg.require_approval,
          hint: 'When on, mutation calls go into the SOAR approvals queue first.' },
        { id: 'allowed_providers', label: 'Allowed secret providers', type: 'multiselect',
          value: cfg.allowed_providers || ['internal'],
          options: [
            { value: 'internal', label: 'Internal (encrypted in DB)' },
            { value: 'vault',    label: 'HashiCorp Vault' },
            { value: 'kms',      label: 'AWS KMS' },
            { value: 'aws',      label: 'AWS Secrets Manager' },
            { value: 'gcp',      label: 'GCP Secret Manager' },
            { value: 'azure',    label: 'Azure Key Vault' }
          ] }
      ],
      validate: function(v){
        if (v.rotation_days < 1 || v.rotation_days > 730) return 'Rotation 1–730 days';
        if (v.audit_retention_days < 7 || v.audit_retention_days > 2555) return 'Audit retention 7–2555 days';
        if (!v.allowed_providers || v.allowed_providers.length === 0) return 'Select at least one allowed provider';
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/soar/secrets/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('Vault config saved','success');
    if (v) refreshPanel('secrets_vault');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('Vault config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

/* ════════════════════════════════════════════════════════════════════════
   MODULE: PR / repo bot  — full override (was pure mock)
   ════════════════════════════════════════════════════════════════════════ */
var origPRBot = PRO.modules.prbot && PRO.modules.prbot.render;
if (PRO.modules.prbot){
  PRO.modules.prbot.render = function(root){
    loading(root, 'LOADING PRs FROM /api/v1/autofix/pr/list …');
    Promise.all([
      proFetch('/api/v1/autofix/pr/list').catch(function(e){ if (e && e.is402) throw e; return null; }),
      proFetch('/api/v1/autofix/repo/list').catch(function(e){ if (e && e.is402) throw e; return null; })
    ]).then(function(results){ renderPRBotReal(root, results[0], results[1]); })
      .catch(function(err){
        if (err && err.is402){
          root.innerHTML = upgradeOverlayHTML('PR / repo bot', err.required, err.current);
          return;
        }
        console.warn('[VSP-PRO-REALAPI] prbot fallback:', err.message || err);
        if (origPRBot) origPRBot.call(PRO.modules.prbot, root);
        root.insertAdjacentHTML('afterbegin', errorBanner('Auto-PR API offline — showing mock data: ' + (err.message || err)));
      });
  };
}

function renderPRBotReal(root, prResp, repoResp){
  var prs   = (prResp  && (prResp.prs   || prResp.items  || prResp.list  || [])) || [];
  var repos = (repoResp && (repoResp.repos || repoResp.items || repoResp.list || [])) || [];

  var blocking = 0, totalFindings = 0;
  prs.forEach(function(p){
    if (p.blocking || p.status === 'fail' || p.gate === 'fail') blocking++;
    totalFindings += (p.findings || p.total_findings || 0);
  });

  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn" onclick="VSP_PRO.prbotRegisterRepo()">+ Register repo</button>' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.prbotRefresh()">↻ Refresh</button>' +
            '<div class="spacer"></div>' + configureBtn('prbot') +
          '</div>';

  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('Open PRs',       prs.length,    'tracked',         '#22d3ee') +
    kpiCard('Blocked',        blocking,      'gate FAIL',       blocking ? '#ef4444' : '#22c55e') +
    kpiCard('Total findings', totalFindings, 'across all PRs',  '#fbbf24') +
    kpiCard('Repos',          repos.length,  'auto-PR enabled', '#22d3ee') +
    '</div>';

  if (repos.length === 0){
    html += '<div class="vspm-empty">' +
            '<div class="lead">No repositories registered yet</div>' +
            '<button class="pro-btn" onclick="VSP_PRO.prbotRegisterRepo()">+ Register first repo</button>' +
            '</div>';
  } else {
    html += '<div class="pro-section-h">Registered repos (' + repos.length + ')</div>';
    html += '<table class="pro-table"><thead><tr>' +
            '<th>Repo</th><th>Provider</th><th>Branch</th><th>Status</th><th>Webhook</th>' +
            '</tr></thead><tbody>';
    repos.forEach(function(rep){
      var st = rep.active === false ? '<span class="pro-pill muted">disabled</span>' :
                                       '<span class="pro-pill ok">active</span>';
      html += '<tr><td><strong>' + esc(rep.full_name || rep.name || rep.url || '') + '</strong></td>' +
              '<td><span class="pro-pill info">' + esc(rep.provider || 'github') + '</span></td>' +
              '<td class="pro-mono">' + esc(rep.default_branch || rep.branch || 'main') + '</td>' +
              '<td>' + st + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + (rep.webhook_id ? esc(rep.webhook_id) : '—') + '</td></tr>';
    });
    html += '</tbody></table>';
  }

  if (prs.length){
    html += '<div class="pro-section-h" style="margin-top:18px">Active pull requests</div>';
    html += '<table class="pro-table"><thead><tr>' +
            '<th>PR</th><th>Repo</th><th>Title</th><th>Status</th><th>Findings</th><th>Created</th>' +
            '</tr></thead><tbody>';
    prs.slice(0, 50).forEach(function(p){
      var st = p.status || (p.gate === 'fail' ? 'FAIL' : 'PASS');
      var stC = /fail|block/i.test(st) ? 'err' : /warn/i.test(st) ? 'warn' : 'ok';
      html += '<tr><td class="pro-mono">#' + esc(p.number || p.pr_id || p.id || '?') + '</td>' +
              '<td>' + esc(p.repo || p.repo_name || '') + '</td>' +
              '<td>' + esc(p.title || '') + '</td>' +
              '<td><span class="pro-pill ' + stC + '">' + esc(st) + '</span></td>' +
              '<td class="pro-mono">' + (p.findings || p.total_findings || 0) + '</td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(p.created_at ? new Date(p.created_at).toLocaleDateString() : '') + '</td></tr>';
    });
    html += '</tbody></table>';
  }
  root.innerHTML = html;
}

PRO.prbotRefresh = function(){ refreshPanel('prbot'); };
PRO.prbotRegisterRepo = function(){
  formModal({
    title: 'Register repository for auto-PR',
    sub: 'The bot will open remediation PRs against the default branch.',
    submitLabel: 'Register',
    fields: [
      { id: 'provider', label: 'Provider', type: 'select', value: 'github', required: true,
        options: [{value:'github',label:'GitHub'},{value:'gitlab',label:'GitLab'},{value:'bitbucket',label:'Bitbucket'}] },
      { id: 'full_name', label: 'Full name', type: 'text', required: true,
        placeholder: 'org/repo (e.g. acme/payments-api)' },
      { id: 'default_branch', label: 'Default branch', type: 'text', value: 'main', required: true },
      { id: 'webhook_secret', label: 'Webhook secret', type: 'password',
        hint: 'HMAC secret used to validate inbound webhooks. Leave blank to skip webhook setup.' }
    ],
    commit: function(v){
      return proFetch('/api/v1/autofix/repo/register', { method: 'POST',
        body: JSON.stringify({
          provider: v.provider, full_name: v.full_name.trim(),
          default_branch: v.default_branch.trim(), webhook_secret: v.webhook_secret || ''
        }) });
    }
  }).then(function(v){ if (v) refreshPanel('prbot'); })
    .catch(function(e){ console.error(e); });
};

/* ════════════════════════════════════════════════════════════════════════
   MODULE: SBOM diff  — full override (was pure mock)
   ════════════════════════════════════════════════════════════════════════ */
var origSbomDiff = PRO.modules.sbomdiff && PRO.modules.sbomdiff.render;
if (PRO.modules.sbomdiff){
  PRO.modules.sbomdiff.render = function(root){
    loading(root, 'LOADING SBOM CONFIG …');
    proFetch('/api/v1/sbom/config').then(function(cfg){
      renderSbomReal(root, cfg);
    }).catch(function(err){
      if (err && err.is402){
        root.innerHTML = upgradeOverlayHTML('SBOM diff', err.required, err.current);
        return;
      }
      console.warn('[VSP-PRO-REALAPI] sbomdiff fallback:', err.message || err);
      if (origSbomDiff) origSbomDiff.call(PRO.modules.sbomdiff, root);
      root.insertAdjacentHTML('afterbegin', errorBanner('SBOM API offline — showing mock data: ' + (err.message || err)));
    });
  };
}

function renderSbomReal(root, cfg){
  cfg = cfg || {};
  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.sbomRefresh()">↻ Refresh</button>' +
            '<div class="spacer"></div>' + configureBtn('sbomdiff') +
          '</div>';
  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('Format',         (cfg.sbom_format||'cyclonedx').toUpperCase(), 'output spec', '#22d3ee') +
    kpiCard('Diff alert',     (cfg.diff_alert_severity||'high').toUpperCase(), 'min severity',
            cfg.diff_alert_severity === 'critical' ? '#ef4444' :
            cfg.diff_alert_severity === 'high' ? '#fbbf24' : '#22d3ee') +
    kpiCard('New CRIT alert', cfg.alert_on_new_critical ? 'on' : 'off', 'paging',
            cfg.alert_on_new_critical ? '#22c55e' : '#94a3b8') +
    kpiCard('Auto-generate',  cfg.auto_generate ? 'on' : 'off', 'on every scan',
            cfg.auto_generate ? '#22c55e' : '#94a3b8') +
    '</div>';
  html += '<div style="color:#94a3b8;font-size:11px;margin-top:8px">' +
          'Per-run SBOMs: <code>GET /api/v1/sbom/{rid}</code> · Diff: <code>GET /api/v1/sbom/{rid}/diff</code></div>';
  html += '<div style="color:#94a3b8;font-size:11px">Last config update: ' +
          (cfg.updated_at ? esc(new Date(cfg.updated_at).toLocaleString()) : '—') + '</div>';
  root.innerHTML = html;
}
PRO.sbomRefresh = function(){ refreshPanel('sbomdiff'); };

/* ════════════════════════════════════════════════════════════════════════
   MODULE: SSO / SAML  — full override (was pure mock)
   ════════════════════════════════════════════════════════════════════════ */
var origSSO = PRO.modules.sso && PRO.modules.sso.render;
if (PRO.modules.sso){
  PRO.modules.sso.render = function(root){
    loading(root, 'LOADING SSO PROVIDERS …');
    Promise.all([
      proFetch('/api/v1/sso/providers').catch(function(e){ if (e && e.is402) throw e; return null; }),
      proFetch('/api/v1/sso/config').catch(function(e){ if (e && e.is402) throw e; return null; })
    ]).then(function(results){ renderSSOReal(root, results[0], results[1]); })
      .catch(function(err){
        if (err && err.is402){
          root.innerHTML = upgradeOverlayHTML('SSO / SAML', err.required, err.current);
          return;
        }
        console.warn('[VSP-PRO-REALAPI] sso fallback:', err.message || err);
        if (origSSO) origSSO.call(PRO.modules.sso, root);
        root.insertAdjacentHTML('afterbegin', errorBanner('SSO API offline — showing mock data: ' + (err.message || err)));
      });
  };
}

function renderSSOReal(root, provResp, cfg){
  cfg = cfg || {};
  var providers = (provResp && (provResp.providers || provResp.items || provResp.list)) ||
                  (Array.isArray(provResp) ? provResp : []);

  var html = '';
  html += '<div class="vspm-toolbar">' +
            '<button class="pro-btn" onclick="VSP_PRO.ssoAddProvider()">+ Add IdP</button>' +
            '<button class="pro-btn ghost" onclick="VSP_PRO.ssoRefresh()">↻ Refresh</button>' +
            '<div class="spacer"></div>' + configureBtn('sso') +
          '</div>';

  html += '<div class="pro-grid c4" style="margin-bottom:18px">' +
    kpiCard('Providers',       providers.length, 'configured IdPs', '#22d3ee') +
    kpiCard('Default role',    (cfg.default_role || 'analyst').toUpperCase(), 'JIT users', '#94a3b8') +
    kpiCard('SCIM',            cfg.scim_enabled ? 'on' : 'off', 'auto provisioning',
            cfg.scim_enabled ? '#22c55e' : '#94a3b8') +
    kpiCard('Require MFA',     cfg.require_mfa ? 'yes' : 'no', 'after SSO login',
            cfg.require_mfa ? '#22c55e' : '#fbbf24') +
    '</div>';

  if (providers.length === 0){
    html += '<div class="vspm-empty">' +
            '<div class="lead">No identity providers configured</div>' +
            '<button class="pro-btn" onclick="VSP_PRO.ssoAddProvider()">+ Add first IdP</button>' +
            '</div>';
  } else {
    html += '<div class="pro-section-h">Identity providers</div>';
    html += '<table class="pro-table"><thead><tr>' +
            '<th>Name</th><th>Type</th><th>Issuer / Entity ID</th><th>Status</th><th>Action</th>' +
            '</tr></thead><tbody>';
    providers.forEach(function(p){
      var enabled = p.enabled !== false;
      var st = enabled ? '<span class="pro-pill ok">enabled</span>' :
                         '<span class="pro-pill muted">disabled</span>';
      html += '<tr><td><strong>' + esc(p.name || p.provider_name || '') + '</strong></td>' +
              '<td><span class="pro-pill info">' + esc(p.type || p.kind || 'oidc') + '</span></td>' +
              '<td class="pro-mono" style="font-size:10px">' + esc(p.issuer || p.entity_id || p.metadata_url || '') + '</td>' +
              '<td>' + st + '</td>' +
              '<td><button class="pro-btn ghost" onclick="VSP_PRO.ssoTestProvider(\'' + esc(p.id || p.name) + '\')">Test login</button></td></tr>';
    });
    html += '</tbody></table>';
  }
  root.innerHTML = html;
}
PRO.ssoRefresh = function(){ refreshPanel('sso'); };
PRO.ssoTestProvider = function(id){
  // Backend handler at internal/api/handler/sso_oidc.go:148 reads
  // r.URL.Query().Get("provider_id") — the param name is provider_id,
  // NOT provider. Mismatch returned {"error":"provider_id required"}
  // when the user clicked "Test login" from this inline panel.
  if (!id) {
    if (typeof window.toast === 'function') window.toast('No provider id — cannot test','error');
    return;
  }
  if (typeof window.toast === 'function') window.toast('Test login flow opened in new tab — check provider redirect','info');
  try { window.open('/api/v1/auth/sso/login?provider_id=' + encodeURIComponent(id), '_blank'); } catch (_e) {}
};
PRO.ssoAddProvider = function(){
  formModal({
    title: 'Add identity provider',
    sub: 'OIDC providers are tested via the discovery URL. SAML providers need metadata XML.',
    submitLabel: 'Add provider',
    fields: [
      { id: 'name', label: 'Display name', type: 'text', required: true,
        placeholder: 'e.g. Okta Production' },
      { id: 'type', label: 'Type', type: 'select', value: 'oidc', required: true,
        options: [{value:'oidc',label:'OIDC'},{value:'saml',label:'SAML 2.0'}] },
      { id: 'issuer', label: 'Issuer / Discovery URL', type: 'text', required: true,
        placeholder: 'https://idp.example.com/.well-known/openid-configuration',
        hint: 'For SAML, paste the IdP entity ID instead.' },
      { id: 'client_id', label: 'Client ID', type: 'text', required: true },
      { id: 'client_secret', label: 'Client secret', type: 'password',
        hint: 'Leave blank for SAML — IdP signs assertions with its private key.' }
    ],
    commit: function(v){
      return proFetch('/api/v1/sso/providers', { method: 'POST',
        body: JSON.stringify({
          name: v.name.trim(), type: v.type, issuer: v.issuer.trim(),
          client_id: v.client_id.trim(), client_secret: v.client_secret || ''
        }) });
    }
  }).then(function(v){ if (v) refreshPanel('sso'); })
    .catch(function(e){ console.error(e); });
};

/* ════════════════════════════════════════════════════════════════════════
   WRAP existing render: cwpp + supplychain → inject Configure button
   These two panels are already wired by their own *_realapi.js companions
   (real Trivy data / real cosign data). We don't replace them — just
   inject a Configure button into the rendered DOM after they finish.
   ════════════════════════════════════════════════════════════════════════ */
function injectConfigureBtn(root, featureID){
  if (!root) return;
  if (root.querySelector('[data-vspm-config]')) return; // already injected
  var bar = document.createElement('div');
  bar.style.cssText = 'display:flex;justify-content:flex-end;margin:0 0 10px 0';
  bar.innerHTML = '<button data-vspm-config class="pro-btn ghost" style="font-size:10px" ' +
                  'onclick="VSP_PRO.openConfig(\'' + featureID + '\')">⚙ Configure</button>';
  root.insertBefore(bar, root.firstChild);
}

(function wrapWithConfigure(featureID){
  var m = PRO.modules[featureID];
  if (!m || !m.render) return;
  var orig = m.render;
  m.render = function(root){
    var ret = orig.call(this, root);
    // Original render may be sync or return a promise — handle both, plus
    // any async DOM updates by polling once after a microtask.
    Promise.resolve(ret).then(function(){
      injectConfigureBtn(root, featureID);
      // Real-API fetches in those panels mutate root after a delay; re-inject.
      setTimeout(function(){ injectConfigureBtn(root, featureID); }, 1200);
      setTimeout(function(){ injectConfigureBtn(root, featureID); }, 3000);
    });
    return ret;
  };
})('cwpp');
(function wrapWithConfigure(featureID){
  var m = PRO.modules[featureID];
  if (!m || !m.render) return;
  var orig = m.render;
  m.render = function(root){
    var ret = orig.call(this, root);
    Promise.resolve(ret).then(function(){
      injectConfigureBtn(root, featureID);
      setTimeout(function(){ injectConfigureBtn(root, featureID); }, 1200);
      setTimeout(function(){ injectConfigureBtn(root, featureID); }, 3000);
    });
    return ret;
  };
})('supplychain');

/* ════════════════════════════════════════════════════════════════════════
   Configure router — extend openConfig to handle the 4 new panels
   ════════════════════════════════════════════════════════════════════════ */
var prevOpenConfig = PRO.openConfig;
PRO.openConfig = function(featureID){
  if (featureID === 'cwpp')        return openCwppConfig();
  if (featureID === 'supplychain') return openSupplyChainConfig();
  if (featureID === 'prbot')       return openPRBotConfig();
  if (featureID === 'sbomdiff')    return openSBOMConfig();
  if (featureID === 'sso')         return openSSOConfig();
  return prevOpenConfig.call(this, featureID);
};

function openCwppConfig(){
  proFetch('/api/v1/cwpp/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'Container security — scanner policy',
      sub: 'Trivy scan thresholds, K8s admission gating, and the registry allowlist.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'alert_critical_threshold', label: 'Page on-call when ≥ N CRITICAL CVEs', type: 'number',
          value: cfg.alert_critical_threshold || 1, required: true,
          hint: '0–1000. 0 disables the threshold. Sends to the configured Observability channel.' },
        { id: 'block_admission_on_crit', label: 'Block K8s admission if image has CRITICAL CVEs', type: 'checkbox',
          value: !!cfg.block_admission_on_crit,
          hint: 'Cluster image policy webhook denies the pod until the image is patched.' },
        { id: 'scan_on_push', label: 'Auto-scan every newly-pushed image', type: 'checkbox',
          value: cfg.scan_on_push !== false,
          hint: 'When off, images are only scanned via explicit POST /api/v1/container/scan.' },
        { id: 'max_scan_age_hours', label: 'Re-scan images older than (hours)', type: 'number',
          value: cfg.max_scan_age_hours || 24, required: true,
          hint: '1–720. The worker rescans any image whose last scan is older than this.' },
        { id: 'registry_allowlist', label: 'Registry allowlist (comma-separated globs)', type: 'textarea',
          value: cfg.registry_allowlist || '',
          placeholder: 'registry.acme.com/**, ghcr.io/myorg/*',
          hint: 'Images matching any glob skip extra signature checks. Leave blank to require signatures everywhere.' }
      ],
      validate: function(v){
        if (v.alert_critical_threshold < 0 || v.alert_critical_threshold > 1000) return 'CRIT threshold 0–1000';
        if (v.max_scan_age_hours < 1 || v.max_scan_age_hours > 720) return 'Re-scan age 1–720 hours';
        if (v.registry_allowlist && v.registry_allowlist.length > 4000) return 'Allowlist too long (max 4000 chars)';
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/cwpp/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('Container security config saved','success');
    if (v) refreshPanel('cwpp');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('Container security config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

function openSupplyChainConfig(){
  proFetch('/api/v1/supply-chain/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'Supply chain — admission policy',
      sub: 'Controls how the cosign / SLSA provenance verifier treats artifacts at admission time.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'verify_required', label: 'Require verification', type: 'checkbox',
          value: cfg.verify_required !== false,
          hint: 'When on, every image must have a valid signature before admission.' },
        { id: 'slsa_min_level', label: 'Minimum SLSA level', type: 'select',
          value: String(cfg.slsa_min_level || 2), required: true,
          options: [
            { value: '1', label: 'L1 — Build process documented' },
            { value: '2', label: 'L2 — Hosted build service' },
            { value: '3', label: 'L3 — Source + build hardened' },
            { value: '4', label: 'L4 — Two-party review + hermetic' }
          ] },
        { id: 'allow_unsigned', label: 'Allow unsigned legacy images', type: 'checkbox',
          value: !!cfg.allow_unsigned,
          hint: 'Bypasses verification for images that match the legacy allowlist.' },
        { id: 'block_admission_below_min', label: 'Block admission below minimum SLSA level', type: 'checkbox',
          value: cfg.block_admission_below_min !== false },
        { id: 'sigstore_root', label: 'Sigstore trust root', type: 'select',
          value: cfg.sigstore_root || 'public-good', required: true,
          options: [
            { value: 'public-good', label: 'Sigstore public-good (default)' },
            { value: 'private',     label: 'Private Rekor + Fulcio' }
          ] }
      ],
      validate: function(v){
        v.slsa_min_level = parseInt(v.slsa_min_level, 10);
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/supply-chain/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('Supply chain config saved','success');
    if (v) refreshPanel('supplychain');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('Supply chain config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

function openPRBotConfig(){
  proFetch('/api/v1/autofix/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'PR / repo bot — auto-PR policy',
      sub: 'Tunes how the bot opens fix PRs. Affects every registered repo for this tenant.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'auto_pr_enabled', label: 'Open PRs automatically', type: 'checkbox',
          value: cfg.auto_pr_enabled !== false,
          hint: 'When off, the bot only suggests fixes inline — no PR is created.' },
        { id: 'sla_hours', label: 'SLA (hours)', type: 'number', required: true,
          value: cfg.sla_hours || 72,
          hint: '1–720. PRs untouched past this are flagged in the SLA breach view.' },
        { id: 'draft_pr_only', label: 'Open as draft PR', type: 'checkbox',
          value: !!cfg.draft_pr_only },
        { id: 'require_review', label: 'Require human review before merge', type: 'checkbox',
          value: cfg.require_review !== false },
        { id: 'max_open_prs', label: 'Max open PRs per repo', type: 'number', required: true,
          value: cfg.max_open_prs || 20,
          hint: '1–500. The bot pauses opening more PRs once this limit is hit.' }
      ],
      validate: function(v){
        if (v.sla_hours < 1 || v.sla_hours > 720) return 'SLA must be 1–720 hours';
        if (v.max_open_prs < 1 || v.max_open_prs > 500) return 'Max open PRs 1–500';
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/autofix/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('PR-bot config saved','success');
    if (v) refreshPanel('prbot');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('PR-bot config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

function openSBOMConfig(){
  proFetch('/api/v1/sbom/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'SBOM — diff & generation policy',
      sub: 'Controls per-tenant SBOM format and when diff alerts page on-call.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'sbom_format', label: 'Output format', type: 'select',
          value: cfg.sbom_format || 'cyclonedx', required: true,
          options: [
            { value: 'cyclonedx', label: 'CycloneDX (recommended)' },
            { value: 'spdx',      label: 'SPDX 2.3' },
            { value: 'syft',      label: 'Syft JSON' }
          ] },
        { id: 'diff_alert_severity', label: 'Diff alert minimum severity', type: 'select',
          value: cfg.diff_alert_severity || 'high', required: true,
          options: [
            { value: 'critical', label: 'CRITICAL only' },
            { value: 'high',     label: 'HIGH and above' },
            { value: 'medium',   label: 'MEDIUM and above' },
            { value: 'low',      label: 'LOW and above (noisy)' }
          ] },
        { id: 'alert_on_new_critical', label: 'Page on first new CRITICAL', type: 'checkbox',
          value: cfg.alert_on_new_critical !== false,
          hint: 'Sends an alert via the configured Observability channel.' },
        { id: 'auto_generate', label: 'Generate SBOM on every scan run', type: 'checkbox',
          value: cfg.auto_generate !== false }
      ],
      commit: function(v){
        return proFetch('/api/v1/sbom/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('SBOM config saved','success');
    if (v) refreshPanel('sbomdiff');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('SBOM config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

function openSSOConfig(){
  proFetch('/api/v1/sso/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'SSO / SAML — tenant policy',
      sub: 'Affects every SSO login for this tenant. Provider list is managed separately above.',
      submitLabel: 'Save', wide: true,
      fields: [
        { id: 'default_role', label: 'Default role for JIT-provisioned users', type: 'select',
          value: cfg.default_role || 'analyst', required: true,
          options: [
            { value: 'admin',    label: 'admin (full access)' },
            { value: 'analyst',  label: 'analyst (view + triage)' },
            { value: 'dev',      label: 'dev (CI / API tokens)' },
            { value: 'auditor',  label: 'auditor (read-only)' }
          ] },
        { id: 'jit_provisioning', label: 'Just-in-time user provisioning', type: 'checkbox',
          value: cfg.jit_provisioning !== false,
          hint: 'Create a local user on first SSO login. Off = users must exist already.' },
        { id: 'scim_enabled', label: 'SCIM 2.0 inbound provisioning', type: 'checkbox',
          value: !!cfg.scim_enabled,
          hint: 'When on, /api/v1/scim/v2/* accepts user/group sync from the IdP.' },
        { id: 'require_mfa', label: 'Require MFA after SSO login', type: 'checkbox',
          value: cfg.require_mfa !== false },
        { id: 'session_max_hours', label: 'Session max age (hours)', type: 'number', required: true,
          value: cfg.session_max_hours || 8,
          hint: '1–168. Forces re-auth after this duration.' }
      ],
      validate: function(v){
        if (v.session_max_hours < 1 || v.session_max_hours > 168) return 'Session max 1–168 h';
        return null;
      },
      commit: function(v){
        return proFetch('/api/v1/sso/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('SSO config saved','success');
    if (v) refreshPanel('sso');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('SSO config', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

/* ════════════════════════════════════════════════════════════════════════
   JSON detail viewer modal — replaces "View XXX → toast" placeholders
   so clicking "View provenance" / "Auto-fix steps" actually shows real data.
   ════════════════════════════════════════════════════════════════════════ */
function openJSONModal(opts){
  // opts: { title, sub, data (object), submitLabel (default 'Copy'), cancelLabel }
  var data = opts.data == null ? {} : opts.data;
  var pretty;
  try { pretty = JSON.stringify(data, null, 2); }
  catch (_e) { pretty = String(data); }
  var body = document.createElement('div');
  body.innerHTML =
    '<pre style="background:#0f172a;border:1px solid rgba(255,255,255,.06);' +
    'border-radius:6px;padding:14px;font-size:11px;color:#cbd5e1;overflow:auto;' +
    'max-height:55vh;margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;' +
    'white-space:pre">' + esc(pretty) + '</pre>';
  return openModal({
    title: opts.title || 'Details',
    sub: opts.sub || '',
    body: body, wide: true,
    submitLabel: opts.submitLabel || 'Copy JSON',
    cancelLabel: opts.cancelLabel || 'Close',
    onSubmit: function(){
      try {
        navigator.clipboard.writeText(pretty);
        if (typeof window.toast === 'function') window.toast('JSON copied to clipboard','success');
      } catch (_e) {
        if (typeof window.toast === 'function') window.toast('Clipboard blocked — select text manually','warn');
      }
      return false; // keep modal open
    }
  });
}

/* ── Override Supply chain "View provenance →" ──────────────────────────────
   The build IDs surfaced in this panel come from two sources:
     · Real signatures from cosign-api  → IDs like "ver-905b75717f61" or UUIDs
     · Mock data from vsp_pro_100.js   → IDs like "B-2891", "B-2890"
   We pattern-match: real-looking IDs hit /api/sc/{attestations,signatures}
   (cosign-api proxy) or /api/v1/supply-chain/signatures (gateway-direct).
   Mock IDs skip the network entirely — fetching them just produces 404/500
   noise in the console without giving the user any useful data — and we
   instead show a richer "demo build" modal explaining how to wire CI. */
function isMockBuildID(id){
  return /^B-\d+$/.test(String(id || ''));
}

function showDemoProvenanceModal(id){
  // Build a richer modal than the JSON fallback so it actually teaches
  // the user how to populate the panel with real data.
  var demoPredicate = {
    buildDefinition: {
      buildType: 'https://slsa-framework.github.io/build-types/github-actions/v1',
      externalParameters: {
        workflow: { ref: 'refs/heads/main', repository: 'org/repo', path: '.github/workflows/release.yml' }
      }
    },
    runDetails: {
      builder: { id: 'https://github.com/actions/runner' },
      metadata: { invocationID: 'demo-' + id }
    }
  };
  var demo = {
    _note: 'Demo build — mock ID pattern (B-NNNN) is not a real cosign signature.',
    _next: [
      'Configure your CI to call cosign sign + cosign attest after the build',
      'Point the gateway\'s cosign-api at your Rekor instance (default: public-good)',
      'Real builds will populate this panel within seconds of CI completing'
    ],
    build_id: id,
    predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: id, digest: { sha256: '<populated-from-cosign-attest>' } }],
    predicate: demoPredicate
  };

  var body = document.createElement('div');
  body.innerHTML =
    '<div style="padding:10px 14px;background:rgba(34,211,238,.08);' +
    'border-left:3px solid #22d3ee;color:#cbd5e1;font-size:11px;border-radius:4px;margin-bottom:14px">' +
    '<strong style="color:#22d3ee">Demo build</strong> — this is a placeholder ID from the seeded panel. ' +
    'Real provenance loads automatically once your CI emits a cosign attestation. Sample structure below.' +
    '</div>' +
    '<pre style="background:#0f172a;border:1px solid rgba(255,255,255,.06);' +
    'border-radius:6px;padding:14px;font-size:11px;color:#cbd5e1;overflow:auto;max-height:50vh;' +
    'margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;white-space:pre">' +
    esc(JSON.stringify(demo, null, 2)) + '</pre>';

  openModal({
    title: 'Provenance — ' + id,
    sub: 'in-toto v1.0 / SLSA Level 3 sample',
    body: body, wide: true,
    submitLabel: 'Copy sample JSON',
    cancelLabel: 'Close',
    onSubmit: function(){
      try {
        navigator.clipboard.writeText(JSON.stringify(demo, null, 2));
        if (typeof window.toast === 'function') window.toast('Sample provenance copied','success');
      } catch (_e){}
      return false;
    }
  });
}

PRO.showProvenance = function(id){
  if (!id) return;
  // Mock IDs → skip network entirely (avoids 500/404 noise) and show the demo
  // modal directly. This is the common case in the seeded VSP demo environment.
  if (isMockBuildID(id)){
    showDemoProvenanceModal(id);
    return;
  }
  // Real IDs — try cosign-api proxy first, then gateway-direct as fallback.
  var attempts = [
    '/api/sc/attestations/' + encodeURIComponent(id),
    '/api/sc/signatures/'   + encodeURIComponent(id),
    '/api/v1/supply-chain/signatures/' + encodeURIComponent(id)
  ];
  function tryNext(i){
    if (i >= attempts.length){
      // No real source had it — fall back to the demo modal so the user
      // still gets something, with a clear explanation.
      showDemoProvenanceModal(id);
      return;
    }
    return proFetch(attempts[i]).then(function(data){
      openJSONModal({
        title: 'Provenance — ' + id,
        sub: 'Source: ' + attempts[i] + '  ·  in-toto / SLSA attestation',
        data: data
      });
    }).catch(function(err){
      if (err && err.is402){
        var body = document.getElementById('pro-body');
        if (body) body.innerHTML = upgradeOverlayHTML('Supply chain provenance', err.required, err.current);
        return;
      }
      tryNext(i + 1);
    });
  }
  tryNext(0);
};

/* ── Override CSPM mock "Auto-fix → / Steps" buttons ────────────────────────
   The mock CSPM panel (only shown if my real CSPM render falls back to mock)
   has buttons that call PRO.cspmFix(i). Default is a toast — replace with a
   modal that explains what would happen. */
var prevCspmFix = PRO.cspmFix;
PRO.cspmFix = function(i){
  openModal({
    title: 'Auto-fix would apply',
    sub: 'In production this calls the connector\'s remediation API. Currently the panel is showing mock findings — once you connect a real cloud account, this button posts to the auto-fix runner.',
    body: '<div style="color:#cbd5e1;font-size:12px;line-height:1.55">' +
          '<strong>Steps:</strong>' +
          '<ol style="margin-top:8px;padding-left:18px;color:#94a3b8">' +
          '<li>Read the finding\'s remediation plan from CSPM rule pack</li>' +
          '<li>Generate the CloudFormation / Terraform / Pulumi patch</li>' +
          '<li>Open a fix PR via the PR-bot, OR apply directly if auto-fix is enabled</li>' +
          '<li>Re-scan the resource and resolve the finding when posture passes</li>' +
          '</ol></div>',
    submitLabel: 'Got it', cancelLabel: ''
  });
};

/* ── Override mock Tenants "Switch →" button ────────────────────────────────
   When mock tenants render is shown, give a real "switch tenant" experience
   instead of a toast. The actual switching is admin-only and goes via a
   different flow; this just confirms the intent. */
var prevSwitchTenant = PRO.switchTenant;
PRO.switchTenant = function(id){
  confirmModal({
    title: 'Switch tenant context',
    message: 'Re-authenticate as tenant "' + id + '"? Your current session will be invalidated and you will be sent to the SSO login flow for that tenant.',
    dangerLabel: 'Switch'
  }).then(function(yes){
    if (!yes) return;
    if (typeof window.toast === 'function') window.toast('Tenant switch is admin-only — contact ops to provision your account','info');
  });
};

/* ── Override mock SSO "Connect / Test" buttons ─────────────────────────────
   Default toasts → open the proper add-provider / test-login flow. */
PRO.idpConnect = function(){ PRO.ssoAddProvider(); };
PRO.idpTest    = function(i){
  openModal({
    title: 'Test SAML round-trip',
    sub: 'In production this initiates a SAML AuthnRequest to the configured IdP and validates the SAMLResponse signature + attribute mapping.',
    body: '<div style="color:#cbd5e1;font-size:12px;line-height:1.55">Configure a real provider via the <strong>+ Add IdP</strong> button to enable test-login.</div>',
    submitLabel: 'OK', cancelLabel: ''
  });
};

/* ════════════════════════════════════════════════════════════════════════
   CWPP — replace alert()/prompt() in vsp_pro_cwpp_realapi.js with modals
   ════════════════════════════════════════════════════════════════════════ */
PRO.cwppSeed = function(){
  proFetch('/api/v1/container/seed', { method: 'POST' }).then(function(data){
    var images = (data && data.images) || [];
    openModal({
      title: 'Demo images seeded',
      sub: 'Trivy will scan each image asynchronously — refresh in ~30s to see CVE counts populate.',
      body: '<div style="color:#cbd5e1;font-size:12px;line-height:1.6">' +
            '<strong>Queued ' + images.length + ' image(s):</strong>' +
            '<ul style="margin-top:8px;padding-left:18px;color:#94a3b8">' +
            images.map(function(i){ return '<li class="pro-mono">' + esc(i) + '</li>'; }).join('') +
            '</ul></div>',
      submitLabel: 'Refresh now',
      cancelLabel: 'Wait 30s',
      onSubmit: function(){ refreshPanel('cwpp'); return true; }
    });
    setTimeout(refreshPanel.bind(null, 'cwpp'), 30000);
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('Container security', err.required, err.current);
      return;
    }
    openModal({ title: 'Seed failed', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
};

PRO.cwppScanNew = function(){
  formModal({
    title: 'Scan a new container image',
    sub: 'Trivy fetches the manifest, downloads layers, and runs the CVE database against installed packages.',
    submitLabel: 'Start scan',
    fields: [
      { id: 'ref', label: 'Image reference', type: 'text', required: true,
        placeholder: 'e.g. nginx:1.25-alpine or registry.acme.com/api:v1.4.2',
        hint: 'Must be pullable from the gateway host. Private registries need credentials configured at the platform level.' }
    ],
    commit: function(v){
      return proFetch('/api/v1/container/scan', { method: 'POST', body: JSON.stringify({ ref: v.ref.trim() }) });
    }
  }).then(function(v){
    if (!v) return;
    if (typeof window.toast === 'function') window.toast('Scan queued — refresh in 30–60s','success');
    setTimeout(refreshPanel.bind(null, 'cwpp'), 30000);
  }).catch(function(e){ console.error(e); });
};

PRO.cwppShowCVEs = function(imageID){
  if (!imageID) return;
  proFetch('/api/v1/container/scan/' + encodeURIComponent(imageID)).then(function(data){
    var vulns = (data && data.vulnerabilities) || [];
    var imageRef = (data && data.image && (data.image.ref || data.image.id)) || imageID;
    if (vulns.length === 0){
      openModal({
        title: 'CVEs for ' + imageRef,
        sub: 'Image scanned clean — no known vulnerabilities in the Trivy DB.',
        body: '<div style="padding:24px;text-align:center;color:#22c55e;font-size:13px">No CVEs found ✓</div>',
        submitLabel: 'OK', cancelLabel: ''
      });
      return;
    }
    var counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    vulns.forEach(function(v){
      var s = (v.severity || 'unknown').toLowerCase();
      counts[s] = (counts[s] || 0) + 1;
    });

    // Build clickable KPI cards (filter by severity on click) + filterable
    // table tagged with data-vspm-export so wireTableExtras + attachPagination
    // give us search + paging + CSV download for free.
    var body = document.createElement('div');
    var safeImage = imageRef.replace(/[^a-zA-Z0-9._-]/g, '_');
    body.innerHTML =
      '<div class="pro-grid c4" style="margin-bottom:14px" data-cve-kpi>' +
        kpiCardClickable('CRITICAL', counts.critical || 0, 'click to filter', '#ef4444', 'critical') +
        kpiCardClickable('HIGH',     counts.high     || 0, 'click to filter', '#fbbf24', 'high') +
        kpiCardClickable('MEDIUM',   counts.medium   || 0, 'click to filter', '#22d3ee', 'medium') +
        kpiCardClickable('LOW',      counts.low      || 0, 'click to filter', '#94a3b8', 'low') +
      '</div>' +
      '<div class="pro-section-h">Vulnerabilities (' + vulns.length + ')</div>' +
      '<table class="pro-table" data-vspm-export="cves-' + safeImage + '.csv"><thead><tr>' +
        '<th>CVE</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th>' +
      '</tr></thead><tbody>' +
      vulns.map(function(v){
        var sev = (v.severity || 'unknown').toLowerCase();
        var sevC = sev === 'critical' ? 'err' : sev === 'high' ? 'warn' : sev === 'medium' ? 'info' : 'muted';
        return '<tr data-vspm-sev="' + esc(sev) + '"><td class="pro-mono">' + esc(v.cve || v.id || '?') + '</td>' +
               '<td><span class="pro-pill ' + sevC + '">' + esc(sev.toUpperCase()) + '</span></td>' +
               '<td>' + esc(v.package || v.library || v.pkg || '') + '</td>' +
               '<td class="pro-mono" style="font-size:10px">' + esc(v.installed || v.installed_version || '') + '</td>' +
               '<td class="pro-mono" style="font-size:10px">' + esc(v.fixed || v.fixed_version || '—') + '</td></tr>';
      }).join('') +
      '</tbody></table>';

    openModal({
      title: 'CVEs for ' + imageRef,
      sub: vulns.length + ' vulnerabilities found by Trivy  ·  click a KPI to filter, type to search',
      body: body, wide: true,
      submitLabel: 'Copy visible', cancelLabel: 'Close',
      onSubmit: function(content){
        // Copy only currently-visible (post filter+page) rows
        var rows = content.querySelectorAll('table.pro-table tbody tr');
        var lines = [];
        rows.forEach(function(tr){
          if (tr.style.display === 'none') return;
          var cells = tr.querySelectorAll('td');
          var arr = [];
          cells.forEach(function(c){ arr.push((c.textContent || '').trim()); });
          lines.push(arr.join('\t'));
        });
        try {
          navigator.clipboard.writeText(lines.join('\n'));
          if (typeof window.toast === 'function') window.toast('Copied ' + lines.length + ' visible CVEs','success');
        } catch (_e){}
        return false;
      }
    });

    // Wire extras AFTER modal is in DOM. wireTableExtras adds search +
    // export, attachPagination adds 25/50/100/All footer.
    setTimeout(function(){
      wireTableExtras(body);
      var t = body.querySelector('table.pro-table[data-vspm-export]');
      if (t) attachPagination(t);

      // KPI click handlers — filter by severity through the search box
      // (so pagination + count update via the existing logic).
      var searchInput = body.querySelector('.vspm-search input');
      var currentSev = '';
      body.querySelectorAll('[data-cve-kpi-sev]').forEach(function(card){
        card.addEventListener('click', function(){
          var sev = card.getAttribute('data-cve-kpi-sev');
          // Toggle: clicking same KPI again clears the filter
          if (currentSev === sev){
            currentSev = '';
            // Clear severity filter — show all
            body.querySelectorAll('table.pro-table tbody tr').forEach(function(tr){
              tr.dataset.vspmFilteredOut = '';
            });
          } else {
            currentSev = sev;
            body.querySelectorAll('table.pro-table tbody tr').forEach(function(tr){
              var match = tr.getAttribute('data-vspm-sev') === sev;
              // Combine with text-search filter
              if (searchInput && searchInput.value.trim()){
                var q = searchInput.value.toLowerCase().trim();
                match = match && (tr.textContent || '').toLowerCase().indexOf(q) !== -1;
              }
              tr.dataset.vspmFilteredOut = match ? '' : '1';
            });
          }
          // Visually mark active KPI
          body.querySelectorAll('[data-cve-kpi-sev]').forEach(function(c){
            c.style.outline = c === card && currentSev ? '2px solid #22d3ee' : '';
          });
          // Re-trigger pagination
          if (t && t.__vspmPager){
            // Force a render — synthesize an input event so paginator recomputes
            if (searchInput) searchInput.dispatchEvent(new Event('input'));
          }
        });
      });
    }, 50);
  }).catch(function(err){
    openModal({ title: 'CVE fetch failed', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
};

// Variant of kpiCard that's clickable (used by the CVE detail modal).
function kpiCardClickable(label, val, sub, color, sevKey){
  return '<div class="pro-card" data-cve-kpi-sev="' + esc(sevKey) + '" ' +
         'style="cursor:pointer;transition:outline .12s" title="Click to filter">' +
         '<div class="lbl">' + esc(label) + '</div>' +
         '<div class="val" style="color:' + color + '">' + esc(String(val)) + '</div>' +
         '<div class="sub">' + esc(sub) + '</div></div>';
}

/* ════════════════════════════════════════════════════════════════════════
   PR-bot — add row-click "View PR details" modal
   ════════════════════════════════════════════════════════════════════════ */
PRO.prbotShowPR = function(prID){
  if (!prID) return;
  proFetch('/api/v1/autofix/pr/' + encodeURIComponent(prID) + '/status').then(function(data){
    var pr = data || {};
    openJSONModal({
      title: 'PR #' + prID + ' — full payload',
      sub: 'Source: GET /api/v1/autofix/pr/' + prID + '/status  ·  in-memory + DB join',
      data: pr
    });
  }).catch(function(err){
    openModal({ title: 'PR fetch failed', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
};

// Re-render the PR table with clickable rows. Wraps the existing render.
var origPRBotRenderForRow = (PRO.modules.prbot && PRO.modules.prbot.render) || null;
if (origPRBotRenderForRow){
  var origRenderRef = origPRBotRenderForRow;
  PRO.modules.prbot.render = function(root){
    var ret = origRenderRef.call(this, root);
    Promise.resolve(ret).then(function(){
      // After our render finishes, decorate each PR row with a "Details" button.
      setTimeout(function(){
        var tables = root.querySelectorAll('table.pro-table');
        if (tables.length < 1) return;
        // The PR table is the second one (first is repos when present).
        var prTable = tables[tables.length - 1];
        var head = prTable.querySelector('thead tr');
        if (head && !head.querySelector('th[data-vspm-act]')){
          var th = document.createElement('th');
          th.setAttribute('data-vspm-act', '1');
          th.textContent = 'Action';
          head.appendChild(th);
        }
        prTable.querySelectorAll('tbody tr').forEach(function(tr){
          if (tr.querySelector('td[data-vspm-act]')) return;
          // First cell content is "#42" → strip the # prefix to get the ID.
          var idCell = tr.querySelector('td.pro-mono');
          if (!idCell) return;
          var id = (idCell.textContent || '').replace(/^#/, '').trim();
          var td = document.createElement('td');
          td.setAttribute('data-vspm-act', '1');
          td.innerHTML = '<button class="pro-btn ghost" onclick="VSP_PRO.prbotShowPR(\'' + esc(id) + '\')">Details</button>';
          tr.appendChild(td);
        });
      }, 50);
    });
    return ret;
  };
}

/* ════════════════════════════════════════════════════════════════════════
   Tenants — add row-click "View tenant" detail modal
   ════════════════════════════════════════════════════════════════════════ */
PRO.tenantsShowDetail = function(slug, name, plan, createdAt){
  openModal({
    title: 'Tenant — ' + (name || slug),
    sub: 'Identity, plan, and creation timestamp from /api/v1/tenants',
    body:
      '<div style="display:grid;grid-template-columns:auto 1fr;gap:10px 18px;font-size:12px">' +
        '<div style="color:#94a3b8">Slug</div>' +
        '<div class="pro-mono">' + esc(slug) + '</div>' +
        '<div style="color:#94a3b8">Display name</div>' +
        '<div>' + esc(name) + '</div>' +
        '<div style="color:#94a3b8">Plan</div>' +
        '<div><span class="pro-pill ' + (plan === 'pro' || plan === 'enterprise' ? 'ok' : 'muted') + '">' + esc(plan) + '</span></div>' +
        '<div style="color:#94a3b8">Created</div>' +
        '<div class="pro-mono" style="font-size:11px">' + esc(createdAt || '—') + '</div>' +
      '</div>' +
      '<div style="margin-top:18px;padding:10px 12px;background:#0f172a;border-left:3px solid #22d3ee;color:#94a3b8;font-size:11px;border-radius:4px">' +
        'Plan changes are admin-only and go through the billing webhook (POST /api/v1/billing/webhook) or the admin tenant API.' +
      '</div>',
    submitLabel: 'OK', cancelLabel: ''
  });
};

// Wrap tenants render to make rows clickable.
var origTenantsRenderForRow = (PRO.modules.tenants && PRO.modules.tenants.render) || null;
if (origTenantsRenderForRow){
  var origTenantsRef = origTenantsRenderForRow;
  PRO.modules.tenants.render = function(root){
    var ret = origTenantsRef.call(this, root);
    Promise.resolve(ret).then(function(){
      setTimeout(function(){
        // The "All tenants" table is the only table in this panel.
        var table = root.querySelector('table.pro-table');
        if (!table) return;
        var head = table.querySelector('thead tr');
        if (head && !head.querySelector('th[data-vspm-act]')){
          var th = document.createElement('th');
          th.setAttribute('data-vspm-act', '1');
          th.textContent = 'Action';
          head.appendChild(th);
        }
        table.querySelectorAll('tbody tr').forEach(function(tr){
          if (tr.querySelector('td[data-vspm-act]')) return;
          var cells = tr.querySelectorAll('td');
          if (cells.length < 4) return;
          // Prefer data-* attributes set by the new tenants renderer
          // (renderTenantsReal above). Falls back to cell text for the
          // legacy mock-data path. This avoids the
          // "STARTERPROENTERPRISEFREE" bug where cells[2] of an admin
          // user contains a <select name="select-option-2" aria-label="Select option"> whose .textContent is the
          // concatenation of every option label.
          var slug = tr.getAttribute('data-tenant-slug') ||
                     (cells[0].textContent || '').trim();
          var name = tr.getAttribute('data-tenant-name') ||
                     (cells[1].textContent || '').trim();
          var plan = tr.getAttribute('data-tenant-plan') ||
                     (cells[2].textContent || '').trim();
          var when = tr.getAttribute('data-tenant-created') ||
                     (cells[3].textContent || '').trim();
          // Friendly date label for the modal; raw ISO stays usable too.
          var whenLabel = when ?
                          (new Date(when).toString() !== 'Invalid Date'
                             ? new Date(when).toLocaleString()
                             : when)
                          : '—';
          var td = document.createElement('td');
          td.setAttribute('data-vspm-act', '1');
          td.innerHTML = '<button class="pro-btn ghost" onclick="VSP_PRO.tenantsShowDetail(\'' +
                         esc(slug) + '\',\'' + esc(name) + '\',\'' + esc(plan) + '\',\'' + esc(whenLabel) + '\')">Details</button>';
          tr.appendChild(td);
        });
      }, 50);
    });
    return ret;
  };
}

/* ════════════════════════════════════════════════════════════════════════
   PRO-grade extras — Export CSV + table-row search filter
   ════════════════════════════════════════════════════════════════════════ */

// Generic CSV exporter. headers: ['Col1','Col2'], rows: [['a','b'], …]
function exportCSV(filename, headers, rows){
  function csvEscape(s){
    if (s == null) return '';
    s = String(s);
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  var lines = [headers.map(csvEscape).join(',')];
  rows.forEach(function(r){ lines.push(r.map(csvEscape).join(',')); });
  var blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 0);
  if (typeof window.toast === 'function') window.toast('Exported ' + rows.length + ' rows → ' + filename, 'success');
}
PRO.exportCSV = exportCSV;

// Wires a search input to filter visible <tr> in a table by substring match.
// Called after a render. Requires a `.vspm-search` container preceding the
// `table.pro-table` element.
function attachTableSearch(searchInput, table, countLabel){
  function apply(){
    var q = searchInput.value.toLowerCase().trim();
    var rows = table.querySelectorAll('tbody tr');
    var visible = 0;
    rows.forEach(function(tr){
      var text = (tr.textContent || '').toLowerCase();
      var show = !q || text.indexOf(q) !== -1;
      tr.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    if (countLabel) countLabel.textContent = q ? (visible + ' / ' + rows.length + ' rows') : (rows.length + ' rows');
  }
  searchInput.addEventListener('input', apply);
  apply();
}

// Decorate any vspm-tagged table with a Search box + Export button.
// Caller marks the table with [data-vspm-export="filename.csv"] and adds
// a <div class="vspm-search"> + <input> right before it.
function wireTableExtras(root){
  if (!root) return;
  root.querySelectorAll('table.pro-table[data-vspm-export]').forEach(function(table){
    var fname = table.getAttribute('data-vspm-export') || 'export.csv';
    // Build a sibling toolbar before the table if we haven't yet.
    if (!table.previousElementSibling || !table.previousElementSibling.classList.contains('vspm-search')){
      var bar = document.createElement('div');
      bar.className = 'vspm-search';
      bar.innerHTML =
        '<input name="filter-rows" aria-label="Filter rows…" type="search" placeholder="Filter rows…" />' +
        '<span class="count"></span>' +
        '<button class="pro-btn ghost" style="font-size:10px">⤓ Export CSV</button>';
      table.parentNode.insertBefore(bar, table);
      var input = bar.querySelector('input');
      var count = bar.querySelector('.count');
      attachTableSearch(input, table, count);
      bar.querySelector('button').addEventListener('click', function(){
        var headers = Array.prototype.map.call(table.querySelectorAll('thead th'),
          function(th){ return (th.textContent || '').trim(); });
        var rows = [];
        table.querySelectorAll('tbody tr').forEach(function(tr){
          if (tr.style.display === 'none') return;
          rows.push(Array.prototype.map.call(tr.querySelectorAll('td'),
            function(td){ return (td.textContent || '').trim(); }));
        });
        exportCSV(fname, headers, rows);
      });
    }
  });
}
PRO.wireTableExtras = wireTableExtras;

/* ── Re-wrap CSPM / Secrets / Audit / PR-bot to add data-vspm-export ──────
   We tag each panel's primary tables and call wireTableExtras after render. */
function decoratePanel(featureID, exportName){
  var m = PRO.modules[featureID];
  if (!m || !m.render) return;
  var orig = m.render;
  m.render = function(root){
    var ret = orig.call(this, root);
    Promise.resolve(ret).then(function(){
      setTimeout(function(){
        // Tag every table in this panel for export
        root.querySelectorAll('table.pro-table').forEach(function(t, i){
          if (!t.hasAttribute('data-vspm-export')){
            t.setAttribute('data-vspm-export',
              exportName + (i > 0 ? '-' + (i+1) : '') + '.csv');
          }
        });
        wireTableExtras(root);
      }, 80);
    });
    return ret;
  };
}
decoratePanel('cspm',          'cspm-findings');
decoratePanel('secrets_vault', 'vault-secrets');
decoratePanel('prbot',         'autopr');
decoratePanel('tenants',       'tenants');
decoratePanel('sso',           'sso-providers');

// Audit sub-panel (opened via secretAudit/secretAuditAll) also gets it.
var origOpenSecretAuditPanel = openSecretAuditPanel;
openSecretAuditPanel = function(name){
  origOpenSecretAuditPanel(name);
  // Wait for the audit panel to render, then decorate.
  setTimeout(function(){
    var body = document.getElementById('pro-body');
    if (!body) return;
    body.querySelectorAll('table.pro-table').forEach(function(t){
      if (!t.hasAttribute('data-vspm-export')){
        t.setAttribute('data-vspm-export', 'secret-audit' + (name ? '-' + name : '') + '.csv');
      }
    });
    wireTableExtras(body);
  }, 250);
};

/* ════════════════════════════════════════════════════════════════════════
   PAGINATION — client-side, applied to every data-vspm-export table.
   The toolbar that wireTableExtras() injected gets a footer underneath the
   table with prev/next + per-page selector. Plays nicely with the search
   filter: pagination only counts visible rows.
   ════════════════════════════════════════════════════════════════════════ */
function attachPagination(table){
  if (table.__vspmPager) return;
  table.__vspmPager = true;

  var perPage = 25;
  var page    = 1;

  // Build the pager UI once, place it after the table.
  var pager = document.createElement('div');
  pager.className = 'vspm-pager';
  pager.innerHTML =
    '<span class="info"></span>' +
    '<label>Per page <select name="select-option-3" aria-label="Select option">' +
      '<option value="25">25</option>' +
      '<option value="50">50</option>' +
      '<option value="100">100</option>' +
      '<option value="0">All</option>' +
    '</select></label>' +
    '<button class="pro-btn ghost prev" style="font-size:10px">‹ Prev</button>' +
    '<button class="pro-btn ghost next" style="font-size:10px">Next ›</button>';
  table.parentNode.insertBefore(pager, table.nextSibling);

  var info  = pager.querySelector('.info');
  var sel   = pager.querySelector('select');
  var prev  = pager.querySelector('.prev');
  var next  = pager.querySelector('.next');

  function applyPagination(){
    var visibleRows = Array.prototype.filter.call(
      table.querySelectorAll('tbody tr'),
      function(tr){ return tr.dataset.vspmFilteredOut !== '1'; });
    var total = visibleRows.length;
    var pages = perPage === 0 ? 1 : Math.max(1, Math.ceil(total / perPage));
    if (page > pages) page = pages;
    var start = perPage === 0 ? 0 : (page - 1) * perPage;
    var end   = perPage === 0 ? total : start + perPage;
    visibleRows.forEach(function(tr, i){
      tr.style.display = (i >= start && i < end) ? '' : 'none';
    });
    if (total === 0){
      info.textContent = '0 rows';
    } else if (perPage === 0){
      info.textContent = total + ' rows (all)';
    } else {
      info.textContent = (start + 1) + '–' + Math.min(end, total) + ' of ' + total;
    }
    prev.disabled = page <= 1;
    next.disabled = page >= pages;
  }

  // The search input and its filter live in the .vspm-search bar from
  // wireTableExtras. Hook into it so search → re-paginate.
  var searchBar = table.previousElementSibling;
  if (searchBar && searchBar.classList.contains('vspm-search')){
    var input = searchBar.querySelector('input');
    if (input){
      // Replace existing filter behaviour to mark filtered-out rows instead
      // of toggling display directly; pagination then takes over the display.
      input.addEventListener('input', function(){
        var q = input.value.toLowerCase().trim();
        var rows = table.querySelectorAll('tbody tr');
        var visible = 0;
        rows.forEach(function(tr){
          var text = (tr.textContent || '').toLowerCase();
          var match = !q || text.indexOf(q) !== -1;
          tr.dataset.vspmFilteredOut = match ? '' : '1';
          if (match) visible++;
        });
        var count = searchBar.querySelector('.count');
        if (count) count.textContent = q ? (visible + ' / ' + rows.length + ' rows') : (rows.length + ' rows');
        page = 1;
        applyPagination();
      });
    }
  }

  prev.addEventListener('click', function(){ if (page > 1){ page--; applyPagination(); } });
  next.addEventListener('click', function(){ page++; applyPagination(); });
  sel.addEventListener('change', function(){
    perPage = parseInt(sel.value, 10) || 0;
    page = 1;
    applyPagination();
  });

  applyPagination();
}

/* ════════════════════════════════════════════════════════════════════════
   BULK ACTIONS — checkbox column + bulk-action bar.
   Only applied to tables tagged with [data-vspm-bulk="<panel-id>"].
   ════════════════════════════════════════════════════════════════════════ */
function attachBulkActions(table, panelID){
  if (table.__vspmBulk) return;
  table.__vspmBulk = true;

  // Insert a leading checkbox cell into header + each row (idempotent).
  var head = table.querySelector('thead tr');
  if (head && !head.querySelector('th[data-vspm-bulk-th]')){
    var th = document.createElement('th');
    th.setAttribute('data-vspm-bulk-th', '1');
    th.style.width = '24px';
    th.innerHTML = '<input name="toggle-option-2" aria-label="Toggle option" type="checkbox" class="vspm-bulk-checkbox" data-vspm-bulk-all />';
    head.insertBefore(th, head.firstChild);
  }
  table.querySelectorAll('tbody tr').forEach(function(tr){
    if (tr.querySelector('td[data-vspm-bulk-td]')) return;
    var td = document.createElement('td');
    td.setAttribute('data-vspm-bulk-td', '1');
    // Use the row's first cell text as the "row key" — works for both
    // CSPM (UUID in column 1) and Secrets (name in column 1).
    var firstCell = tr.querySelector('td');
    var rowKey = firstCell ? (firstCell.textContent || '').trim() : '';
    td.innerHTML = '<input name="vspm-row-key" aria-label="Vspm row key" type="checkbox" class="vspm-bulk-checkbox" data-vspm-row-key="' + esc(rowKey) + '" />';
    tr.insertBefore(td, tr.firstChild);
  });

  // Bulk action bar — appears above the table when ≥1 row selected.
  var bar = table.parentNode.querySelector('.vspm-bulk[data-vspm-bulk-bar]');
  if (!bar){
    bar = document.createElement('div');
    bar.className = 'vspm-bulk';
    bar.setAttribute('data-vspm-bulk-bar', '1');
    bar.style.display = 'none';
    bar.innerHTML =
      '<strong class="count">0 selected</strong>' +
      '<div class="spacer"></div>' +
      '<button class="pro-btn ghost" data-bulk-clear>Clear</button>' +
      '<button class="pro-btn" data-bulk-action style="background:#7f1d1d;border-color:#ef4444">Delete selected</button>';
    table.parentNode.insertBefore(bar, table);
  }

  function refreshBar(){
    var checks = table.querySelectorAll('tbody input[data-vspm-row-key]:checked');
    var n = checks.length;
    bar.style.display = n > 0 ? 'flex' : 'none';
    bar.querySelector('.count').textContent = n + ' selected';
  }

  // Master select-all
  var allBox = head && head.querySelector('input[data-vspm-bulk-all]');
  if (allBox){
    allBox.addEventListener('change', function(){
      table.querySelectorAll('tbody input[data-vspm-row-key]').forEach(function(c){
        // Only toggle visible (post-filter) rows
        var tr = c.closest('tr');
        if (tr && tr.dataset.vspmFilteredOut === '1') return;
        c.checked = allBox.checked;
      });
      refreshBar();
    });
  }
  table.addEventListener('change', function(e){
    if (e.target && e.target.matches('input[data-vspm-row-key]')) refreshBar();
  });

  bar.querySelector('[data-bulk-clear]').addEventListener('click', function(){
    table.querySelectorAll('tbody input[data-vspm-row-key]:checked').forEach(function(c){ c.checked = false; });
    if (allBox) allBox.checked = false;
    refreshBar();
  });
  bar.querySelector('[data-bulk-action]').addEventListener('click', function(){
    var keys = Array.prototype.map.call(
      table.querySelectorAll('tbody input[data-vspm-row-key]:checked'),
      function(c){ return c.getAttribute('data-vspm-row-key'); });
    if (keys.length === 0) return;
    confirmModal({
      title: 'Bulk delete (' + keys.length + ' rows)',
      message: 'Delete the following ' + keys.length + ' item(s)? This cannot be undone.\n\n' + keys.slice(0, 8).join(', ') + (keys.length > 8 ? ' …' : ''),
      danger: true, dangerLabel: 'Delete ' + keys.length
    }).then(function(yes){
      if (!yes) return;
      var deletes = keys.map(function(k){
        var url;
        if (panelID === 'cspm')           url = '/api/v1/cspm/findings/' + encodeURIComponent(k) + '/status';
        else if (panelID === 'secrets')   url = '/api/v1/soar/secrets/'  + encodeURIComponent(k);
        else return Promise.resolve();
        // CSPM doesn't have a bulk delete; use status=resolved as a soft-delete.
        if (panelID === 'cspm'){
          return proFetch(url, { method: 'POST', body: JSON.stringify({ status: 'resolved' }) });
        }
        return proFetch(url, { method: 'DELETE' });
      });
      Promise.allSettled(deletes).then(function(results){
        var ok = results.filter(function(r){ return r.status === 'fulfilled'; }).length;
        if (typeof window.toast === 'function') window.toast('Bulk: ' + ok + '/' + keys.length + ' processed', ok === keys.length ? 'success' : 'warn');
        // Refresh the affected panel
        if (panelID === 'cspm') refreshPanel('cspm');
        else if (panelID === 'secrets') refreshPanel('secrets_vault');
      });
    });
  });

  refreshBar();
}

/* Hook bulk into the existing decoratePanel chain for CSPM + Secrets. */
function decorateBulk(featureID, panelKey){
  var m = PRO.modules[featureID];
  if (!m || !m.render) return;
  var orig = m.render;
  m.render = function(root){
    var ret = orig.call(this, root);
    Promise.resolve(ret).then(function(){
      setTimeout(function(){
        // The "primary" data table is always the LAST one rendered
        // (CSPM: findings; Secrets: list — both come after the KPI cards).
        var tables = root.querySelectorAll('table.pro-table[data-vspm-export]');
        if (tables.length > 0) attachBulkActions(tables[tables.length - 1], panelKey);
        // Also wire pagination to every export-tagged table.
        tables.forEach(attachPagination);
      }, 120);
    });
    return ret;
  };
}
decorateBulk('cspm',          'cspm');
decorateBulk('secrets_vault', 'secrets');

// PR-bot, Tenants, SSO get pagination only (no bulk).
['prbot', 'tenants', 'sso'].forEach(function(fid){
  var m = PRO.modules[fid];
  if (!m || !m.render) return;
  var orig = m.render;
  m.render = function(root){
    var ret = orig.call(this, root);
    Promise.resolve(ret).then(function(){
      setTimeout(function(){
        root.querySelectorAll('table.pro-table[data-vspm-export]').forEach(attachPagination);
      }, 140);
    });
    return ret;
  };
});

/* ════════════════════════════════════════════════════════════════════════
   NOTIFICATIONS — cross-panel config (Slack/Teams/Webhook/Email/PagerDuty)
   Accessible from any Configure modal via the new top-bar button, plus
   directly via VSP_PRO.openNotifications().
   ════════════════════════════════════════════════════════════════════════ */
PRO.openNotifications = function(){
  proFetch('/api/v1/notifications/config').then(function(cfg){
    cfg = cfg || {};
    return formModal({
      title: 'Notifications — channels & event routing',
      sub: 'Tenant-scoped. Once configured, every PRO panel can fan events into these channels.',
      submitLabel: 'Save', wide: true,
      fields: [
        // Channels
        { id: 'slack_webhook',   label: 'Slack incoming-webhook URL',   type: 'text',
          value: cfg.slack_webhook || '',   placeholder: 'https://hooks.slack.com/services/T…/B…/…' },
        { id: 'teams_webhook',   label: 'Microsoft Teams webhook URL',  type: 'text',
          value: cfg.teams_webhook || '',   placeholder: 'https://outlook.office.com/webhook/…' },
        { id: 'generic_webhook', label: 'Generic JSON webhook URL',     type: 'text',
          value: cfg.generic_webhook || '', placeholder: 'https://your-receiver.example.com/vsp' },
        { id: 'pagerduty_key',   label: 'PagerDuty integration key',    type: 'password',
          value: cfg.pagerduty_key || '',   hint: 'Service-level routing key (Events API v2).' },
        { id: 'email_recipients', label: 'Email recipients (comma-separated)', type: 'text',
          value: (cfg.email_recipients || []).join(', '),
          placeholder: 'oncall@acme.com, sec-leads@acme.com' },
        // Per-event toggles
        { id: 'alert_on_critical_finding',  label: 'Alert on new CRITICAL finding', type: 'checkbox',
          value: cfg.alert_on_critical_finding !== false },
        { id: 'alert_on_image_admission',   label: 'Alert on K8s admission denial (CWPP)', type: 'checkbox',
          value: cfg.alert_on_image_admission !== false },
        { id: 'alert_on_supply_chain_fail', label: 'Alert on supply-chain verification failure', type: 'checkbox',
          value: cfg.alert_on_supply_chain_fail !== false },
        { id: 'alert_on_pr_blocked',        label: 'Alert on auto-PR blocked by gate', type: 'checkbox',
          value: cfg.alert_on_pr_blocked !== false },
        { id: 'alert_on_secret_rotated',    label: 'Notify on secret rotation', type: 'checkbox',
          value: !!cfg.alert_on_secret_rotated },
        { id: 'alert_on_sso_login_failure', label: 'Notify on repeated SSO login failures', type: 'checkbox',
          value: !!cfg.alert_on_sso_login_failure },
        { id: 'rate_limit_per_hour',        label: 'Rate limit (alerts / hour, per channel)', type: 'number',
          value: cfg.rate_limit_per_hour || 60, required: true,
          hint: '1–10000. Excess events are dropped to avoid pager fatigue.' }
      ],
      validate: function(v){
        for (var k of ['slack_webhook','teams_webhook','generic_webhook']){
          if (v[k] && !/^https?:\/\//.test(v[k])) return k + ' must start with http(s)://';
          if (v[k] && v[k].length > 2000) return k + ' too long';
        }
        if (v.rate_limit_per_hour < 1 || v.rate_limit_per_hour > 10000) return 'rate_limit 1–10000';
        return null;
      },
      commit: function(v){
        v.email_recipients = (v.email_recipients || '').split(',').map(function(s){ return s.trim(); }).filter(Boolean);
        return proFetch('/api/v1/notifications/config', { method: 'PUT', body: JSON.stringify(v) });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast('Notification config saved','success');
  }).catch(function(err){
    if (err && err.is402){
      var body = document.getElementById('pro-body');
      if (body) body.innerHTML = upgradeOverlayHTML('Notifications', err.required, err.current);
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
};

PRO.testNotificationChannel = function(channel){
  proFetch('/api/v1/notifications/test', { method: 'POST', body: JSON.stringify({ channel: channel }) })
    .then(function(){
      if (typeof window.toast === 'function') window.toast('Test event queued for ' + channel + ' — check the log','success');
    })
    .catch(function(e){
      openModal({ title: 'Test failed', body: esc(e.error || e.message || e), submitLabel: 'OK', cancelLabel: '' });
    });
};

/* Add a "🔔 Notifications" button to every panel toolbar so users can
   reach the config from anywhere without going through Configure. */
function injectNotificationsBtn(root){
  if (!root) return;
  if (root.querySelector('[data-vspm-notif]')) return;
  var toolbar = root.querySelector('.vspm-toolbar .spacer');
  if (!toolbar) return;
  var btn = document.createElement('button');
  btn.setAttribute('data-vspm-notif', '1');
  btn.className = 'pro-btn ghost';
  btn.style.cssText = 'font-size:10px;margin-right:6px';
  btn.textContent = '🔔 Notifications';
  btn.addEventListener('click', function(){ PRO.openNotifications(); });
  toolbar.parentNode.insertBefore(btn, toolbar.nextSibling);
}

['cwpp','cspm','supplychain','prbot','secrets_vault','sbomdiff','observe','tenants','sso'].forEach(function(fid){
  var m = PRO.modules[fid];
  if (!m || !m.render) return;
  var orig = m.render;
  m.render = function(root){
    var ret = orig.call(this, root);
    Promise.resolve(ret).then(function(){
      setTimeout(function(){ injectNotificationsBtn(root); }, 200);
    });
    return ret;
  };
});

/* ════════════════════════════════════════════════════════════════════════
   INLINE PANELS — Analytics / Executive / Export render directly in the
   parent shell (not iframes). The SIEM companion script can't reach them
   so we decorate from here: detect panel activation and inject a small
   "⚙ Configure   🔔 Notifications" toolbar near the panel header.
   ════════════════════════════════════════════════════════════════════════ */

var INLINE_PANEL_SCHEMAS = {
  'panel-analytics': {
    feature_id: 'analytics',
    title: 'Analytics — retention + aggregation',
    sub: 'How long historical metrics are kept and which dashboards are precomputed.',
    fields: [
      { id: 'retention_days', label: 'Trend chart retention (days)', type: 'number',
        value: 90, required: true,
        hint: '7–730. PRO tier supports 730. Older runs are aggregated then dropped.' },
      { id: 'precompute_dashboards', label: 'Pre-compute dashboard aggregates', type: 'checkbox',
        value: true,
        hint: 'Reduces page-load time but costs extra DB cycles every 5 min.' },
      { id: 'default_chart_window', label: 'Default chart window', type: 'select',
        value: '30d', required: true,
        options: [
          { value: '7d',   label: 'Last 7 days' },
          { value: '30d',  label: 'Last 30 days (default)' },
          { value: '90d',  label: 'Last 90 days' },
          { value: '365d', label: 'Last year' }
        ] },
      { id: 'enable_anomaly_detection', label: 'Flag anomalies on trend lines', type: 'checkbox',
        value: true,
        hint: 'Z-score > 3 spikes get a red dot on the timeline.' }
    ],
    validate: function(v){
      if (v.retention_days < 7 || v.retention_days > 730) return 'Retention 7–730 days';
      return null;
    }
  },
  'panel-executive': {
    feature_id: 'executive',
    title: 'Executive report — content + cadence',
    sub: 'What appears in the auto-generated CISO/board report and when it is rendered.',
    fields: [
      { id: 'auto_generate_cron', label: 'Auto-generate cadence (cron)', type: 'text',
        value: '0 9 * * 1', required: true,
        hint: '5-field cron. Default = Mondays at 09:00 (weekly status).' },
      { id: 'include_kpi_summary', label: 'Include KPI summary', type: 'checkbox', value: true },
      { id: 'include_top_findings', label: 'Include top-10 critical findings', type: 'checkbox', value: true },
      { id: 'include_compliance_section', label: 'Include compliance posture section', type: 'checkbox', value: true,
        hint: 'NIST 800-53 / FedRAMP / CMMC roll-up.' },
      { id: 'include_trend_charts', label: 'Include trend charts (last 30 days)', type: 'checkbox', value: true },
      { id: 'recipients', label: 'Email recipients (CSV)', type: 'text',
        value: '', placeholder: 'ciso@acme.com, board-sec@acme.com',
        hint: 'Reports auto-emailed via the Notifications channel. Leave blank for download-only.' },
      { id: 'pdf_renderer', label: 'PDF render engine', type: 'select',
        value: 'chromium', required: true,
        options: [
          { value: 'chromium',     label: 'Headless Chromium (best fidelity)' },
          { value: 'wkhtmltopdf',  label: 'wkhtmltopdf (fast, basic)' },
          { value: 'weasyprint',   label: 'WeasyPrint (Python, FedRAMP-friendly)' }
        ] }
    ],
    validate: function(v){
      if (v.auto_generate_cron && (v.auto_generate_cron || '').split(/\s+/).filter(Boolean).length !== 5)
        return 'Cron must be 5 fields (e.g. "0 9 * * 1")';
      return null;
    }
  },
  'panel-export': {
    feature_id: 'export',
    title: 'Export — formats + size limits',
    sub: 'Per-tenant constraints on findings export to SARIF / CSV / JSON / OSCAL.',
    fields: [
      { id: 'max_rows_per_export', label: 'Max rows per export', type: 'number',
        value: 50000, required: true,
        hint: '100–5000000. Larger exports are streamed in chunks; PRO tier raises the cap.' },
      { id: 'default_format', label: 'Default download format', type: 'select',
        value: 'sarif', required: true,
        options: [
          { value: 'sarif',  label: 'SARIF v2.1.0 (DevTools spec)' },
          { value: 'csv',    label: 'CSV' },
          { value: 'json',   label: 'JSON (raw)' },
          { value: 'oscal',  label: 'OSCAL Assessment Results' }
        ] },
      { id: 'include_remediation', label: 'Include remediation guidance', type: 'checkbox',
        value: true,
        hint: 'Increases file size but makes the export self-contained for downstream tools.' },
      { id: 'redact_pii_in_export', label: 'Redact PII before export', type: 'checkbox',
        value: false,
        hint: 'On = scrub emails / IPs / SSNs from finding context. Required for some compliance flows.' },
      { id: 'enable_signed_export', label: 'Sign exports with cosign', type: 'checkbox',
        value: false,
        hint: 'PRO only. Adds an in-toto attestation alongside the file.' }
    ],
    validate: function(v){
      if (v.max_rows_per_export < 100 || v.max_rows_per_export > 5000000) return 'Max rows 100–5000000';
      return null;
    }
  }
};

function decorateInlinePanel(panelEl, schemaKey){
  if (!panelEl || panelEl.querySelector('[data-vspm-inline-toolbar]')) return;
  var schema = INLINE_PANEL_SCHEMAS[schemaKey];
  if (!schema) return;

  var bar = document.createElement('div');
  bar.setAttribute('data-vspm-inline-toolbar', '1');
  bar.style.cssText = 'display:flex;justify-content:flex-end;gap:6px;padding:8px 12px 0';
  bar.innerHTML =
    '<button class="pro-btn ghost" style="font-size:10px" data-act="cfg">⚙ Configure</button>' +
    '<button class="pro-btn ghost" style="font-size:10px" data-act="notif">🔔 Notifications</button>';
  panelEl.insertBefore(bar, panelEl.firstChild);

  bar.querySelector('[data-act="cfg"]').addEventListener('click', function(){
    openInlinePanelConfig(schema);
  });
  bar.querySelector('[data-act="notif"]').addEventListener('click', function(){
    if (PRO.openNotifications) PRO.openNotifications();
  });
}

function openInlinePanelConfig(schema){
  proFetch('/api/v1/features/' + schema.feature_id + '/config').then(function(resp){
    var saved = (resp && resp.config) || {};
    var fields = schema.fields.map(function(f){
      var copy = Object.assign({}, f);
      if (saved[f.id] !== undefined) copy.value = saved[f.id];
      return copy;
    });
    return formModal({
      title: schema.title, sub: schema.sub,
      submitLabel: 'Save', wide: true,
      fields: fields,
      validate: schema.validate,
      commit: function(values){
        return proFetch('/api/v1/features/' + schema.feature_id + '/config', {
          method: 'PUT', body: JSON.stringify({ config: values })
        });
      }
    });
  }).then(function(v){
    if (v && typeof window.toast === 'function') window.toast(schema.feature_id + ' config saved','success');
  }).catch(function(err){
    if (err && err.is402){
      openModal({ title: schema.title, body: upgradeOverlayHTML(schema.title, err.required, err.current), submitLabel: 'OK', cancelLabel: '' });
      return;
    }
    openModal({ title: 'Config error', body: esc(err.error || err.message || err), submitLabel: 'OK', cancelLabel: '' });
  });
}

// Decorate on initial load + watch for class changes (panel switcher toggles
// .active classes when user navigates the sidebar). MutationObserver keeps
// us idempotent — decoratePanelEl checks for an existing toolbar.
function decorateAllInlinePanels(){
  Object.keys(INLINE_PANEL_SCHEMAS).forEach(function(id){
    var el = document.getElementById(id);
    if (el) decorateInlinePanel(el, id);
  });
}
if (document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', decorateAllInlinePanels);
} else {
  decorateAllInlinePanels();
}
setTimeout(decorateAllInlinePanels, 800);
setTimeout(decorateAllInlinePanels, 2000);

(window.VSP_DEBUG && console.log('[VSP-PRO-REALAPI v3.8] + inline-panel Configure decorators (analytics/executive/export)'));
})();
