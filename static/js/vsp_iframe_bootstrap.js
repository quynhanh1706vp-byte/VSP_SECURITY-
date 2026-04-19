/* VSP iframe token bootstrap v2 — single source of truth
 * Replaces the 25x duplicated inline <script> blocks in static/panels/*.html
 *
 * TODO(SEC-007): khi migrate JWT sang httpOnly cookie (item #6 trong VSP_42),
 * xoa toan bo viec doc/ghi localStorage o file nay — chi giu postMessage path.
 *
 * Include o dau <head> moi panel bang 1 dong:
 *   <script src="/static/js/vsp_iframe_bootstrap.js"></script>
 */
(function () {
  'use strict';
  if (window.__vspBootstrapV2) return;
  window.__vspBootstrapV2 = true;

  var DEBUG = !!window.VSP_DEBUG;
  var MIN_LEN = 20;
  var tok = '';

  try {
    var p = new URLSearchParams(window.location.search).get('token');
    if (p) tok = p;
  } catch (e) {}

  if (!tok) {
    try { tok = localStorage.getItem('vsp_token') || ''; } catch (e) {}
  }

  if (!tok) {
    try { tok = window.parent.TOKEN || window.parent.localStorage.getItem('vsp_token') || ''; } catch (e) {}
  }
  if (!tok) {
    try { tok = window.top.TOKEN || window.top.localStorage.getItem('vsp_token') || ''; } catch (e) {}
  }

  var resolveReady;
  window.__vspTokenReady = new Promise(function (r) { resolveReady = r; });

  if (tok && tok.length >= MIN_LEN) {
    window.TOKEN = tok;
    try { localStorage.setItem('vsp_token', tok); } catch (e) {}
    if (DEBUG) console.log('[VSP bootstrap v2] token len=', tok.length);
    resolveReady(tok);
  } else {
    if (DEBUG) console.warn('[VSP bootstrap v2] no token yet, waiting for postMessage');
    window.addEventListener('message', function onMsg(e) {
      if (!e.data || e.data.type !== 'vsp:token') return;
      var t = e.data.token || '';
      if (t.length >= MIN_LEN && !window.TOKEN) {
        window.TOKEN = t;
        try { localStorage.setItem('vsp_token', t); } catch (err) {}
        resolveReady(t);
        window.removeEventListener('message', onMsg);
      }
    });
    if (window.parent !== window) {
      try { window.parent.postMessage({ type: 'vsp:request_token' }, '*'); } catch (e) {}
    }
  }
})();
