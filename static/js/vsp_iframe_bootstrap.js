/* VSP iframe token bootstrap v3 — centralized origin check
 *
 * v3 changes (VSP-SEC-001 Sprint 0):
 *   - Added origin whitelist for postMessage receivers
 *   - Exposed window.VSPOrigin.check(event) helper for panel code
 *   - postMessage send uses explicit target origin (not '*')
 *   - Origins configurable via <meta name="vsp-allowed-origins" content="...">
 *
 * Include ở đầu <head> mỗi panel bằng 1 dòng:
 *   <meta name="vsp-allowed-origins" content="self">
 *   <script src="/static/js/vsp_iframe_bootstrap.js"></script>
 *
 * Meta values:
 *   "self"                         → window.location.origin only
 *   "self,https://vsp.mil"         → same-origin + vsp.mil
 *   "self,https://*.vsp.mil"       → NOT supported (no wildcard, explicit list)
 *
 * TODO(SEC-007): khi migrate JWT sang httpOnly cookie (item #6 trong VSP_42),
 * xoa toan bo viec doc/ghi localStorage o file nay — chi giu postMessage path.
 */
(function () {
  'use strict';
  if (window.__vspBootstrapV3) return;
  window.__vspBootstrapV3 = true;

  var DEBUG = !!window.VSP_DEBUG;
  var MIN_LEN = 20;
  var tok = '';

  // ── Origin whitelist setup ────────────────────────────────
  function buildAllowedOrigins() {
    var list = [window.location.origin];
    var meta = document.querySelector('meta[name="vsp-allowed-origins"]');
    if (!meta) return list;

    var content = (meta.content || '').split(',');
    for (var i = 0; i < content.length; i++) {
      var val = content[i].trim();
      if (!val || val === 'self') continue;
      if (val.indexOf('*') !== -1) {
        if (DEBUG) console.warn('[VSP] wildcard origin rejected:', val);
        continue;
      }
      try {
        var parsed = new URL(val);
        // Only allow https (or http for localhost)
        var isLocalhost = parsed.hostname === 'localhost' ||
                          parsed.hostname === '127.0.0.1' ||
                          parsed.hostname.endsWith('.localhost');
        if (parsed.protocol !== 'https:' && !isLocalhost) {
          if (DEBUG) console.warn('[VSP] non-https origin rejected:', val);
          continue;
        }
        list.push(parsed.origin);
      } catch (e) {
        if (DEBUG) console.warn('[VSP] invalid origin rejected:', val);
      }
    }
    return list;
  }

  var ALLOWED_ORIGINS = buildAllowedOrigins();
  if (DEBUG) console.log('[VSP bootstrap v3] allowed origins:', ALLOWED_ORIGINS);

  // ── Public helper for panel code ──────────────────────────
  window.VSPOrigin = {
    allowed: ALLOWED_ORIGINS.slice(),
    /**
     * Check if a postMessage event is from an allowed origin.
     * Panels MUST call this at the top of their message handlers:
     *
     *   window.addEventListener('message', function(e) {
     *     if (!window.VSPOrigin.check(e)) return;
     *     // ... handler logic
     *   });
     */
    check: function (event) {
      if (!event || typeof event.origin !== 'string') return false;
      for (var i = 0; i < ALLOWED_ORIGINS.length; i++) {
        if (event.origin === ALLOWED_ORIGINS[i]) return true;
      }
      if (DEBUG) console.warn('[VSP] rejected message from:', event.origin);
      return false;
    },
    /**
     * Safe postMessage helper — uses target's origin, not '*'.
     */
    send: function (target, data, targetOrigin) {
      if (!target || typeof target.postMessage !== 'function') return false;
      var origin = targetOrigin || window.location.origin;
      // Only send to allowed origins
      for (var i = 0; i < ALLOWED_ORIGINS.length; i++) {
        if (origin === ALLOWED_ORIGINS[i]) {
          target.postMessage(data, origin);
          return true;
        }
      }
      if (DEBUG) console.warn('[VSP] postMessage to non-allowed origin blocked:', origin);
      return false;
    }
  };

  // ── Token acquisition ─────────────────────────────────────
  try {
    var p = new URLSearchParams(window.location.search).get('token');
    if (p) tok = p;
  } catch (e) {}

  if (!tok) {
    try { tok = localStorage.getItem('vsp_token') || ''; } catch (e) {}
  }

  // Parent frame access — only works if same-origin (browser enforced)
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
    if (DEBUG) console.log('[VSP bootstrap v3] token len=', tok.length);
    resolveReady(tok);
  } else {
    if (DEBUG) console.warn('[VSP bootstrap v3] no token yet, waiting for postMessage');
    window.addEventListener('message', function onMsg(e) {
      // VSP-SEC-001: reject non-allowed origins
      if (!window.VSPOrigin.check(e)) return;
      if (!e.data || e.data.type !== 'vsp:token') return;
      var t = e.data.token || '';
      if (t.length >= MIN_LEN && !window.TOKEN) {
        window.TOKEN = t;
        try { localStorage.setItem('vsp_token', t); } catch (err) {}
        resolveReady(t);
        window.removeEventListener('message', onMsg);
      }
    });
    // Request token from parent — use parent's origin, not wildcard
    if (window.parent !== window) {
      // Parent must be same-origin for iframe to work with CSP frame-ancestors 'self'
      // so parent.origin === window.location.origin
      try {
        window.parent.postMessage(
          { type: 'vsp:request_token' },
          window.location.origin
        );
      } catch (e) {
        if (DEBUG) console.warn('[VSP] failed to request token from parent:', e);
      }
    }
  }
})();
