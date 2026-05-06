/* FEAT-21 PATCH APPLIED — settings L2 UX states */
/* Wraps 3 async loaders with VSPUXState skeleton/empty/error pattern */
(function() {
  if (window.__FEAT21_APPLIED__) return;
  window.__FEAT21_APPLIED__ = true;

  var hasUX = function() { return typeof VSPUXState !== 'undefined'; };

  // ── Wrap loadAPIKeysFromBackend ───────────────────────────────
  function wrapAPIKeys() {
    if (typeof loadAPIKeysFromBackend !== 'function') return false;
    if (loadAPIKeysFromBackend.__feat21_wrapped__) return true;
    var _orig = loadAPIKeysFromBackend;
    window.loadAPIKeysFromBackend = async function() {
      if (hasUX()) {
        try { VSPUXState.skeleton('#apikeys-tbody', {rows: 4, kind: 'table'}); } catch(e) {}
      }
      try {
        var result = await _orig.apply(this, arguments);
        if (hasUX() && typeof _apiKeys !== 'undefined' && _apiKeys.length === 0) {
          try {
            VSPUXState.empty('#apikeys-tbody',
              'No API keys yet — create one to allow programmatic access',
              loadAPIKeysFromBackend);
          } catch(e) {}
        }
        return result;
      } catch (e) {
        console.error('[FEAT-21] loadAPIKeysFromBackend failed', e);
        if (hasUX()) {
          try {
            VSPUXState.error('#apikeys-tbody',
              'Failed to load API keys: ' + (e.message || 'unknown'),
              loadAPIKeysFromBackend);
          } catch(_) {}
        }
        if (typeof showToast === 'function') showToast('API keys load failed', 'error');
        throw e;
      }
    };
    window.loadAPIKeysFromBackend.__feat21_wrapped__ = true;
    return true;
  }

  // ── Wrap loadHealth ───────────────────────────────────────────
  function wrapHealth() {
    if (typeof loadHealth !== 'function') return false;
    if (loadHealth.__feat21_wrapped__) return true;
    var _orig = loadHealth;
    window.loadHealth = async function() {
      if (hasUX()) {
        try { VSPUXState.skeleton('#health-body', {rows: 3, kind: 'card'}); } catch(e) {}
      }
      try {
        var result = await _orig.apply(this, arguments);
        return result;
      } catch (e) {
        console.error('[FEAT-21] loadHealth failed', e);
        if (hasUX()) {
          try {
            VSPUXState.error('#health-body',
              'Health probe failed: ' + (e.message || 'backend unreachable'),
              loadHealth);
          } catch(_) {}
        }
        if (typeof showToast === 'function') showToast('Health load failed', 'error');
        throw e;
      }
    };
    window.loadHealth.__feat21_wrapped__ = true;
    return true;
  }

  // ── Wrap loadToolConfig ───────────────────────────────────────
  function wrapToolConfig() {
    if (typeof loadToolConfig !== 'function') return false;
    if (loadToolConfig.__feat21_wrapped__) return true;
    var _orig = loadToolConfig;
    window.loadToolConfig = async function() {
      if (hasUX()) {
        try { VSPUXState.skeleton('#tool-cfg-body', {rows: 5, kind: 'list'}); } catch(e) {}
      }
      try {
        var result = await _orig.apply(this, arguments);
        return result;
      } catch (e) {
        console.error('[FEAT-21] loadToolConfig failed', e);
        if (hasUX()) {
          try {
            VSPUXState.error('#tool-cfg-body',
              'Tool config load failed: ' + (e.message || 'unknown'),
              loadToolConfig);
          } catch(_) {}
        }
        if (typeof showToast === 'function') showToast('Tool config load failed', 'error');
        throw e;
      }
    };
    window.loadToolConfig.__feat21_wrapped__ = true;
    return true;
  }

  function tryWrapAll() {
    var ok1 = wrapAPIKeys();
    var ok2 = wrapHealth();
    var ok3 = wrapToolConfig();
    if (ok1 && ok2 && ok3) {
      console.log('[FEAT-21] settings — 3 loaders wrapped (apikeys, health, tool-cfg)');
      return;
    }
    setTimeout(tryWrapAll, 100);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', tryWrapAll);
  } else {
    tryWrapAll();
  }
})();
