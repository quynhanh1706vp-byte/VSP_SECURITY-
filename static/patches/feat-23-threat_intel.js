/* ═══════════════════════════════════════════════════════════════════════
   FEAT-23 — threat_intel panel L2 UX states
   ───────────────────────────────────────────────────────────────────────
   Wraps the threat_intel panel's data loader (`loadFromAPI`) with the
   VSPUXState skeleton/empty/error pattern, applied to:
     • #ioc-list    (IOC matches card)
     • #feeds-list  (Feed sources card)
   KPIs (#k-iocs, #k-matches, #k-cves, #k-feeds) are reset on empty/error.

   Pattern mirrors FEAT-20 (ai_analyst), FEAT-21 (settings),
   FEAT-22 (correlation).

   Note: threat_intel.html runs inside an iframe and pulls TOKEN via
   postMessage. The patch handles the no-token state by showing
   "Sign in to load …" instead of leaving skeleton stuck.

   Inject via:
     <script src="/static/patches/feat-23-threat_intel.js"></script>
   in threat_intel.html, just before </body>.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  if (typeof window.loadFromAPI !== 'function') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', _install, { once: true });
    } else {
      setTimeout(_install, 0);
    }
    return;
  }
  _install();

  function _install() {
    if (typeof window.loadFromAPI !== 'function') {
      console.warn('[FEAT-23] threat_intel — loadFromAPI not found, skipping');
      return;
    }
    if (window.__FEAT_23_INSTALLED__) return;
    window.__FEAT_23_INSTALLED__ = true;

    // ── UX state helpers ────────────────────────────────────────────────
    const SKEL_ROW = (h) =>
      '<div class="vsp-skel" style="height:' + h + 'px;margin:6px 0;' +
      'border-radius:6px;background:linear-gradient(90deg,' +
      'rgba(255,255,255,.04) 0%,rgba(255,255,255,.08) 50%,' +
      'rgba(255,255,255,.04) 100%);background-size:200% 100%;' +
      'animation:vsp-shimmer 1.2s infinite linear"></div>';

    function _ensureShimmerCSS() {
      if (document.getElementById('vsp-ux-shimmer-css')) return;
      const css = document.createElement('style');
      css.id = 'vsp-ux-shimmer-css';
      css.textContent =
        '@keyframes vsp-shimmer{0%{background-position:200% 0}' +
        '100%{background-position:-200% 0}}' +
        '.vsp-empty{padding:24px 12px;text-align:center;color:var(--t3);' +
        'font-size:12px;font-style:italic}' +
        '.vsp-error{padding:14px 12px;border-left:2px solid var(--red);' +
        'background:rgba(239,68,68,.05);color:var(--red);font-size:12px;' +
        'border-radius:0 6px 6px 0;display:flex;justify-content:space-between;' +
        'align-items:center;gap:10px}' +
        '.vsp-error button{background:rgba(239,68,68,.1);border:1px solid ' +
        'rgba(239,68,68,.3);color:var(--red);padding:4px 10px;border-radius:4px;' +
        'font-size:11px;cursor:pointer;font-family:inherit}' +
        '.vsp-error button:hover{background:rgba(239,68,68,.2)}';
      document.head.appendChild(css);
    }

    function showSkeleton(elId, rows, h) {
      const el = document.getElementById(elId);
      if (!el) return;
      let html = '';
      for (let i = 0; i < (rows || 4); i++) html += SKEL_ROW(h || 56);
      el.innerHTML = html;
    }

    function showEmpty(elId, msg) {
      const el = document.getElementById(elId);
      if (!el) return;
      el.innerHTML = '<div class="vsp-empty">' + (msg || 'No data') + '</div>';
    }

    function showError(elId, msg, retryFn) {
      const el = document.getElementById(elId);
      if (!el) return;
      const btnId = 'vsp-retry-' + elId;
      el.innerHTML =
        '<div class="vsp-error"><span>⚠ ' + (msg || 'Failed to load') +
        '</span><button id="' + btnId + '">↻ Retry</button></div>';
      const btn = document.getElementById(btnId);
      if (btn && typeof retryFn === 'function') {
        btn.addEventListener('click', retryFn, { once: true });
      }
    }

    _ensureShimmerCSS();

    // ── Wrap loadFromAPI ────────────────────────────────────────────────
    const _origLoadFromAPI = window.loadFromAPI;

    window.loadFromAPI = function _wrappedLoadFromAPI() {
      const iocEl = document.getElementById('ioc-list');
      const feedsEl = document.getElementById('feeds-list');
      const iocEmpty = iocEl && iocEl.children.length === 0;
      const feedsEmpty = feedsEl && feedsEl.children.length === 0;

      if (iocEmpty) showSkeleton('ioc-list', 5, 52);
      if (feedsEmpty) showSkeleton('feeds-list', 4, 44);

      // No TOKEN → show sign-in prompt instead of stuck skeleton.
      // (Original silently returns when no TOKEN.)
      if (!window.TOKEN) {
        if (iocEmpty) showEmpty('ioc-list', 'Sign in to load IOCs');
        if (feedsEmpty) showEmpty('feeds-list', 'Sign in to load feeds');
        return;
      }

      const API = window.API || '';
      const h = { Authorization: 'Bearer ' + window.TOKEN };

      Promise.all([
        fetch(API + '/api/v1/ti/iocs?limit=20', { headers: h })
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))),
        fetch(API + '/api/v1/ti/feeds', { headers: h })
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))),
        fetch(API + '/api/v1/ti/matches', { headers: h })
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))),
      ])
        .then(function (res) {
          // IOCs
          const iocs = (res[0] && res[0].iocs) || [];
          if (iocs.length) {
            window.IOCS = iocs.map(function (i) {
              return Object.assign({
                id: i.id || Math.random().toString(36).slice(2),
                matched: false, findings: [], mitre: [],
              }, i);
            });
            if (typeof window.renderIOCs === 'function') window.renderIOCs();
          } else {
            showEmpty('ioc-list', 'No IOC matches yet');
            const kIocs = document.getElementById('k-iocs');
            if (kIocs) kIocs.textContent = '0';
          }

          // Feeds
          const feeds = (res[1] && res[1].feeds) || [];
          if (feeds.length) {
            window.FEEDS = feeds.map(function (f) {
              return Object.assign({ icon: '◈', lastSync: '—' }, f);
            });
            if (typeof window.renderFeeds === 'function') window.renderFeeds();
          } else {
            showEmpty('feeds-list', 'No feed sources configured');
            const kFeeds = document.getElementById('k-feeds');
            if (kFeeds) kFeeds.textContent = '0';
          }

          // Matches KPI (no list, just counter)
          const matches = (res[2] && res[2].matches) || [];
          const kMatches = document.getElementById('k-matches');
          if (kMatches) kMatches.textContent = matches.length || 0;
        })
        .catch(function (err) {
          console.error('[FEAT-23] threat_intel load failed:', err);
          showError('ioc-list', 'Failed to load IOCs', function () { window.loadFromAPI(); });
          showError('feeds-list', 'Failed to load feeds', function () { window.loadFromAPI(); });
        });
    };

    // Initial paint
    setTimeout(function () {
      const iocEl = document.getElementById('ioc-list');
      const feedsEl = document.getElementById('feeds-list');
      if (iocEl && iocEl.children.length === 0) showSkeleton('ioc-list', 5, 52);
      if (feedsEl && feedsEl.children.length === 0) showSkeleton('feeds-list', 4, 44);
    }, 0);

    console.log('[FEAT-23] threat_intel — loadFromAPI wrapped (iocs + feeds + matches)');
  }
})();
