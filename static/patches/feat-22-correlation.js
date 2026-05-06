/* ═══════════════════════════════════════════════════════════════════════
   FEAT-22 — correlation panel L2 UX states
   ───────────────────────────────────────────────────────────────────────
   Wraps the correlation panel's data loader (`loadFromAPI`) with the
   VSPUXState skeleton/empty/error pattern, applied to:
     • #rules-list      (correlation rules card)
     • #incidents-list  (active incidents card)

   Pattern mirrors FEAT-20 (ai_analyst) + FEAT-21 (settings):
     1. Show skeleton rows immediately on call.
     2. Catch fetch failures → render error state with retry button.
     3. After success, if a list is empty → render empty state.

   No backend changes. No HTML edits required (pure JS overlay).
   Inject via:
     <script src="/static/patches/feat-22-correlation.js"></script>
   in correlation.html, just before </body>.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  // ── Guards: only run on the correlation panel page ────────────────────
  if (typeof window.loadFromAPI !== 'function') {
    // If correlation.html hasn't defined loadFromAPI yet, defer once.
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', _install, { once: true });
    } else {
      // Fallback: small delay to let inline <script> finish
      setTimeout(_install, 0);
    }
    return;
  }
  _install();

  function _install() {
    if (typeof window.loadFromAPI !== 'function') {
      console.warn('[FEAT-22] correlation — loadFromAPI not found, skipping');
      return;
    }
    if (window.__FEAT_22_INSTALLED__) return;
    window.__FEAT_22_INSTALLED__ = true;

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
      // Don't show skeleton if lists already have data (avoids flicker
      // on the periodic re-poll). Detect by counting children.
      const rulesEl = document.getElementById('rules-list');
      const incEl = document.getElementById('incidents-list');
      const rulesEmpty = rulesEl && rulesEl.children.length === 0;
      const incEmpty = incEl && incEl.children.length === 0;

      if (rulesEmpty) showSkeleton('rules-list', 5, 48);
      if (incEmpty) showSkeleton('incidents-list', 4, 64);

      // Token guard — original returns silently if no TOKEN.
      // We mirror that but show empty state instead of leaving skeleton.
      if (!window.TOKEN) {
        if (rulesEmpty) showEmpty('rules-list', 'Sign in to load rules');
        if (incEmpty) showEmpty('incidents-list', 'Sign in to load incidents');
        return;
      }

      const API = window.API || '';
      const h = { Authorization: 'Bearer ' + window.TOKEN };

      Promise.all([
        fetch(API + '/api/v1/correlation/rules', { headers: h })
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))),
        fetch(API + '/api/v1/correlation/incidents', { headers: h })
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))),
      ])
        .then(function (res) {
          // Rules
          const rules = (res[0] && res[0].rules) || [];
          if (rules.length) {
            window.RULES = rules.map(function (r) {
              return Object.assign({}, r, { cond: r.cond || r.condition_expr || '' });
            });
            if (typeof window.renderRules === 'function') window.renderRules();
          } else {
            showEmpty('rules-list', 'No correlation rules yet — click + New rule');
          }

          // Incidents
          const incidents = (res[1] && res[1].incidents) || [];
          if (incidents.length) {
            window.INCIDENTS = incidents.map(function (i) {
              return Object.assign({}, i, {
                severity: (i.severity || 'MEDIUM').toUpperCase(),
                source_refs: i.source_refs || [],
                timeline: [{
                  ts: i.created_at ? i.created_at.slice(11, 19) : 'now',
                  sev: 'info', src: 'system', msg: i.title,
                }],
                evidence: [], mitre: [],
                actions: [
                  { icon: '▶', label: 'Run SOAR playbook', color: 'var(--purple2)', tc: 'var(--purple)' },
                  { icon: '⊕', label: 'Create Jira ticket', color: 'var(--cyan2)', tc: 'var(--cyan)' },
                ],
              });
            });
            if (typeof window.renderIncidents === 'function') window.renderIncidents();
          } else {
            showEmpty('incidents-list', '✓ No active incidents');
            // Still update KPI
            const kInc = document.getElementById('k-inc');
            const kIncSub = document.getElementById('k-inc-sub');
            const incSub = document.getElementById('inc-sub');
            if (kInc) kInc.textContent = '0';
            if (kIncSub) kIncSub.textContent = '0 critical';
            if (incSub) incSub.textContent = '0 incidents';
          }
        })
        .catch(function (err) {
          console.error('[FEAT-22] correlation load failed:', err);
          showError('rules-list', 'Failed to load rules', function () { window.loadFromAPI(); });
          showError('incidents-list', 'Failed to load incidents', function () { window.loadFromAPI(); });
        });
    };

    // ── Initial paint: if loadFromAPI hasn't fired yet, show skeletons ──
    // The original page calls loadFromAPI on token-ready. We pre-paint so
    // the user never sees a blank pane.
    setTimeout(function () {
      const rulesEl = document.getElementById('rules-list');
      const incEl = document.getElementById('incidents-list');
      if (rulesEl && rulesEl.children.length === 0) showSkeleton('rules-list', 5, 48);
      if (incEl && incEl.children.length === 0) showSkeleton('incidents-list', 4, 64);
    }, 0);

    console.log('[FEAT-22] correlation — loadFromAPI wrapped (rules + incidents)');
  }
})();
