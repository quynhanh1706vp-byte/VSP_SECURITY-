// =====================================================================
// H3.Q Fix Validation Pipeline — Frontend integration
// File: web/static/h3q_validation_ui.js
//
// Drop-in extension to existing autofix modal (H3.N "Preview fix").
// Adds:
//   • Validation score gauge (0-100)
//   • Per-validator badges (pass/fail/skip)
//   • Confidence-final pill (with "downgraded" indicator if applicable)
//   • Expand-to-see error messages on fail
//
// Wire-up: in vsp_features_patch.js after fetching cache hit, call
//          renderH3QValidation(modalEl, cacheKey)
// =====================================================================

(function () {
  'use strict';

  const API_BASE = window.VSP_API_BASE || '';
  const TOKEN = window.VSP_TOKEN || localStorage.getItem('vsp_token') || '';

  const VALIDATOR_LABELS = {
    line_scope: 'Line scope',
    lint:       'Pattern regression',
    syntax:     'Syntax',
    ast_diff:   'AST structure',
    idempotent: 'Idempotency',
    compile:    'Compile (vet)',
  };

  const STATUS_STYLES = {
    pass:  { bg: 'rgba(34,197,94,.15)',  fg: '#22c55e', icon: '✓' },
    fail:  { bg: 'rgba(239,68,68,.15)',  fg: '#ef4444', icon: '✗' },
    skip:  { bg: 'rgba(148,163,184,.15)',fg: '#94a3b8', icon: '–' },
    error: { bg: 'rgba(245,158,11,.15)', fg: '#f59e0b', icon: '!' },
  };

  /**
   * Fetch validation results for a cache_key.
   * Returns null on 404 (legacy cache entry, pre-H3.Q).
   */
  async function fetchValidation(cacheKey) {
    if (!cacheKey) return null;
    try {
      const r = await fetch(API_BASE + '/api/v1/autofix/validation/' + encodeURIComponent(cacheKey), {
        headers: TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {},
      });
      if (r.status === 404) return null;
      if (!r.ok) return null;
      return await r.json();
    } catch (_) {
      return null;
    }
  }

  /**
   * Render validation panel inside an existing autofix modal.
   * @param {HTMLElement} container — element to append the panel to
   * @param {string} cacheKey
   */
  async function renderH3QValidation(container, cacheKey) {
    if (!container) return;

    // Placeholder while loading
    let panel = container.querySelector('[data-h3q-panel]');
    if (!panel) {
      panel = document.createElement('div');
      panel.setAttribute('data-h3q-panel', '1');
      panel.style.cssText = 'margin-top:14px;padding:12px;background:rgba(15,23,42,.5);' +
        'border:1px solid rgba(148,163,184,.15);border-radius:8px;font-size:11px';
      panel.innerHTML = '<div style="color:#94a3b8">⟳ Loading validation results…</div>';
      container.appendChild(panel);
    }

    const data = await fetchValidation(cacheKey);

    if (!data || !data.results || data.results.length === 0) {
      panel.innerHTML = '<div style="color:#94a3b8;font-size:10px">' +
        '⚠ No validation data — this fix predates H3.Q (cached before validation pipeline). ' +
        '<a href="#" data-h3q-revalidate style="color:#06b6d4;text-decoration:none">Re-validate now →</a></div>';

      const link = panel.querySelector('[data-h3q-revalidate]');
      if (link) {
        link.addEventListener('click', async function (e) {
          e.preventDefault();
          link.textContent = '⟳ Validating…';
          try {
            const r = await fetch(API_BASE + '/api/v1/autofix/validation/run', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...(TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {}),
              },
              body: JSON.stringify({ cache_key: cacheKey, force: true }),
            });
            if (r.ok) {
              await renderH3QValidation(container, cacheKey);
            } else {
              link.textContent = '✗ Re-validation failed (' + r.status + ')';
            }
          } catch (err) {
            link.textContent = '✗ ' + err.message;
          }
        });
      }
      return;
    }

    panel.innerHTML = buildPanelHTML(data);
  }

  function buildPanelHTML(d) {
    const scoreColor =
      d.score >= 90 ? '#22c55e' :
      d.score >= 70 ? '#06b6d4' :
      d.score >= 50 ? '#f59e0b' : '#ef4444';

    const overallStyle = STATUS_STYLES[d.overall_status] || STATUS_STYLES.skip;

    const downgraded = d.confidence_in &&
                       d.confidence_final &&
                       d.confidence_in !== d.confidence_final;

    const validatorRows = (d.results || []).map(function (r) {
      const st = STATUS_STYLES[r.status] || STATUS_STYLES.skip;
      const label = VALIDATOR_LABELS[r.validator] || r.validator;
      const dur = r.duration_ms != null ? r.duration_ms + 'ms' : '';
      const errMsg = r.error_msg ? escapeHtml(r.error_msg) : '';
      return (
        '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;' +
        'border-radius:5px;margin-bottom:3px;background:' + st.bg + '">' +
          '<span style="color:' + st.fg + ';font-weight:700;width:14px;text-align:center">' + st.icon + '</span>' +
          '<span style="flex:1;color:#e2e8f0;font-size:11px">' + escapeHtml(label) + '</span>' +
          '<span style="color:' + st.fg + ';font-size:10px;font-weight:600;text-transform:uppercase">' + r.status + '</span>' +
          '<span style="color:#64748b;font-size:9px;font-family:monospace">' + dur + '</span>' +
        '</div>' +
        (errMsg ?
          '<div style="margin:-2px 0 6px 24px;padding:4px 6px;background:rgba(0,0,0,.25);' +
          'border-radius:4px;color:#cbd5e1;font-size:10px;font-family:monospace;' +
          'word-break:break-word">' + errMsg + '</div>' : '')
      );
    }).join('');

    return (
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">' +
        '<div style="flex:1">' +
          '<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px">' +
          'H3.Q Validation</div>' +
          '<div style="font-size:13px;color:#e2e8f0;font-weight:600;margin-top:2px">' +
            'Status: <span style="color:' + overallStyle.fg + ';text-transform:uppercase">' +
              d.overall_status + '</span>' +
          '</div>' +
        '</div>' +
        '<div style="text-align:center;padding:4px 10px;border-radius:6px;background:rgba(0,0,0,.3)">' +
          '<div style="font-size:18px;font-weight:700;color:' + scoreColor + ';line-height:1">' +
            d.score + '</div>' +
          '<div style="font-size:9px;color:#64748b;letter-spacing:.5px">SCORE</div>' +
        '</div>' +
      '</div>' +

      // Confidence row
      '<div style="display:flex;align-items:center;gap:6px;margin-bottom:10px;font-size:10px">' +
        '<span style="color:#64748b">Confidence:</span>' +
        '<span style="padding:2px 6px;border-radius:4px;background:rgba(148,163,184,.1);' +
        'color:#cbd5e1;font-family:monospace">' + (d.confidence_in || 'medium') + '</span>' +
        (downgraded ?
          '<span style="color:#f59e0b">→</span>' +
          '<span style="padding:2px 6px;border-radius:4px;background:rgba(245,158,11,.15);' +
          'color:#f59e0b;font-family:monospace;font-weight:600">' + d.confidence_final + '</span>' +
          '<span style="color:#f59e0b;font-size:9px;margin-left:auto">⚠ downgraded</span>' :
          '<span style="color:#64748b">·</span>' +
          '<span style="color:#64748b;font-size:9px;margin-left:auto">no change</span>'
        ) +
      '</div>' +

      // Validator rows
      '<div>' + validatorRows + '</div>' +

      // Footer
      '<div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(148,163,184,.1);' +
      'display:flex;justify-content:space-between;color:#64748b;font-size:9px">' +
        '<span>Validated ' + relativeTime(d.validated_at) + '</span>' +
        '<span>cache_key: <span style="font-family:monospace">' +
          (d.cache_key || '').slice(0, 12) + '…</span></span>' +
      '</div>'
    );
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;',
               '"': '&quot;', "'": '&#39;' }[m];
    });
  }

  function relativeTime(iso) {
    if (!iso) return 'just now';
    const d = new Date(iso);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return Math.floor(diff) + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  /**
   * Render aggregate stats (for admin dashboard).
   * @param {HTMLElement} container
   */
  async function renderH3QStats(container) {
    if (!container) return;
    container.innerHTML = '<div style="color:#94a3b8;font-size:11px">⟳ Loading…</div>';
    try {
      const r = await fetch(API_BASE + '/api/v1/autofix/validation/stats', {
        headers: TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {},
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const d = await r.json();

      const sm = d.summary || {};
      let html = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px">' +
        statCard('Cache entries (30d)', sm.cache_entries_30d || 0, '#cbd5e1') +
        statCard('Validated', sm.validated || 0, '#06b6d4') +
        statCard('Pass', sm.pass || 0, '#22c55e') +
        statCard('Coverage',
          (sm.validation_coverage_pct || 0) + '%',
          (sm.validation_coverage_pct || 0) >= 90 ? '#22c55e' : '#f59e0b') +
        '</div>';

      html += '<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;' +
        'letter-spacing:.5px;margin-bottom:6px">Per-validator (last 30 days)</div>';
      html += '<div>';
      (d.validators || []).forEach(function (v) {
        const pr = v.pass_rate_pct || 0;
        const prColor = pr >= 90 ? '#22c55e' : pr >= 70 ? '#06b6d4' : '#f59e0b';
        html += '<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;' +
          'border-radius:5px;margin-bottom:3px;background:rgba(15,23,42,.4)">' +
          '<span style="flex:1;color:#e2e8f0;font-size:11px">' +
            (VALIDATOR_LABELS[v.validator] || v.validator) + '</span>' +
          '<span style="color:#64748b;font-size:10px">' + v.total + ' runs</span>' +
          '<span style="color:#22c55e;font-size:10px">✓' + v.pass + '</span>' +
          '<span style="color:#ef4444;font-size:10px">✗' + v.fail + '</span>' +
          '<span style="color:' + prColor + ';font-weight:600;font-size:11px;width:42px;text-align:right">' +
            pr.toFixed(1) + '%</span>' +
          '<span style="color:#64748b;font-size:9px;font-family:monospace;width:48px;text-align:right">' +
            v.avg_duration_ms.toFixed(0) + 'ms</span>' +
          '</div>';
      });
      html += '</div>';

      container.innerHTML = html;
    } catch (e) {
      container.innerHTML = '<div style="color:#ef4444;font-size:11px">' +
        '✗ Failed to load: ' + escapeHtml(e.message) + '</div>';
    }
  }

  function statCard(label, value, color) {
    return '<div style="background:rgba(15,23,42,.5);border:1px solid rgba(148,163,184,.15);' +
      'border-radius:6px;padding:8px 10px">' +
        '<div style="font-size:18px;font-weight:700;color:' + color + ';line-height:1.1">' +
          value + '</div>' +
        '<div style="font-size:9px;color:#94a3b8;letter-spacing:.3px;margin-top:2px;' +
        'text-transform:uppercase">' + label + '</div>' +
      '</div>';
  }

  // Export
  window.H3Q = {
    renderValidation: renderH3QValidation,
    renderStats:      renderH3QStats,
    fetchValidation:  fetchValidation,
  };

  // Auto-attach: if existing modal opens via custom event, hook in
  document.addEventListener('vsp:autofix-modal-open', function (e) {
    if (e && e.detail && e.detail.cacheKey && e.detail.container) {
      renderH3QValidation(e.detail.container, e.detail.cacheKey);
    }
  });

})();
