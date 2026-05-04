// =====================================================================
// H3.S Auto-PR — Frontend integration
// File: web/static/h3s_autopr_ui.js
//
// Adds:
//   • "Apply fix → Create PR" button in autofix modal (alongside H3.Q badges)
//   • Repo selector dropdown (multi-tenant)
//   • PR status indicator after creation
//   • Admin PR list panel (renderH3SPRList)
// =====================================================================

(function () {
  'use strict';

  const API_BASE = window.VSP_API_BASE || '';
  const TOKEN = window.VSP_TOKEN || localStorage.getItem('vsp_token') || '';

  function authHeaders() {
    return TOKEN ? { 'Authorization': 'Bearer ' + TOKEN } : {};
  }

  // ── Status colors ────────────────────────────────────────────
  const STATUS_STYLES = {
    pending:  { bg: 'rgba(148,163,184,.15)', fg: '#94a3b8', label: 'pending'  },
    creating: { bg: 'rgba(6,182,212,.15)',   fg: '#06b6d4', label: 'creating' },
    created:  { bg: 'rgba(59,130,246,.15)',  fg: '#3b82f6', label: 'open'     },
    merged:   { bg: 'rgba(34,197,94,.15)',   fg: '#22c55e', label: 'merged ✓' },
    closed:   { bg: 'rgba(148,163,184,.15)', fg: '#94a3b8', label: 'closed'   },
    conflict: { bg: 'rgba(245,158,11,.15)',  fg: '#f59e0b', label: 'conflict ⚠' },
    failed:   { bg: 'rgba(239,68,68,.15)',   fg: '#ef4444', label: 'failed ✗'  },
  };

  // ── Fetch repos for current user ─────────────────────────────
  async function fetchRepos() {
    // Repos are a sub-resource. List endpoint returns enabled repos for tenant.
    try {
      const r = await fetch(API_BASE + '/api/v1/autofix/repo/list', { headers: authHeaders() });
      if (r.ok) {
        const d = await r.json();
        return d.repos || [];
      }
    } catch (_) {}
    return [];
  }

  // ── Render "Create PR" panel inside autofix modal ────────────
  async function renderH3SCreatePR(container, opts) {
    if (!container || !opts || !opts.cacheKey) return;

    const wrapper = document.createElement('div');
    wrapper.setAttribute('data-h3s-panel', '1');
    wrapper.style.cssText =
      'margin-top:14px;padding:12px;background:rgba(15,23,42,.5);' +
      'border:1px solid rgba(148,163,184,.15);border-radius:8px;font-size:11px';
    wrapper.innerHTML =
      '<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">' +
      'H3.S Auto-PR</div>' +
      '<div data-h3s-body>⟳ Loading repos…</div>';
    container.appendChild(wrapper);
    const body = wrapper.querySelector('[data-h3s-body]');

    const repos = await fetchRepos();
    if (repos.length === 0) {
      body.innerHTML =
        '<div style="color:#f59e0b;font-size:10px">' +
        '⚠ No repository configured. Admin must register a repo via ' +
        '<code>POST /api/v1/autofix/repo/register</code></div>';
      return;
    }

    // Repo selector
    const opts_html = repos.map(function (r) {
      return '<option value="' + escapeAttr(r.id) + '">' +
        escapeHtml(r.nickname || r.repo_owner + '/' + r.repo_name) +
        ' <span style="color:#64748b">(' + escapeHtml(r.platform) + ')</span></option>';
    }).join('');

    body.innerHTML =
      '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">' +
        '<label style="font-size:10px;color:#94a3b8">Target repo:</label>' +
        '<select data-h3s-repo style="flex:1;background:rgba(0,0,0,.3);border:1px solid rgba(148,163,184,.2);' +
        'color:#e2e8f0;padding:4px 6px;border-radius:4px;font-size:11px">' + opts_html + '</select>' +
      '</div>' +
      '<button data-h3s-create style="width:100%;padding:8px 12px;background:rgba(34,197,94,.15);' +
      'border:1px solid #22c55e;color:#22c55e;border-radius:6px;font-weight:600;cursor:pointer;font-size:12px">' +
      '→ Create Pull Request</button>' +
      '<div data-h3s-result style="margin-top:8px"></div>';

    const select = body.querySelector('[data-h3s-repo]');
    const btn    = body.querySelector('[data-h3s-create]');
    const result = body.querySelector('[data-h3s-result]');

    btn.addEventListener('click', async function () {
      const repoConfigID = select.value;
      btn.disabled = true;
      btn.textContent = '⟳ Creating PR (clone + push + API)…';
      result.innerHTML = '';

      try {
        const r = await fetch(API_BASE + '/api/v1/autofix/pr/create', {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
          body: JSON.stringify({
            cache_key:      opts.cacheKey,
            finding_id:     opts.findingID || '',
            repo_config_id: repoConfigID,
          }),
        });

        if (r.status === 201) {
          const d = await r.json();
          renderPRSuccess(result, d);
          btn.style.display = 'none';
        } else {
          const d = await r.json().catch(function () { return { error: 'HTTP ' + r.status }; });
          renderPRError(result, d.error || 'Unknown error');
          btn.disabled = false;
          btn.textContent = '↻ Retry';
        }
      } catch (e) {
        renderPRError(result, e.message);
        btn.disabled = false;
        btn.textContent = '↻ Retry';
      }
    });
  }

  function renderPRSuccess(el, d) {
    const url = d.pr_url || '#';
    el.innerHTML =
      '<div style="padding:10px;background:rgba(34,197,94,.1);border-radius:6px;border:1px solid rgba(34,197,94,.3)">' +
        '<div style="color:#22c55e;font-weight:600;font-size:12px;margin-bottom:4px">✓ PR created successfully</div>' +
        '<div style="font-size:11px;color:#e2e8f0">PR <strong>#' + d.pr_number + '</strong> · ' +
          'branch <code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px">' +
          escapeHtml(d.branch_name || 'auto') + '</code></div>' +
        '<a href="' + escapeAttr(url) + '" target="_blank" rel="noopener noreferrer" ' +
        'style="display:inline-block;margin-top:6px;color:#06b6d4;text-decoration:none;font-size:11px">' +
        '→ Open PR on GitHub Enterprise</a>' +
      '</div>';
  }

  function renderPRError(el, msg) {
    el.innerHTML =
      '<div style="padding:10px;background:rgba(239,68,68,.1);border-radius:6px;border:1px solid rgba(239,68,68,.3)">' +
        '<div style="color:#ef4444;font-weight:600;font-size:11px">✗ PR creation failed</div>' +
        '<div style="margin-top:4px;color:#cbd5e1;font-size:10px;font-family:monospace">' + escapeHtml(msg) + '</div>' +
      '</div>';
  }

  // ── Render PR list (admin panel) ─────────────────────────────
  async function renderH3SPRList(container, opts) {
    opts = opts || {};
    if (!container) return;
    container.innerHTML = '<div style="color:#94a3b8;font-size:11px">⟳ Loading PRs…</div>';

    const params = new URLSearchParams();
    if (opts.status) params.set('status', opts.status);
    params.set('limit', String(opts.limit || 50));

    try {
      const r = await fetch(API_BASE + '/api/v1/autofix/pr/list?' + params.toString(),
        { headers: authHeaders() });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const d = await r.json();
      container.innerHTML = buildListHTML(d);
    } catch (e) {
      container.innerHTML = '<div style="color:#ef4444;font-size:11px">✗ ' + escapeHtml(e.message) + '</div>';
    }
  }

  function buildListHTML(d) {
    const sm = d.summary_30d || {};
    const stats =
      '<div style="display:grid;grid-template-columns:repeat(6,1fr);gap:6px;margin-bottom:14px">' +
        statCard('Pending', sm.pending || 0, '#94a3b8') +
        statCard('Open',    sm.created || 0, '#3b82f6') +
        statCard('Merged',  sm.merged  || 0, '#22c55e') +
        statCard('Closed',  sm.closed  || 0, '#94a3b8') +
        statCard('Conflict',sm.conflict|| 0, '#f59e0b') +
        statCard('Failed',  sm.failed  || 0, '#ef4444') +
      '</div>';

    if (!d.prs || d.prs.length === 0) {
      return stats + '<div style="color:#64748b;text-align:center;padding:20px;font-size:11px">' +
        'No PRs yet. Trigger a scan or click "Apply fix" on a finding.</div>';
    }

    const rows = d.prs.map(function (p) {
      const st = STATUS_STYLES[p.status] || STATUS_STYLES.pending;
      const trigger = p.trigger_type === 'sla'
        ? '<span style="color:#a855f7;font-size:9px">⏱ SLA</span>'
        : '<span style="color:#06b6d4;font-size:9px">👤 manual</span>';
      const prLink = p.pr_url
        ? '<a href="' + escapeAttr(p.pr_url) + '" target="_blank" rel="noopener" ' +
          'style="color:#06b6d4;text-decoration:none">#' + p.pr_number + '</a>'
        : '<span style="color:#64748b">—</span>';
      const score = p.validation_score
        ? '<span style="color:' + (p.validation_score >= 90 ? '#22c55e' :
                                   p.validation_score >= 70 ? '#06b6d4' : '#f59e0b') +
          ';font-weight:600">' + p.validation_score + '</span>'
        : '<span style="color:#64748b">—</span>';

      return '<tr style="border-bottom:1px solid rgba(148,163,184,.08)">' +
        '<td style="padding:6px 4px">' + prLink + '</td>' +
        '<td style="padding:6px 4px">' +
          '<span style="padding:2px 6px;border-radius:4px;background:' + st.bg +
          ';color:' + st.fg + ';font-size:10px;font-weight:600">' + st.label + '</span>' +
        '</td>' +
        '<td style="padding:6px 4px;font-family:monospace;font-size:10px;color:#cbd5e1">' +
          escapeHtml((p.rule_id || '').substring(0, 30)) + '</td>' +
        '<td style="padding:6px 4px;font-size:10px;color:#94a3b8">' +
          escapeHtml((p.severity || '').toUpperCase()) + '</td>' +
        '<td style="padding:6px 4px">' + score + '</td>' +
        '<td style="padding:6px 4px">' + trigger + '</td>' +
        '<td style="padding:6px 4px;color:#64748b;font-size:10px">' +
          relativeTime(p.created_at) + '</td>' +
        '</tr>';
    }).join('');

    return stats +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:11px">' +
        '<thead><tr style="border-bottom:1px solid rgba(148,163,184,.2);color:#94a3b8;font-size:10px;text-transform:uppercase">' +
          '<th style="text-align:left;padding:6px 4px">PR</th>' +
          '<th style="text-align:left;padding:6px 4px">Status</th>' +
          '<th style="text-align:left;padding:6px 4px">Rule</th>' +
          '<th style="text-align:left;padding:6px 4px">Sev</th>' +
          '<th style="text-align:left;padding:6px 4px">Score</th>' +
          '<th style="text-align:left;padding:6px 4px">Trigger</th>' +
          '<th style="text-align:left;padding:6px 4px">When</th>' +
        '</tr></thead><tbody>' + rows + '</tbody>' +
      '</table></div>';
  }

  function statCard(label, value, color) {
    return '<div style="background:rgba(15,23,42,.5);border:1px solid rgba(148,163,184,.15);' +
      'border-radius:6px;padding:6px 8px;text-align:center">' +
        '<div style="font-size:16px;font-weight:700;color:' + color + ';line-height:1.1">' + value + '</div>' +
        '<div style="font-size:9px;color:#94a3b8;letter-spacing:.3px;text-transform:uppercase">' + label + '</div>' +
      '</div>';
  }

  // ── Helpers ──────────────────────────────────────────────────
  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
    });
  }
  function escapeAttr(s) { return escapeHtml(s); }

  function relativeTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return Math.floor(diff) + 's';
    if (diff < 3600) return Math.floor(diff / 60) + 'm';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h';
    return Math.floor(diff / 86400) + 'd';
  }

  // Export
  window.H3S = {
    renderCreatePR: renderH3SCreatePR,
    renderPRList:   renderH3SPRList,
    fetchRepos:     fetchRepos,
  };

  // Auto-attach to existing autofix modal events
  document.addEventListener('vsp:autofix-modal-open', function (e) {
    if (e && e.detail && e.detail.cacheKey && e.detail.container) {
      renderH3SCreatePR(e.detail.container, {
        cacheKey:  e.detail.cacheKey,
        findingID: e.detail.findingID,
      });
    }
  });

})();
