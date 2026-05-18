/* VSP_F1_BULK_SELECT_BEGIN ─────────────────────────────────────────────────
 * VSP Bulk Select Hub — F1 (Sprint 1, patch 1/8)
 *
 * Adds bulk-select to the Findings (vuln_mgmt) panel:
 *   • Checkbox column prepended to Top CVEs table
 *   • Header select-all (only filtered/visible rows)
 *   • Floating bottom action bar: Resolve / Suppress / Assign / POA&M
 *   • Optimistic UI with 8s undo window (Ctrl+Z)
 *
 * Design: additive monkey-patch on top of existing core + Block 1 (E5 EPSS/KEV).
 * MUST run AFTER core renderCVEs and AFTER Block 1's hook installs, so it sees
 * the EPSS/KEV columns and keeps colspans consistent.
 *
 * Reuses Block 2 toast (window._vspUNI.toast) when available, else self-fallback.
 * Reuses Block 2 modal (window._vspUNI.showModal) for assign-owner picker only.
 *
 * Idempotency: window.__VSP_BULK_F1__ guard.
 * Pattern follows the existing 3 inline blocks (E5, UNI-POLISH, CROSS-LINK-V3).
 * VSP_F1_BULK_SELECT_END ─────────────────────────────────────────────────── */
(function () {
  'use strict';
  if (window.__VSP_BULK_F1__) return;
  window.__VSP_BULK_F1__ = true;

  // ── Helpers ──────────────────────────────────────────────────────────
  function $id(id) { return document.getElementById(id); }
  function $$(s, ctx) { return Array.from((ctx || document).querySelectorAll(s)); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }
  function authFetch(url, opts) {
    return (window.vspAuthFetch || window.fetch)(url, opts || {});
  }
  // VSP_F1_CSRF_PATCHED — read vsp_csrf cookie + add to headers (double-submit pattern)
  function vspCsrfHeaders(base) {
    base = base || {};
    try {
      var m = document.cookie.match(/(?:^|;\s*)vsp_csrf=([^;]+)/);
      if (m && m[1]) base['X-CSRF-Token'] = decodeURIComponent(m[1]);
    } catch (e) { /* malformed cookie — let request fail naturally */ }
    return base;
  }

  // Use Block 2 toast if available, else minimal fallback
  function toast(msg, type) {
    if (window._vspUNI && typeof window._vspUNI.toast === 'function') {
      return window._vspUNI.toast(msg, type);
    }
    // Fallback — append a minimal toast (degrades gracefully)
    var c = $id('vsp-bulk-toast-fallback');
    if (!c) {
      c = document.createElement('div');
      c.id = 'vsp-bulk-toast-fallback';
      c.style.cssText = 'position:fixed;bottom:80px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;pointer-events:none';
      document.body.appendChild(c);
    }
    var color = ({ success: '#10b981', error: '#ef4444', warn: '#f59e0b' })[type] || '#3b82f6';
    var t = document.createElement('div');
    t.style.cssText = 'pointer-events:auto;background:rgba(0,0,0,.85);border-left:3px solid ' + color +
                      ';padding:8px 12px;border-radius:4px;font-size:11px;color:#e5e7eb;max-width:320px;box-shadow:0 4px 12px rgba(0,0,0,.4)';
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(function () { t.remove(); }, 3500);
  }

  // ── Inject CSS once ──────────────────────────────────────────────────
  function injectCSS() {
    if ($id('vsp-bulk-f1-css')) return;
    var s = document.createElement('style');
    s.id = 'vsp-bulk-f1-css';
    s.textContent = [
      /* checkbox styling — minimal, theme-aware */
      '.vsp-cb{appearance:none;-webkit-appearance:none;width:14px;height:14px;border:1.5px solid var(--t4,#52525b);border-radius:3px;background:var(--bg,#0a0a0a);cursor:pointer;position:relative;flex-shrink:0;transition:border-color .12s,background .12s;vertical-align:middle}',
      '.vsp-cb:hover{border-color:var(--blue,#3b82f6)}',
      '.vsp-cb:checked{background:var(--blue,#3b82f6);border-color:var(--blue,#3b82f6)}',
      '.vsp-cb:checked::after{content:"";position:absolute;left:3px;top:0px;width:5px;height:9px;border:solid #fff;border-width:0 1.5px 1.5px 0;transform:rotate(45deg)}',
      /* checkbox cell sizing — narrow column */
      '.vsp-cb-cell{width:24px;padding:7px 4px 7px 8px !important;text-align:center}',
      '.vsp-cb-th{width:24px;padding:6px 4px 6px 8px !important}',
      'tr.vsp-row-selected td{background:rgba(59,130,246,.06) !important}',
      /* floating action bar */
      '#vsp-bulk-bar{position:fixed;left:50%;bottom:-100px;transform:translateX(-50%);background:var(--bg2,#1c1c1c);border:1px solid var(--border2,#3f3f46);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.5);padding:10px 14px;display:flex;align-items:center;gap:10px;z-index:150;transition:bottom .25s cubic-bezier(.2,.9,.3,1.2);font-size:11px;backdrop-filter:blur(12px)}',
      '#vsp-bulk-bar.show{bottom:20px}',
      '#vsp-bulk-bar .vsp-bulk-count{font-family:var(--font-mono,monospace);font-weight:700;color:var(--blue,#3b82f6);min-width:24px;text-align:right}',
      '#vsp-bulk-bar .vsp-bulk-sep{color:var(--t4,#52525b);margin:0 4px}',
      '#vsp-bulk-bar .vsp-bulk-btn{background:var(--surface,#171717);border:1px solid var(--border,#27272a);color:var(--t1,#e5e7eb);padding:5px 10px;border-radius:5px;font-size:11px;cursor:pointer;font-family:inherit;transition:background .12s,border-color .12s}',
      '#vsp-bulk-bar .vsp-bulk-btn:hover{background:var(--bg,#0a0a0a);border-color:var(--blue,#3b82f6)}',
      '#vsp-bulk-bar .vsp-bulk-btn-pri{background:rgba(59,130,246,.15);border-color:var(--blue,#3b82f6);color:var(--blue,#3b82f6)}',
      '#vsp-bulk-bar .vsp-bulk-btn-pri:hover{background:rgba(59,130,246,.25)}',
      /* undo banner */
      '#vsp-bulk-undo{position:fixed;left:50%;bottom:80px;transform:translateX(-50%);background:var(--surface,#171717);border:1px solid var(--border2,#3f3f46);border-radius:8px;padding:8px 14px;display:none;align-items:center;gap:10px;z-index:151;font-size:11px;box-shadow:0 4px 16px rgba(0,0,0,.4);color:var(--t1,#e5e7eb)}',
      '#vsp-bulk-undo.show{display:flex;animation:vsp-bulk-undo-in .2s ease-out}',
      '@keyframes vsp-bulk-undo-in{from{opacity:0;transform:translate(-50%,8px)}to{opacity:1;transform:translate(-50%,0)}}',
      '#vsp-bulk-undo .vsp-bulk-bar-fill{width:60px;height:3px;background:var(--t4,#52525b);border-radius:2px;overflow:hidden;position:relative}',
      '#vsp-bulk-undo .vsp-bulk-bar-fill::after{content:"";position:absolute;inset:0;background:var(--blue,#3b82f6);transform-origin:left;animation:vsp-bulk-shrink 8s linear forwards}',
      '@keyframes vsp-bulk-shrink{from{transform:scaleX(1)}to{transform:scaleX(0)}}',
      /* assign menu */
      '.vsp-bulk-menu{position:absolute;background:var(--bg2,#1c1c1c);border:1px solid var(--border2,#3f3f46);border-radius:8px;padding:4px;min-width:160px;box-shadow:0 8px 24px rgba(0,0,0,.4);display:none;z-index:200}',
      '.vsp-bulk-menu.show{display:block}',
      '.vsp-bulk-menu button{display:block;width:100%;text-align:left;padding:6px 10px;background:none;border:none;color:var(--t1,#e5e7eb);font-size:11px;cursor:pointer;border-radius:4px;font-family:inherit}',
      '.vsp-bulk-menu button:hover{background:var(--surface,#171717)}',
      /* mobile */
      '@media(max-width:640px){#vsp-bulk-bar{flex-wrap:wrap;justify-content:center;width:calc(100% - 24px);left:12px;transform:none}#vsp-bulk-bar.show{bottom:12px}}'
    ].join('\n');
    document.head.appendChild(s);
  }

  // ── Inject DOM (action bar + undo + menu) ────────────────────────────
  function injectDOM() {
    if ($id('vsp-bulk-bar')) return;
    var bar = document.createElement('div');
    bar.id = 'vsp-bulk-bar';
    bar.setAttribute('role', 'toolbar');
    bar.setAttribute('aria-label', 'Bulk actions');
    bar.innerHTML =
      '<span class="vsp-bulk-count" id="vsp-bulk-count">0</span>' +
      '<span style="color:var(--t3,#a1a1aa)">selected</span>' +
      '<span class="vsp-bulk-sep">·</span>' +
      '<button class="vsp-bulk-btn" data-act="resolve"  title="Mark as resolved">✓ Resolve</button>' +
      '<button class="vsp-bulk-btn" data-act="suppress" title="Suppress (won&#39;t show until rediscovered)">⊘ Suppress</button>' +
      '<button class="vsp-bulk-btn" data-act="assign"   title="Assign owner">👤 Assign ▾</button>' +
      '<button class="vsp-bulk-btn vsp-bulk-btn-pri" data-act="create_poam" title="Create POA&amp;M item">📋 POA&amp;M</button>' +
      '<span class="vsp-bulk-sep">·</span>' +
      '<button class="vsp-bulk-btn" data-act="clear" title="Clear selection (Esc)">✕</button>';
    document.body.appendChild(bar);

    var menu = document.createElement('div');
    menu.id = 'vsp-bulk-assign-menu';
    menu.className = 'vsp-bulk-menu';
    menu.setAttribute('role', 'menu');
    menu.innerHTML =
      '<button data-owner="soc-l1">SOC L1</button>' +
      '<button data-owner="soc-l2">SOC L2</button>' +
      '<button data-owner="appsec">AppSec</button>' +
      '<button data-owner="platform">Platform team</button>' +
      '<button data-owner="me">Assign to me</button>';
    document.body.appendChild(menu);

    var undo = document.createElement('div');
    undo.id = 'vsp-bulk-undo';
    undo.setAttribute('role', 'status');
    undo.setAttribute('aria-live', 'polite');
    undo.innerHTML =
      '<span id="vsp-bulk-undo-msg">Action done</span>' +
      '<div class="vsp-bulk-bar-fill" aria-hidden="true"></div>' +
      '<button class="vsp-bulk-btn" id="vsp-bulk-undo-btn">Undo (Ctrl+Z)</button>';
    document.body.appendChild(undo);

    // Wire button clicks (delegated)
    bar.addEventListener('click', function (e) {
      var btn = e.target.closest('button');
      if (!btn) return;
      var act = btn.dataset.act;
      if (act === 'clear') Sel.clear();
      else if (act === 'assign') Sel.openAssign(e);
      else Sel.act(act);
    });

    menu.addEventListener('click', function (e) {
      var btn = e.target.closest('button');
      if (!btn) return;
      var owner = btn.dataset.owner;
      menu.classList.remove('show');
      Sel.act('assign', { owner: owner });
    });

    $id('vsp-bulk-undo-btn').addEventListener('click', Sel.undo);
  }

  // ── Selection store ──────────────────────────────────────────────────
  var Sel = {
    _set: new Set(),
    _last: null,    // { action, ids, snapshot, undoToken }
    _timer: null,

    has: function (id) { return this._set.has(id); },
    size: function () { return this._set.size; },

    toggle: function (id, on) {
      if (on === undefined) on = !this._set.has(id);
      if (on) this._set.add(id); else this._set.delete(id);
      this.refresh();
    },

    toggleAll: function (on) {
      var ids = $$('tr[data-vsp-cve]').map(function (r) { return r.dataset.vspCve; });
      var set = this._set;
      ids.forEach(function (id) { if (on) set.add(id); else set.delete(id); });
      this.refresh();
    },

    clear: function () {
      this._set.clear();
      this.refresh();
    },

    refresh: function () {
      var bar = $id('vsp-bulk-bar');
      var n = this._set.size;
      if (!bar) return;
      $id('vsp-bulk-count').textContent = n;
      bar.classList.toggle('show', n > 0);

      var set = this._set;
      $$('tr[data-vsp-cve]').forEach(function (tr) {
        var on = set.has(tr.dataset.vspCve);
        tr.classList.toggle('vsp-row-selected', on);
        var cb = tr.querySelector('input.vsp-cb');
        if (cb) cb.checked = on;
      });

      var hcb = $id('vsp-bulk-cb-all');
      if (hcb) {
        var visible = $$('tr[data-vsp-cve]').map(function (r) { return r.dataset.vspCve; });
        var allOn = visible.length > 0 && visible.every(function (id) { return set.has(id); });
        var anyOn = visible.some(function (id) { return set.has(id); });
        hcb.checked = allOn;
        hcb.indeterminate = !allOn && anyOn;
      }
    },

    act: function (action, metadata) {
      var ids = Array.from(this._set);
      if (!ids.length) return;
      metadata = metadata || {};

      // Optimistic remove for resolve/suppress
      var willRemove = (action === 'resolve' || action === 'suppress');
      var snapshot = (Array.isArray(window._cveData) ? window._cveData.slice() : null);
      if (willRemove && snapshot) {
        var setRef = this._set;
        window._cveData = window._cveData.filter(function (c) { return !setRef.has(c.cve); });
        if (typeof window.filterCVEs === 'function') window.filterCVEs();
      }

      var self = this;
      authFetch('/api/v1/vulns/bulk', {
        method: 'POST',
        credentials: 'include',
        headers: vspCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ action: action, cve_ids: ids, metadata: metadata })
      }).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      }).then(function (data) {
        var n = data.affected || ids.length;
        self._last = { action: action, ids: ids, snapshot: snapshot, undoToken: data.undo_token };
        toast(self._msgFor(action, n), 'success');
        self._showUndo(self._msgFor(action, n));
        self.clear();
      }).catch(function (e) {
        // Rollback optimistic remove
        if (willRemove && snapshot) {
          window._cveData = snapshot;
          if (typeof window.filterCVEs === 'function') window.filterCVEs();
        }
        toast('Bulk action failed: ' + (e.message || e), 'error');
      });
    },

    _msgFor: function (action, n) {
      var verb = ({
        resolve: 'Resolved',
        suppress: 'Suppressed',
        assign: 'Assigned',
        create_poam: 'POA&M created for'
      })[action] || 'Updated';
      return verb + ' ' + n + ' CVE' + (n === 1 ? '' : 's');
    },

    _showUndo: function (msg) {
      var u = $id('vsp-bulk-undo');
      if (!u) return;
      $id('vsp-bulk-undo-msg').textContent = msg;
      u.classList.remove('show');
      // restart shrink animation
      void u.offsetWidth;
      u.classList.add('show');
      if (this._timer) clearTimeout(this._timer);
      var self = this;
      this._timer = setTimeout(function () {
        u.classList.remove('show');
        self._last = null;
      }, 8000);
    },

    undo: function () {
      var last = Sel._last;
      if (!last) return;
      var u = $id('vsp-bulk-undo');
      if (u) u.classList.remove('show');
      if (Sel._timer) { clearTimeout(Sel._timer); Sel._timer = null; }

      // Restore client state immediately
      if (last.snapshot) {
        window._cveData = last.snapshot;
        if (typeof window.filterCVEs === 'function') window.filterCVEs();
      }

      // Best-effort backend notify
      authFetch('/api/v1/vulns/bulk/undo', {
        method: 'POST',
        credentials: 'include',
        headers: vspCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ undo_token: last.undoToken })
      }).catch(function () { /* ignore */ });

      toast('Undone', 'success');
      Sel._last = null;
    },

    openAssign: function (ev) {
      var menu = $id('vsp-bulk-assign-menu');
      if (!menu) return;
      var rect = (ev.target.closest('button') || ev.target).getBoundingClientRect();
      menu.style.left = rect.left + 'px';
      menu.style.top = (rect.top - 200) + 'px';
      menu.classList.add('show');
      // Close on next outside click
      setTimeout(function () {
        document.addEventListener('click', function closer(e) {
          if (!menu.contains(e.target)) {
            menu.classList.remove('show');
            document.removeEventListener('click', closer);
          }
        });
      }, 0);
    }
  };

  // Expose for debugging / external tooling
  window.VSPSel = Sel;

  // ── Hook filterCVEs (CHAINED — runs after E5/UNI/Cross hooks) ───────
  function hookFilterCVEs() {
    if (typeof window.filterCVEs !== 'function') {
      // Core not ready yet, retry
      setTimeout(hookFilterCVEs, 250);
      return;
    }
    if (window.__VSP_BULK_F1_HOOKED__) return;
    window.__VSP_BULK_F1_HOOKED__ = true;

    var _orig = window.filterCVEs;
    window.filterCVEs = function () {
      var ret = _orig.apply(this, arguments);
      // Defer DOM mutation past Block 1's own setTimeout(50)
      setTimeout(injectCheckboxes, 80);
      return ret;
    };
    // Run once for current state
    setTimeout(injectCheckboxes, 80);
    (window.VSP_DEBUG && console.log('[VSP-BULK-F1] filterCVEs hooked'));
  }

  // ── Inject checkbox column into rendered rows + header ──────────────
  function injectCheckboxes() {
    var tbody = $id('cve-body');
    if (!tbody) return;

    // Header: prepend checkbox th once
    var thead = tbody.parentElement && tbody.parentElement.querySelector('thead tr');
    if (thead && !thead.querySelector('.vsp-cb-th')) {
      var th = document.createElement('th');
      th.className = 'vsp-cb-th';
      th.innerHTML = '<input type="checkbox" class="vsp-cb" id="vsp-bulk-cb-all" aria-label="Select all visible">';
      thead.insertBefore(th, thead.firstChild);
      var hcb = $id('vsp-bulk-cb-all');
      hcb.addEventListener('change', function () { Sel.toggleAll(this.checked); });
    }

    // Rows: handle empty/loading rows (colspan) — bump colspan by 1
    var emptyTds = tbody.querySelectorAll('td[colspan]');
    emptyTds.forEach(function (td) {
      // Mark to avoid double-bump on re-render
      if (td.dataset.vspBulkBumped) return;
      var cs = parseInt(td.getAttribute('colspan'), 10) || 1;
      td.setAttribute('colspan', String(cs + 1));
      td.dataset.vspBulkBumped = '1';
    });

    // Each data row: prepend a checkbox cell
    var rows = tbody.querySelectorAll('tr');
    rows.forEach(function (tr) {
      // Skip empty/loading rows
      if (tr.querySelector('td[colspan]')) return;
      // Skip if already injected
      if (tr.querySelector('.vsp-cb-cell')) return;

      // Extract CVE id from first data cell (text up to whitespace, strips "fix ✓")
      var firstTd = tr.querySelector('td');
      if (!firstTd) return;
      var cveText = (firstTd.textContent || '').trim().split(/\s+/)[0];
      if (!/^CVE-\d{4}-\d+/i.test(cveText)) return;

      tr.dataset.vspCve = cveText;

      var td = document.createElement('td');
      td.className = 'vsp-cb-cell';
      td.innerHTML = '<input name="select" type="checkbox" class="vsp-cb" aria-label="Select ' + esc(cveText) + '">';
      // Stop click bubble so existing row click (openCVEDetail) doesn't fire
      td.addEventListener('click', function (e) { e.stopPropagation(); });
      var cb = td.querySelector('input');
      cb.addEventListener('change', function () { Sel.toggle(cveText, this.checked); });
      // Reflect current selection state
      if (Sel.has(cveText)) {
        cb.checked = true;
        tr.classList.add('vsp-row-selected');
      }

      tr.insertBefore(td, tr.firstChild);
    });

    // Refresh header indeterminate state
    Sel.refresh();
  }

  // ── Keyboard shortcuts ──────────────────────────────────────────────
  document.addEventListener('keydown', function (e) {
    var meta = e.ctrlKey || e.metaKey;
    if (meta && (e.key === 'z' || e.key === 'Z') && Sel._last) {
      e.preventDefault();
      Sel.undo();
    } else if (e.key === 'Escape' && Sel.size() > 0) {
      Sel.clear();
    }
  });

  // ── Init ─────────────────────────────────────────────────────────────
  function init() {
    // Only run on Findings panel
    if (!/vuln_mgmt/.test(location.pathname)) return;
    injectCSS();
    injectDOM();
    hookFilterCVEs();
    (window.VSP_DEBUG && console.log('[VSP-BULK-F1] Active'));
  }

  if (document.readyState !== 'loading') {
    setTimeout(init, 850); // run after Block 2 (init at 800) so toast is ready
  } else {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(init, 850);
    });
  }

  // Re-init poll for late renders (matches existing block pattern)
  var pollCount = 0;
  var poll = setInterval(function () {
    if (window.__VSP_BULK_F1_HOOKED__) {
      injectCheckboxes(); // ensure rows from late re-renders get checkboxes
    } else {
      hookFilterCVEs();
    }
    if (++pollCount > 5) clearInterval(poll);
  }, 1500);
})();
