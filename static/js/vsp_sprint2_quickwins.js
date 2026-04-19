/* VSP Sprint 2 Quick-Wins Patch Pack v1.0
 * Items: #1 CSRF bug box, #2 DAST banner, #3 Health inconsistency,
 *        #9 API key never-expiry, #10 IP 0.0.0.0/0 default
 * Load sau vsp_upgrade_v100.js trong static/index.html.
 */
(function vspSprint2QuickWins() {
'use strict';

// ─── #1 — Hide CSRF "BUG" box ──────────────────────────────────────────────
(function fixCsrfBugExposure() {
  var sel = '[data-internal-bug], .internal-bug-box, #csrf-bug-note';
  document.querySelectorAll(sel).forEach(function (el) { el.remove(); });
  var mo = new MutationObserver(function (muts) {
    muts.forEach(function (m) {
      m.addedNodes.forEach(function (n) {
        if (n.nodeType !== 1) return;
        if (n.matches && n.matches(sel)) {
          console.debug('[VSP internal] suppressed internal-bug note');
          n.remove();
        }
        if (n.querySelectorAll) {
          n.querySelectorAll(sel).forEach(function (c) { c.remove(); });
        }
      });
    });
  });
  mo.observe(document.body, { childList: true, subtree: true });
})();

// ─── #2 — DAST empty state ─────────────────────────────────────────────────
(function fixDastEmptyState() {
  function render() {
    var banner = document.querySelector('.dast-warning-banner, [data-dast-warn]');
    if (!banner) return;
    banner.outerHTML =
      '<div class="empty-state-card" data-mode="dast" ' +
      'style="padding:20px;border:1px dashed var(--t3);border-radius:8px;' +
      'text-align:center;color:var(--t2);font-size:13px">' +
      '<div style="font-size:24px;margin-bottom:8px;opacity:.5">&#8857;</div>' +
      '<div style="font-weight:500;color:var(--t1);margin-bottom:4px">DAST not configured</div>' +
      '<div style="margin-bottom:12px">Dynamic Application Security Testing needs a target URL to run.</div>' +
      '<button class="btn btn-primary btn-sm" ' +
      'onclick="showPanel(\'settings\',null);setTimeout(function(){var t=document.getElementById(\'dast-target\');t&&t.focus();},200)">' +
      'Configure target URL &rarr;</button></div>';
  }
  render();
  window.addEventListener('vsp:panel-loaded', render);
})();

// ─── #3 — Scheduler health real status ─────────────────────────────────────
(function fixSchedulerHealth() {
  async function computeRealStatus() {
    var tok = window.TOKEN || localStorage.getItem('vsp_token') || '';
    if (!tok) return { level: 'unknown', text: 'Awaiting auth' };
    try {
      var r = await fetch('/api/v1/schedules', {
        headers: { Authorization: 'Bearer ' + tok }
      });
      if (!r.ok) return { level: 'red', text: 'HTTP ' + r.status };
      var data = await r.json();
      var scheds = data.schedules || [];
      var active = scheds.filter(function (s) {
        return s.enabled && s.next_run && new Date(s.next_run) > new Date();
      });
      if (active.length === 0) return { level: 'amber', text: 'No active schedules' };
      return { level: 'green', text: active.length + ' active' };
    } catch (e) {
      return { level: 'red', text: 'Connection error' };
    }
  }
  async function patchHealthCard() {
    var card = document.querySelector('[data-health-component="scheduler"]');
    if (!card) return;
    var st = await computeRealStatus();
    var colors = {
      green: 'var(--green)', amber: 'var(--amber)',
      red: 'var(--red)', unknown: 'var(--t3)'
    };
    var dot = card.querySelector('.status-dot');
    var txt = card.querySelector('.status-text');
    if (dot) dot.style.background = colors[st.level];
    if (txt) txt.textContent = st.text;
  }
  patchHealthCard();
  setInterval(patchHealthCard, 30000);
})();

// ─── #9 — API key max 1 year expiry ────────────────────────────────────────
(function fixApiKeyExpiry() {
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form.matches('[data-form="api-key-create"]')) return;
    var exp = form.querySelector('[name="expires_at"]');
    if (!exp) return;
    if (!exp.value || exp.value === 'never') {
      e.preventDefault();
      alert('API keys must have an expiration date. Maximum 1 year.');
      exp.focus();
      return;
    }
    var max = new Date();
    max.setFullYear(max.getFullYear() + 1);
    if (new Date(exp.value) > max) {
      e.preventDefault();
      alert('Expiration cannot exceed 1 year from today.');
      exp.focus();
    }
  }, true);
  document.querySelectorAll('select[name="expires_at"] option[value="never"]')
    .forEach(function (o) { o.remove(); });
})();

// ─── #10 — Block default 0.0.0.0/0 ─────────────────────────────────────────
(function fixOpenIpRange() {
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form.matches('[data-form="ip-allowlist"], [data-form="api-key-create"]')) return;
    var cidr = form.querySelector('[name="allowed_cidr"], [name="ip_range"]');
    if (!cidr) return;
    var v = (cidr.value || '').trim();
    if (!v) {
      e.preventDefault();
      alert('IP allowlist cannot be empty. Specify a CIDR (e.g. 10.0.0.0/8).');
      cidr.focus();
      return;
    }
    if (v === '0.0.0.0/0' || v === '::/0') {
      var ok = confirm('WARNING: 0.0.0.0/0 allows connections from anywhere on the internet. Are you sure?');
      if (!ok) { e.preventDefault(); cidr.focus(); return; }
      var c = prompt('Type YES to confirm 0.0.0.0/0:');
      if (c !== 'YES') { e.preventDefault(); cidr.focus(); }
    }
  }, true);
})();

console.log('[VSP Sprint 2] quick-wins patch loaded — items #1,#2,#3,#9,#10 fixed');
})();
