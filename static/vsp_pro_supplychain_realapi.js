/* vsp_pro_supplychain_realapi.js
 * ─────────────────────────────────────────────────────────────────────────
 * VSP PRO — Supply Chain real-API patch
 *
 * Drop-in companion for vsp_pro_100.js. Replaces the Supply Chain mock
 * fetchers with calls to the cosign-api microservice on :8091, mirroring
 * the pattern used by vsp_pro_cwpp_realapi.js for the Trivy microservice.
 *
 * Endpoints consumed (cmd/cosign-api/main.go):
 *   POST /sign         — sign an image
 *   POST /verify       — verify a signature
 *   POST /attest       — SLSA provenance attestation
 *   GET  /signatures   — list every signature this service has produced
 *   POST /sbom/diff    — diff two CycloneDX/SPDX JSON SBOMs
 *
 * Load order in vsp-ui.html:
 *   <script src="/panels/vsp_pro_100.js"></script>
 *   <script src="/panels/vsp_pro_cwpp_realapi.js"></script>
 *   <script src="/panels/vsp_pro_supplychain_realapi.js"></script>   ← here
 *
 * No build step. No external deps. Pure DOM + fetch.
 * ───────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  // ── config ──────────────────────────────────────────────────────────────
  const API_BASE  = (window.VSP_COSIGN_API || 'http://127.0.0.1:8091').replace(/\/$/, '');
  const TIMEOUT   = 95_000; // cosign sign/verify can be slow on first OCI fetch
  const STORE_KEY = 'vsp.supplychain.lastImage';

  // ── helpers ─────────────────────────────────────────────────────────────
  function $(id)  { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function toast(msg, kind) {
    if (typeof window.showToast === 'function') return window.showToast(msg, kind || 'info');
    (window.VSP_DEBUG && console.log('[supplychain]', kind || 'info', msg));
  }
  async function api(path, opts) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
    try {
      const r = await fetch(API_BASE + path, Object.assign({
        headers: { 'Content-Type': 'application/json' },
        signal:  ctrl.signal,
      }, opts || {}));
      const ct = r.headers.get('content-type') || '';
      const body = ct.includes('json') ? await r.json() : await r.text();
      if (!r.ok && typeof body === 'object') {
        throw new Error(body.error || ('HTTP ' + r.status));
      }
      if (!r.ok) throw new Error('HTTP ' + r.status + ': ' + String(body).slice(0, 200));
      return body;
    } finally {
      clearTimeout(timer);
    }
  }
  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }
  function statusPill(status) {
    // Status taxonomy mirrors backend classifyVerifyFailure (cosign-api).
    // Distinct colours so an auditor can tell at a glance whether they
    // are looking at an ops problem (amber) vs a real security event
    // (red — TAMPERED only).
    const map = {
      signed:      { c: 'var(--green)',  t: '✓ SIGNED' },
      verified:    { c: 'var(--green)',  t: '✓ VERIFIED' },
      tampered:    { c: 'var(--red)',    t: '✗ TAMPERED' }, // real attack
      unsigned:    { c: 'var(--t3)',     t: '○ UNSIGNED' }, // expected in dev
      not_found:   { c: 'var(--amber)',  t: '? REGISTRY UNREACHABLE' }, // localhost:5000 offline
      unavailable: { c: 'var(--amber)',  t: '! UNAVAILABLE' }, // ops issue
      failed:      { c: 'var(--red)',    t: '✗ FAILED' },
    };
    const s = map[status] || { c: 'var(--t3)', t: (status || '—').toUpperCase() };
    return `<span style="font-family:var(--font-mono);font-size:10px;font-weight:700;
            color:${s.c};padding:2px 8px;border-radius:4px;
            background:${s.c.replace(')', ',0.12)').replace('var(', 'rgba(')};
            ">${s.t}</span>`;
  }

  // ── panel discovery ─────────────────────────────────────────────────────
  // vsp_pro_100.js builds a panel called either "Supply Chain" or "supplychain".
  // We attach to whichever container we find, otherwise self-mount under #app.
  function findPanel() {
    return $('panel-supplychain')
        || $('panel-supply-chain')
        || document.querySelector('[data-panel="supplychain"]')
        || document.querySelector('[data-panel="supply-chain"]');
  }

  // ── UI mount ────────────────────────────────────────────────────────────
  function mount(panel) {
    if (panel.dataset.realApi === '1') return; // idempotent
    panel.dataset.realApi = '1';

    // Clear stale images that require auth (ghcr.io, docker.io private)
  const _stored = localStorage.getItem(STORE_KEY) || '';
  if (_stored.startsWith('ghcr.io') || _stored.startsWith('docker.io/library/hello')) {
    localStorage.removeItem(STORE_KEY);
  }
  const lastImg = localStorage.getItem(STORE_KEY) || 'ttl.sh/vsp-alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1';

    panel.insertAdjacentHTML('afterbegin', `
      <div class="card mb14" id="sc-controls">
        <div class="card-head">
          <div>
            <div class="card-title">Supply chain — Cosign / Sigstore</div>
            <div class="card-sub">
              microservice <code style="color:var(--cyan);font-family:var(--font-mono)">${esc(API_BASE)}</code>
              · keypair <code style="color:var(--t3);font-family:var(--font-mono)">/etc/vsp/cosign.{key,pub}</code>
            </div>
          </div>
          <div style="display:flex;gap:6px;align-items:center">
            <span id="sc-health" class="mono-sm" style="color:var(--t3)">checking…</span>
          </div>
        </div>

        <div style="padding:14px;display:grid;grid-template-columns:1fr auto auto auto;gap:8px">
          <input aria-label="image:tag — e.g. ghcr.io/org/api:1.2.3" id="sc-image" class="form-ctrl"
                 placeholder="e.g. ghcr.io/org/api:1.2.3 or ttl.sh/myimage:1h"
                 value="${esc(lastImg)}"
                 style="font-family:var(--font-mono);font-size:12px">
          <button class="btn btn-primary btn-sm" id="sc-btn-sign">Sign</button>
          <button class="btn btn-sm"             id="sc-btn-verify">Verify</button>
          <button class="btn btn-sm"             id="sc-btn-attest">Attest (SLSA)</button>
        </div>

        <div id="sc-result" style="padding:0 14px 14px;font-family:var(--font-mono);
             font-size:11px;color:var(--t2);min-height:24px"></div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">Signature ledger</div>
            <div class="card-sub" id="sc-ledger-sub">loading…</div>
          </div>
          <div style="display:flex;gap:6px;align-items:center">
            <select id="sc-ledger-filter" onchange="filterLedger()"
              style="font-size:11px;padding:3px 6px;border-radius:4px;
                     background:var(--bg2,#18181b);border:1px solid var(--border);
                     color:var(--t2);cursor:pointer">
              <option value="">All</option>
              <option value="signed">✓ Signed</option>
              <option value="verified">✓ Verified</option>
              <option value="failed">✗ Failed</option>
              <option value="not_found">? Unreachable</option>
            </select>
            <button class="btn btn-sm" id="sc-btn-refresh">↻ Refresh</button>
          </div>
        </div>
        <div style="padding:0">
          <table class="data-table" style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="text-align:left;font-size:10px;color:var(--t3);
                         text-transform:uppercase;letter-spacing:0.06em;
                         background:var(--bg3);border-bottom:1px solid var(--border)">
                <th style="padding:8px 12px">Image</th>
                <th style="padding:8px 12px">Status</th>
                <th style="padding:8px 12px">Digest</th>
                <th style="padding:8px 12px">When</th>
                <th style="padding:8px 12px">ID</th>
              </tr>
            </thead>
            <tbody id="sc-ledger-rows">
              <tr><td colspan="5" style="padding:18px;text-align:center;color:var(--t3)">
                  loading signatures…</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card mb14">
        <div class="card-head">
          <div>
            <div class="card-title">SBOM diff</div>
            <div class="card-sub">paste two CycloneDX or SPDX JSON SBOMs to see new / fixed / persisted components</div>
          </div>
          <button class="btn btn-sm" id="sc-btn-sbom-sample">Load sample</button>
        </div>
        <div style="padding:14px;display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div>
            <label class="form-label" for="sc-sbom-a">SBOM A (previous)</label>
            <textarea id="sc-sbom-a" class="form-ctrl" rows="8"
                      style="font-family:var(--font-mono);font-size:10px;
                             white-space:pre;overflow:auto"
                      placeholder='{"bomFormat":"CycloneDX","components":[…]}'></textarea>
          </div>
          <div>
            <label class="form-label" for="sc-sbom-b">SBOM B (current)</label>
            <textarea id="sc-sbom-b" class="form-ctrl" rows="8"
                      style="font-family:var(--font-mono);font-size:10px;
                             white-space:pre;overflow:auto"
                      placeholder='{"bomFormat":"CycloneDX","components":[…]}'></textarea>
          </div>
        </div>
        <div style="padding:0 14px 14px;display:flex;gap:8px;align-items:center">
          <button class="btn btn-primary btn-sm" id="sc-btn-sbom-diff">Diff →</button>
          <span id="sc-sbom-stats" class="mono-sm" style="color:var(--t3)"></span>
        </div>
        <div id="sc-sbom-result" style="padding:0 14px 14px"></div>
      </div>
    `);

    // ── handlers ──────────────────────────────────────────────────────────
    $('sc-btn-sign')        .addEventListener('click', onSign);
    $('sc-btn-verify')      .addEventListener('click', onVerify);
    $('sc-btn-attest')      .addEventListener('click', onAttest);
    $('sc-btn-refresh')     .addEventListener('click', refreshLedger);
    $('sc-btn-sbom-diff')   .addEventListener('click', onSBOMDiff);
    $('sc-btn-sbom-sample') .addEventListener('click', loadSBOMSample);

    $('sc-image').addEventListener('change', e => {
      localStorage.setItem(STORE_KEY, e.target.value);
    });

    // initial
    healthCheck();
    refreshLedger();
  }

  // ── actions ───────────────────────────────────────────────────────────
  async function healthCheck() {
    const el = $('sc-health');
    if (!el) return;
    try {
      const h = await api('/healthz');
      el.innerHTML = `<span style="color:var(--green)">●</span> healthy · <span style="color:var(--t3)">${h.signatures} signatures stored</span> · <span style="color:var(--amber)">registry: use public OCI (ghcr.io / docker.io)</span>`;
    } catch (e) {
      el.innerHTML = `<span style="color:var(--red)">●</span> unreachable
        — <span style="color:var(--t3)">is vsp-cosign-api running on :8091?</span>`;
    }
  }

  function getImage() {
    const v = ($('sc-image').value || '').trim();
    if (!v) { toast('image required', 'warn'); return null; }
    localStorage.setItem(STORE_KEY, v);
    return v;
  }

  async function onSign() {
    const image = getImage(); if (!image) return;
    setBusy('sc-btn-sign', true);
    showResult('⏳ signing ' + image + '…', 'pending');
    try {
      const r = await api('/sign', {
        method: 'POST',
        body: JSON.stringify({ image }),
      });
      showResult(formatSigResult(r), r.status === 'signed' ? 'ok' : 'err');
      toast(r.status === 'signed' ? 'Image signed' : 'Sign failed', r.status === 'signed' ? 'success' : 'error');
      refreshLedger();
    } catch (e) {
      showResult('✗ ' + e.message, 'err');
      toast('Sign failed: ' + e.message, 'error');
    } finally { setBusy('sc-btn-sign', false); }
  }

  async function onVerify() {
    const image = getImage(); if (!image) return;
    setBusy('sc-btn-verify', true);
    showResult('⏳ verifying ' + image + '…', 'pending');
    try {
      const r = await api('/verify', {
        method: 'POST',
        body: JSON.stringify({ image }),
      });
      showResult(formatSigResult(r), r.status === 'verified' ? 'ok' : 'err');
      toast(r.status === 'verified' ? 'Signature valid' : 'Verification failed',
            r.status === 'verified' ? 'success' : 'error');
      refreshLedger();
    } catch (e) {
      showResult('✗ ' + e.message, 'err');
      toast('Verify failed: ' + e.message, 'error');
    } finally { setBusy('sc-btn-verify', false); }
  }

  async function onAttest() {
    const image = getImage(); if (!image) return;
    setBusy('sc-btn-attest', true);
    showResult('⏳ generating SLSA provenance for ' + image + '…', 'pending');
    try {
      const r = await api('/attest', {
        method: 'POST',
        body: JSON.stringify({ image, predicate: 'slsaprovenance' }),
      });
      showResult(formatSigResult(r), r.status === 'signed' ? 'ok' : 'err');
      toast(r.status === 'signed' ? 'Attestation written' : 'Attest failed',
            r.status === 'signed' ? 'success' : 'error');
      refreshLedger();
    } catch (e) {
      showResult('✗ ' + e.message, 'err');
      toast('Attest failed: ' + e.message, 'error');
    } finally { setBusy('sc-btn-attest', false); }
  }

  function formatSigResult(r) {
    const lines = [
      'id      : ' + esc(r.id),
      'image   : ' + esc(r.image),
      'status  : ' + esc(r.status),
    ];
    if (r.digest)    lines.push('digest  : ' + esc(r.digest));
    if (r.predicate) lines.push('predicate: ' + esc(r.predicate));
    if (r.reason)    lines.push('reason  : ' + esc(r.reason).slice(0, 240));
    return '<pre style="margin:0;white-space:pre-wrap">' + lines.join('\n') + '</pre>';
  }

  function showResult(html, kind) {
    const el = $('sc-result');
    if (!el) return;
    const colors = { ok: 'var(--green)', err: 'var(--red)', pending: 'var(--amber)' };
    el.style.color = colors[kind] || 'var(--t2)';
    el.innerHTML = html;
  }

  function setBusy(btnId, busy) {
    const b = $(btnId);
    if (!b) return;
    b.disabled = busy;
    b.style.opacity = busy ? '0.55' : '1';
    b.style.cursor  = busy ? 'wait' : 'pointer';
  }

  // ── ledger ──────────────────────────────────────────────────────────────
  async function refreshLedger() {
    const sub  = $('sc-ledger-sub');
    const rows = $('sc-ledger-rows');
    if (sub)  sub.textContent = 'loading…';
    try {
      const j = await api('/signatures');
      const arr = j.signatures || []; _ledgerCache = arr;
      const total = arr.length;
      const verified = arr.filter(s => s.status === 'verified' || s.status === 'signed').length;
      const failed = arr.filter(s => s.status === 'failed' || s.status === 'tampered').length;
      const unreachable = arr.filter(s => s.status === 'not_found' || s.status === 'unavailable').length;
      if (sub) sub.textContent = `${total} records · ${verified} ok · ${failed} failed · ${unreachable} unreachable`;
      if (!arr.length) {
        rows.innerHTML = `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--t3)">
          no signatures yet — sign an image above to populate the ledger</td></tr>`;
        return;
      }
      // Render via filterLedger to respect current filter
      filterLedger();
    } catch (e) {
      if (sub) sub.textContent = 'error';
      rows.innerHTML = `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--red)">
        ✗ ${esc(e.message)}</td></tr>`;
    }
  }

  // Cache for filter
  let _ledgerCache = [];

  window.filterLedger = filterLedger;
  function filterLedger() {
    const filter = document.getElementById('sc-ledger-filter');
    const rows = $('sc-ledger-rows');
    if (!filter || !rows || !_ledgerCache.length) return;
    const val = filter.value;
    const filtered = val ? _ledgerCache.filter(s => s.status === val) : _ledgerCache;
    if (!filtered.length) {
      rows.innerHTML = `<tr><td colspan="5" style="padding:18px;text-align:center;color:var(--t3)">
        no matching records</td></tr>`;
      return;
    }
    rows.innerHTML = filtered.slice(0, 100).map(s => `
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:8px 12px;font-family:var(--font-mono);font-size:11px;max-width:300px;
                   overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.image)}">${esc(s.image)}</td>
        <td style="padding:8px 12px">${statusPill(s.status)}</td>
        <td style="padding:8px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3)">
            ${esc(s.digest || '—').slice(0, 24)}${s.digest && s.digest.length > 24 ? '…' : ''}</td>
        <td style="padding:8px 12px;font-size:11px;color:var(--t3)">${fmtTime(s.created_at)}</td>
        <td style="padding:8px 12px;font-family:var(--font-mono);font-size:10px;color:var(--t3)">${esc(s.id)}</td>
      </tr>`).join('');
  }

  // ── SBOM diff ───────────────────────────────────────────────────────────
  async function onSBOMDiff() {
    const aRaw = $('sc-sbom-a').value.trim();
    const bRaw = $('sc-sbom-b').value.trim();
    const stats = $('sc-sbom-stats');
    const out   = $('sc-sbom-result');
    if (!aRaw || !bRaw) { toast('paste both SBOMs', 'warn'); return; }
    let a, b;
    try { a = JSON.parse(aRaw); } catch (e) { toast('SBOM A is not valid JSON', 'error'); return; }
    try { b = JSON.parse(bRaw); } catch (e) { toast('SBOM B is not valid JSON', 'error'); return; }

    setBusy('sc-btn-sbom-diff', true);
    stats.textContent = 'diffing…';
    out.innerHTML = '';
    try {
      const j = await api('/sbom/diff', {
        method: 'POST',
        body: JSON.stringify({ a, b }),
      });
      stats.innerHTML =
        `<span style="color:var(--green)">+${j.stats.added} added</span> · ` +
        `<span style="color:var(--red)">−${j.stats.removed} removed</span> · ` +
        `<span style="color:var(--t3)">${j.stats.persisted} persisted</span> · ` +
        `<span style="color:var(--amber)">${j.stats.churn_pct}% churn</span>`;
      out.innerHTML = renderSBOMDiff(j);
    } catch (e) {
      stats.textContent = '';
      out.innerHTML = `<div style="color:var(--red);font-family:var(--font-mono);font-size:11px">✗ ${esc(e.message)}</div>`;
    } finally { setBusy('sc-btn-sbom-diff', false); }
  }

  function renderSBOMDiff(d) {
    const col = (title, arr, color) => `
      <div>
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.08em;
                    color:${color};font-weight:700;margin-bottom:6px">
          ${title} (${arr.length})
        </div>
        <div style="max-height:280px;overflow:auto;border:1px solid var(--border);
                    border-radius:4px;background:var(--bg3)">
          ${arr.length === 0
            ? '<div style="padding:12px;color:var(--t3);font-size:11px">none</div>'
            : arr.slice(0, 200).map(c => `
                <div style="padding:6px 10px;border-bottom:1px solid var(--border);
                            font-family:var(--font-mono);font-size:10px">
                  <span style="color:var(--t1)">${esc(c.name)}</span>
                  <span style="color:var(--t3)">@${esc(c.version || '—')}</span>
                </div>`).join('')
          }
        </div>
      </div>`;
    return `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:10px">
              ${col('+ Added',     d.added,     'var(--green)')}
              ${col('− Removed',   d.removed,   'var(--red)')}
              ${col('= Persisted', d.persisted, 'var(--t3)')}
            </div>`;
  }

  function loadSBOMSample() {
    const a = {
      bomFormat: 'CycloneDX', specVersion: '1.4',
      components: [
        { name: 'openssl',      version: '3.0.12', purl: 'pkg:apk/alpine/openssl@3.0.12' },
        { name: 'libcrypto3',   version: '3.0.12', purl: 'pkg:apk/alpine/libcrypto3@3.0.12' },
        { name: 'zlib',         version: '1.2.13', purl: 'pkg:apk/alpine/zlib@1.2.13' },
        { name: 'curl',         version: '8.4.0' },
        { name: 'busybox',      version: '1.36.1' },
      ],
    };
    const b = {
      bomFormat: 'CycloneDX', specVersion: '1.4',
      components: [
        { name: 'openssl',      version: '3.0.15', purl: 'pkg:apk/alpine/openssl@3.0.15' },
        { name: 'libcrypto3',   version: '3.0.15', purl: 'pkg:apk/alpine/libcrypto3@3.0.15' },
        { name: 'zlib',         version: '1.2.13', purl: 'pkg:apk/alpine/zlib@1.2.13' },
        { name: 'curl',         version: '8.10.1' },
        { name: 'busybox',      version: '1.36.1' },
        { name: 'ca-certificates', version: '20240705' },
      ],
    };
    $('sc-sbom-a').value = JSON.stringify(a, null, 2);
    $('sc-sbom-b').value = JSON.stringify(b, null, 2);
    toast('Sample SBOMs loaded — click Diff →', 'info');
  }

  // ── boot ────────────────────────────────────────────────────────────────
  function boot() {
    const panel = findPanel();
    if (!panel) {
      // Try again later — vsp_pro_100.js may not have rendered yet.
      setTimeout(boot, 600);
      return;
    }
    mount(panel);

    // re-mount whenever Supply Chain becomes visible (panel rebuild safe)
    const obs = new MutationObserver(() => {
      const p = findPanel();
      if (p && p.dataset.realApi !== '1') mount(p);
    });
    obs.observe(document.body, { childList: true, subtree: true });

    // poll health every 30s while panel is in DOM
    setInterval(() => {
      if ($('sc-health')) healthCheck();
    }, 30_000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // expose for console debugging
  window.VSPSupplyChain = {
    refresh: refreshLedger,
    health:  healthCheck,
    api:     api,
    apiBase: API_BASE,
  };

  (window.VSP_DEBUG && console.log('[vsp-supplychain] real-API patch loaded — backend:', API_BASE));
})();
