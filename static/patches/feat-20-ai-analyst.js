/* FEAT-20 PATCH APPLIED — ai_analyst L2 UX states (rev: 20b) */
/* Wraps loadAllData() with skeleton/empty/error pattern via VSPUXState */
(function() {
  if (window.__FEAT20_APPLIED__) return;
  window.__FEAT20_APPLIED__ = true;

  // Real IDs discovered from static/panels/ai_analyst.html
  var KPI_IDS = ['kpi-score', 'kpi-gate', 'kpi-inc', 'kpi-crit'];
  var CTX_IDS = ['ctx-scan-sub'];
  var INC_LIST = 'right-incidents';

  function inlineSkeleton(width) {
    return '<span class="skeleton" style="display:inline-block;width:' +
           (width || 60) + 'px;height:14px;border-radius:3px"></span>';
  }

  function showSkeleton() {
    KPI_IDS.forEach(function(id) {
      var el = document.getElementById(id);
      if (el) {
        el.dataset._orig = el.textContent;
        el.innerHTML = inlineSkeleton(40);
      }
    });
    CTX_IDS.forEach(function(id) {
      var el = document.getElementById(id);
      if (el) {
        el.dataset._orig = el.textContent;
        el.innerHTML = inlineSkeleton(120);
      }
    });
    var inc = document.getElementById(INC_LIST);
    if (inc) {
      inc.dataset._orig = inc.innerHTML;
      inc.innerHTML = '<div class="skeleton" style="height:32px;margin:4px 0;border-radius:4px"></div>'
                    + '<div class="skeleton" style="height:32px;margin:4px 0;border-radius:4px"></div>'
                    + '<div class="skeleton" style="height:32px;margin:4px 0;border-radius:4px"></div>';
      // Use VSPUXState if available — matches ai_advisor/attestation convention
      if (typeof VSPUXState !== 'undefined' && VSPUXState.skeleton) {
        try { VSPUXState.skeleton('#right-incidents', {rows: 3, kind: 'card'}); } catch(e) {}
      }
    }
  }

  function showError(msg) {
    var inc = document.getElementById(INC_LIST);
    if (inc && typeof VSPUXState !== 'undefined' && VSPUXState.error) {
      try {
        VSPUXState.error('#right-incidents', msg || 'Failed to load AI analyst data',
                         function() { if (typeof loadAllData === 'function') loadAllData(); });
      } catch(e) {}
    }
    // Mark KPIs as failed
    KPI_IDS.forEach(function(id) {
      var el = document.getElementById(id);
      if (el && el.innerHTML.indexOf('skeleton') !== -1) {
        el.innerHTML = '<span style="color:var(--red);font-size:12px" title="' +
                       (msg || 'load failed') + '">⚠</span>';
      }
    });
    if (typeof showToast === 'function') {
      showToast('AI analyst load failed: ' + (msg || 'unknown'), 'error');
    }
  }

  function isEmpty(ctx) {
    if (!ctx) return true;
    var run = ctx.run || {};
    var incs = ctx.incidents || [];
    var scheds = ctx.schedules || [];
    var runs = ctx.recentRuns || [];
    return !run.summary && incs.length === 0 && scheds.length === 0 && runs.length === 0;
  }

  function showEmpty() {
    var inc = document.getElementById(INC_LIST);
    if (inc && typeof VSPUXState !== 'undefined' && VSPUXState.empty) {
      try {
        VSPUXState.empty('#right-incidents',
                         'No scan data yet — run a scan to enable AI analysis',
                         function() { if (typeof loadAllData === 'function') loadAllData(); });
      } catch(e) {}
    }
  }

  function tryWrap() {
    if (typeof loadAllData !== 'function') {
      setTimeout(tryWrap, 100);
      return;
    }
    if (loadAllData.__feat20_wrapped__) return;

    var _orig = loadAllData;
    window.loadAllData = async function() {
      showSkeleton();
      try {
        var result = await _orig.apply(this, arguments);
        if (typeof _ctxData !== 'undefined' && isEmpty(_ctxData)) {
          showEmpty();
        }
        return result;
      } catch (e) {
        console.error('[FEAT-20] loadAllData failed', e);
        showError(e && e.message ? e.message : String(e));
        throw e;
      }
    };
    window.loadAllData.__feat20_wrapped__ = true;
    console.log('[FEAT-20b] ai_analyst loadAllData wrapped (real IDs: kpi-score/gate/inc/crit + ctx-scan-sub + right-incidents)');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', tryWrap);
  } else {
    tryWrap();
  }
})();
