// ═══════════════════════════════════════════════════════
// VSP Browser Auto-Probe
// Paste vào Console của http://127.0.0.1:8080
// Auto-click tất cả panels + intercept fetch + report
// ═══════════════════════════════════════════════════════

(async function vspAutoTest() {
  if (window._vspAutoTestRunning) {
    console.log('⚠️ Already running. Reload page first.');
    return;
  }
  window._vspAutoTestRunning = true;
  window._vspApiLog = [];
  
  // ─── Install fetch probe cho parent + all iframes ───
  function installProbe(target, label) {
    if (!target.fetch || target._vspProbed) return;
    target._vspProbed = true;
    const orig = target.fetch;
    target.fetch = function(url, opts) {
      const u = typeof url === 'string' ? url : url.url;
      if (u && u.includes('/api/')) {
        const entry = {frame: label, url: u, status: 'pending', time: Date.now()};
        window._vspApiLog.push(entry);
        return orig.apply(this, arguments).then(r => {
          entry.status = r.status;
          entry.duration = Date.now() - entry.time;
          return r;
        }).catch(e => {
          entry.status = 'ERR';
          entry.error = e.message;
          throw e;
        });
      }
      return orig.apply(this, arguments);
    };
  }
  
  installProbe(window, 'parent');
  document.querySelectorAll('iframe').forEach(f => {
    try {
      if (f.contentWindow) {
        const lbl = f.id || f.src?.split('/').pop()?.slice(0,20);
        installProbe(f.contentWindow, lbl);
      }
    } catch(e) {}
  });
  
  // Watch for new iframes
  new MutationObserver(mutations => {
    mutations.forEach(m => m.addedNodes.forEach(n => {
      if (n.tagName === 'IFRAME') {
        n.addEventListener('load', () => {
          try {
            const lbl = n.id || 'new-iframe';
            installProbe(n.contentWindow, lbl);
          } catch(e) {}
        });
      }
    }));
  }).observe(document.body, {childList: true, subtree: true});
  
  // ─── Auto click all panels ───
  const panels = [
    'dashboard', 'scanlog', 'runs', 'findings', 'remediation',
    'policy', 'audit', 'soc',
    'governance', 'compliance', 'p4compliance', 'sbom', 'sla',
    'analytics', 'executive', 'export',
    'users', 'cicd', 'integrations', 'settings',
    'ai_analyst', 'scheduler', 'correlation', 'soar', 'logsources',
    'ueba', 'assets', 'swinventory', 'netflow',
    'threathunt', 'vulnmgmt', 'threatintel'
  ];
  
  console.log(`🧪 Starting auto-test: ${panels.length} panels, ~${panels.length*2}s`);
  
  for (const p of panels) {
    try {
      console.log(`→ ${p}`);
      if (window.showPanel) window.showPanel(p);
      await new Promise(r => setTimeout(r, 2000));
    } catch(e) {
      console.warn(`✗ ${p}: ${e.message}`);
    }
  }
  
  // ─── Report ───
  const log = window._vspApiLog;
  const total = log.length;
  const failed = log.filter(x => typeof x.status === 'number' && x.status >= 400);
  const warned = log.filter(x => typeof x.status === 'number' && x.status >= 300 && x.status < 400);
  const ok = log.filter(x => x.status === 200);
  
  console.log('');
  console.log('═══════════════════════════════════════════');
  console.log(`✅ RESULTS: ${total} API calls`);
  console.log(`   OK (200):   ${ok.length}`);
  console.log(`   WARN (3xx): ${warned.length}`);
  console.log(`   FAIL (4xx/5xx): ${failed.length}`);
  console.log('═══════════════════════════════════════════');
  
  if (failed.length > 0) {
    console.log('');
    console.log('❌ FAILED:');
    console.table(failed.map(f => ({frame: f.frame, url: f.url.slice(0,80), status: f.status})));
  }
  
  // Top slow calls
  const sorted = [...log].filter(x => x.duration).sort((a,b) => b.duration - a.duration).slice(0,5);
  console.log('');
  console.log('🐌 TOP 5 SLOW:');
  console.table(sorted.map(x => ({url: x.url.slice(0,60), duration: x.duration+'ms'})));
  
  window._vspAutoTestRunning = false;
  window.vspFailedApis = () => console.table(failed);
  window.vspAllApis = () => console.table(log);
  
  console.log('');
  console.log('📊 Helpers:');
  console.log('   vspFailedApis()   → show failed');
  console.log('   vspAllApis()      → show all');
})();
