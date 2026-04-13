/* ================================================================
   VSP SIEM INTEGRATION PATCH v2
   - Fix: truyền JWT token từ parent xuống iframe
   - Fix: iframe không cần load lại VSP patches
   - Fix: correlation/soar/logsources/threatintel dùng token của parent
================================================================ */

// 1. Register SIEM panels in PANEL_META
(function() {
  if (typeof PANEL_META !== 'undefined') {
    Object.assign(PANEL_META, {
      correlation: { title:'Correlation engine', sub:'VSP / SIEM / Event correlation · incidents' },
      soar:        { title:'SOAR playbooks',     sub:'VSP / SIEM / Orchestration & automation'   },
      logsources:  { title:'Log ingestion',      sub:'VSP / SIEM / Sources · parsers · stream'   },
      threatintel: { title:'Threat intelligence',sub:'VSP / SIEM / IOC · CVE enrichment · MITRE' },
    });
  }
})();

// 2. Hook showPanel
(function() {
  const _prev = window.showPanel;
  window.showPanel = function(name, btn) {
    if (_prev) _prev(name, btn);
    const panelFrameMap = {
      correlation: '#panel-correlation iframe',
      soar:        '#panel-soar iframe',
      logsources:  '#panel-logsources iframe',
      threatintel: '#panel-threatintel iframe',
      ueba:        '#panel-ueba iframe',
      assets:      '#panel-assets iframe',
      threathunt:  '#threathunt-frame',
      netflow:     '#panel-netflow iframe',
      ai_analyst:  '#panel-ai_analyst iframe',
      vulnmgmt:    '#panel-vulnmgmt iframe',
      scheduler:   '#panel-scheduler iframe',
      users:       '#panel-users iframe',
      swrisk:      '#panel-swrisk iframe',
    };
    const loaders = {
      correlation: loadCorrelation,
      soar:        loadSOAR,
      logsources:  loadLogSources,
      threatintel: loadThreatIntel,
      ueba:        loadUEBA,
      assets:      loadAssets,
    };
    // Load iframe src từ data-src nếu chưa load
    const sel = panelFrameMap[name];
    if (sel) {
      const frame = document.querySelector(sel);
      if (frame) {
        const ds = frame.getAttribute('data-src');
        if (ds && (!frame.src || frame.src.endsWith('/'))) {
          frame.src = ds;
          frame.addEventListener('load', function onLoad() {
            frame.removeEventListener('load', onLoad);
            // Inject token
            const tk = window.TOKEN || '';
            if (tk) {
              try { frame.contentWindow.postMessage({type:'vsp:token', token:tk}, '*'); } catch(e) {}
            }
            // Load data sau 400ms
            if (loaders[name]) setTimeout(loaders[name], 400);
          });
          return;
        }
      }
    }
    // Frame đã load — chỉ cần inject token + data
    if (loaders[name]) setTimeout(loaders[name], 300);
  };
})();

// 3. Truyền token vào iframe sau khi load
function _injectTokenToFrame(frameEl) {
  if (!frameEl) return;
  const send = () => {
    try {
      frameEl.contentWindow.postMessage({
        type:  'vsp:token',
        token: window.TOKEN || localStorage.getItem('vsp_token') || '',
      }, '*');
    } catch(e) {}
  };
  // Gửi ngay nếu đã load, gửi lại khi load xong
  send();
  frameEl.addEventListener('load', send);
}

// 4. Khi iframe load xong → inject token + data
function _setupFrame(panelId, dataFn) {
  const frame = document.querySelector('#' + panelId + ' iframe');
  if (!frame) return;

  // Inject token ngay khi frame ready
  frame.addEventListener('load', function() {
    // Token
    try {
      frame.contentWindow.postMessage({
        type:  'vsp:token',
        token: window.TOKEN || localStorage.getItem('vsp_token') || '',
      }, '*');
    } catch(e) {}
    // Data
    if (typeof dataFn === 'function') {
      dataFn().then(data => {
        try {
          frame.contentWindow.postMessage({ type: 'vsp:data', ...data }, '*');
        } catch(e) {}
      }).catch(() => {});
    }
  });

  // Nếu frame đã load (cached)
  try {
    if (frame.contentDocument && frame.contentDocument.readyState === 'complete') {
      frame.contentWindow.postMessage({
        type:  'vsp:token',
        token: window.TOKEN || localStorage.getItem('vsp_token') || '',
      }, '*');
    }
  } catch(e) {}
}

// 5. Loaders
async function loadCorrelation() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };

  // Inject token vào frame trước
  const frame = document.querySelector('#panel-correlation iframe');
  if (frame) {
    try {
      frame.contentWindow.postMessage({
        type: 'vsp:token',
        token: window.TOKEN,
      }, '*');
    } catch(e) {}
  }

  // Load data
  const [rules, incidents] = await Promise.all([
    fetch('/api/v1/correlation/rules',    { headers: h }).then(r => r.json()).catch(() => ({ rules: [] })),
    fetch('/api/v1/correlation/incidents',{ headers: h }).then(r => r.json()).catch(() => ({ incidents: [] })),
  ]);

  const badge = document.getElementById('badge-incidents');
  if (badge) badge.textContent = incidents.total ?? (incidents.incidents || []).length ?? 0;

  if (frame) {
    try {
      frame.contentWindow.postMessage({ type: 'vsp:data', rules, incidents }, '*');
    } catch(e) {}
  }
}

async function loadSOAR() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const frame = document.querySelector('#panel-soar iframe');
  if (frame) {
    try { frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*'); } catch(e) {}
  }
  const [playbooks, runs] = await Promise.all([
    fetch('/api/v1/soar/playbooks',    { headers: h }).then(r => r.json()).catch(() => ({ playbooks: [] })),
    fetch('/api/v1/soar/runs?limit=20',{ headers: h }).then(r => r.json()).catch(() => ({ runs: [] })),
  ]);
  if (frame) {
    try { frame.contentWindow.postMessage({ type: 'vsp:data', playbooks, runs }, '*'); } catch(e) {}
  }
}

async function loadLogSources() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const frame = document.querySelector('#panel-logsources iframe');
  if (frame) {
    try { frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*'); } catch(e) {}
  }
  const [sources, stats] = await Promise.all([
    fetch('/api/v1/logs/sources',{ headers: h }).then(r => r.json()).catch(() => ({ sources: [] })),
    fetch('/api/v1/logs/stats',  { headers: h }).then(r => r.json()).catch(() => ({})),
  ]);
  if (frame) {
    try { frame.contentWindow.postMessage({ type: 'vsp:data', sources, stats }, '*'); } catch(e) {}
  }
}

async function loadThreatIntel() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const frame = document.querySelector('#panel-threatintel iframe');
  if (frame) {
    try { frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*'); } catch(e) {}
  }
  const [iocs, feeds, matches] = await Promise.all([
    fetch('/api/v1/ti/iocs?limit=20',{ headers: h }).then(r => r.json()).catch(() => ({ iocs: [] })),
    fetch('/api/v1/ti/feeds',        { headers: h }).then(r => r.json()).catch(() => ({ feeds: [] })),
    fetch('/api/v1/ti/matches',      { headers: h }).then(r => r.json()).catch(() => ({ matches: [] })),
  ]);
  if (frame) {
    try { frame.contentWindow.postMessage({ type: 'vsp:data', iocs, feeds, matches }, '*'); } catch(e) {}
  }
}

async function loadUEBA() {
  if (!await ensureToken()) return;
  const frame = document.querySelector('#panel-ueba iframe');
  if (!frame) return;
  try {
    frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*');
  } catch(e) {}
}

async function loadAssets() {
  if (!await ensureToken()) return;
  const frame = document.querySelector('#panel-assets iframe');
  if (!frame) return;
  try {
    frame.contentWindow.postMessage({ type: 'vsp:token', token: window.TOKEN }, '*');
  } catch(e) {}
}


// 6. Auto-trigger SOAR từ SSE
window._siemAutoTrigger = async function(msg) {
  if (!msg) return;
  if (msg.type === 'scan_complete' && msg.gate === 'FAIL') {
    if (!await ensureToken()) return;
    fetch('/api/v1/soar/trigger', {
      method:  'POST',
      headers: { Authorization: 'Bearer ' + window.TOKEN, 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        trigger:  'gate_fail',
        gate:     msg.gate,
        severity: msg.max_severity || 'HIGH',
        run_id:   msg.rid,
        findings: msg.total_findings,
      }),
    })
    .then(r => r.json())
    .then(d => { if (d.triggered > 0 && typeof showToast === 'function') showToast('SOAR: ' + d.triggered + ' playbook(s) triggered', 'info'); })
    .catch(() => {});
  }
};

// 7. Quick search
(function() {
  if (typeof QS_PANELS === 'undefined') return;
  const already = QS_PANELS.some(p => p.p === 'correlation');
  if (already) return;
  QS_PANELS.push(
    { name:'Correlation engine', icon:'◆', p:'correlation', desc:'Cross-source rules · incidents' },
    { name:'SOAR playbooks',     icon:'▶', p:'soar',        desc:'Automated response workflows'   },
    { name:'Log ingestion',      icon:'⊞', p:'logsources',  desc:'Syslog · CEF · agent sources'   },
    { name:'Threat intelligence',icon:'◈', p:'threatintel', desc:'IOC · CVE enrichment · MITRE'   }
  );
})();

// 8. Broadcast token tới tất cả iframes khi TOKEN thay đổi
//    (sau login thành công)
(function() {
  const _origGovLogin = window.govLoginSubmit;
  if (!_origGovLogin) return;
  window.govLoginSubmit = async function() {
    await _origGovLogin.apply(this, arguments);
    // Sau login, broadcast token vào tất cả iframes
    setTimeout(function() {
      document.querySelectorAll('iframe').forEach(function(f) {
        try {
          f.contentWindow.postMessage({
            type:  'vsp:token',
            token: window.TOKEN || localStorage.getItem('vsp_token') || '',
          }, '*');
        } catch(e) {}
      });
    }, 800);
  };
})();

// 9. Listener trong iframe nhận token từ parent
//    (chạy trong context của soar.html / log_pipeline.html / etc.)
if (window.parent !== window) {
  // Đây là iframe — lắng nghe token từ parent
  window.addEventListener('message', function(e) {
    if (!e.data) return;

    // Nhận token
    if (e.data.type === 'vsp:token' && e.data.token) {
      window.TOKEN = e.data.token;
      // Lưu để ensureToken() tìm thấy
      try { localStorage.setItem('vsp_token', e.data.token); } catch(ex) {}
    }

    // Nhận data
    if (e.data.type === 'vsp:data') {
      // SOAR
      if (e.data.playbooks && typeof PLAYBOOKS !== 'undefined') {
        PLAYBOOKS = e.data.playbooks.map(function(p) {
          return Object.assign({}, p, {
            steps: (p.steps || []).map(function(s, i) {
              return Object.assign({}, s, { id: 's' + i, status: 'idle' });
            })
          });
        });
        if (typeof renderList === 'function') renderList();
      }
      // Log sources
      if (e.data.sources && typeof SOURCES !== 'undefined') {
        SOURCES = e.data.sources.map(function(s) {
          return Object.assign({ eps: s.events_per_min || 0, pr: s.parse_rate || 0, last: s.last_event || '?' }, s);
        });
        if (typeof renderSources === 'function') renderSources();
      }
    }
  });

  // Yêu cầu token từ parent ngay khi load
  window.parent.postMessage({ type: 'vsp:request_token' }, '*');
}

// 10. Parent lắng nghe yêu cầu token từ iframe
if (window.parent === window) {
  window.addEventListener('message', function(e) {
    if (e.data && e.data.type === 'vsp:request_token') {
      // Tìm iframe nguồn và reply token
      document.querySelectorAll('iframe').forEach(function(f) {
        try {
          if (f.contentWindow === e.source) {
            f.contentWindow.postMessage({
              type:  'vsp:token',
              token: window.TOKEN || localStorage.getItem('vsp_token') || '',
            }, '*');
          }
        } catch(ex) {}
      });
      // Broadcast tới tất cả nếu không xác định được source
      document.querySelectorAll('iframe').forEach(function(f) {
        try {
          f.contentWindow.postMessage({
            type:  'vsp:token',
            token: window.TOKEN || localStorage.getItem('vsp_token') || '',
          }, '*');
        } catch(ex) {}
      });
    }
  });
}

console.log('VSP SIEM patch loaded ✓ — correlation | soar | logsources | threatintel');
