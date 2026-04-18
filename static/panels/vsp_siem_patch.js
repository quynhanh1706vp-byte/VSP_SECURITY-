/* VSP SIEM patch — clean rewrite, no token loop */

// 1. PANEL_META
(function() {
  if (typeof PANEL_META !== 'undefined') {
    Object.assign(PANEL_META, {
      correlation: { title:'Correlation engine', sub:'VSP / SIEM / Event correlation · incidents' },
      soar:        { title:'SOAR playbooks',     sub:'VSP / SIEM / Orchestration & automation'   },
      logsources:  { title:'Log ingestion',      sub:'VSP / SIEM / Sources · parsers · stream'   },
      threatintel: { title:'Threat intelligence',sub:'VSP / SIEM / IOC · CVE enrichment · MITRE' },
      ueba:        { title:'UEBA analytics',     sub:'VSP / SIEM / Behavioral baseline · anomalies' },
      assets:      { title:'Asset inventory',    sub:'VSP / SIEM / CMDB · risk scoring · findings' },
      threathunt:  { title:'Threat Hunting',      sub:'VSP / SIEM / Log query · pivot · timeline' },
      vulnmgmt:    { title:'Vulnerability Mgmt',  sub:'VSP / Security / CVE tracking · trend · SLA' },
    });
  }
})();

// 2. Override showPanel sau khi tất cả patches load xong
var _siemLoaded = {};
function _siemShowPanel(name) {
  var panelMap = {logsources:'panel-logsources', threatintel:'panel-threatintel', ai_analyst:'panel-ai_analyst'};
  var panelId = panelMap[name] || ('panel-' + name);
  var frame = document.querySelector('#' + panelId + ' iframe');
  if (!frame) return;
  var tk = window.TOKEN || localStorage.getItem('vsp_token') || '';
  // FIX: bỏ điều kiện length < 50 — token có thể ngắn hơn
  if (!tk) return;

  var ds = frame.dataset.src || frame.getAttribute('data-src') || '';
  if (!ds) return;

  // FIX: kiểm tra đã load chưa bằng cách so sánh với data-src filename
  var fname = ds.split('?')[0].split('/').pop();
  var alreadyLoaded = frame.src && frame.src.indexOf(fname) >= 0;

  if (!alreadyLoaded) {
    // Lazy load
    frame.src = ds + (ds.indexOf('?') >= 0 ? '&' : '?') + '_t=' + Date.now();
    frame.onload = function() {
      var t = window.TOKEN || localStorage.getItem('vsp_token') || '';
      setTimeout(function() {
        try { frame.contentWindow.postMessage({type:'vsp:token', token:t}, '*'); } catch(e) {}
        setTimeout(function() {
          try { frame.contentWindow.postMessage({type:'vsp:token', token:t}, '*'); } catch(e) {}
        }, 1000);
      }, 300);
      var loaders = {correlation:loadCorrelation,soar:loadSOAR,logsources:loadLogSources,
                     threatintel:loadThreatIntel,ueba:loadUEBA,assets:loadAssetsPanel};
      if (loaders[name]) setTimeout(loaders[name], 600);
    };
  } else {
    // Đã load — push token + data
    try { frame.contentWindow.postMessage({type:'vsp:token', token:tk}, '*'); } catch(e) {}
    var loaders = {correlation:loadCorrelation,soar:loadSOAR,logsources:loadLogSources,
                   threatintel:loadThreatIntel,ueba:loadUEBA,assets:loadAssetsPanel};
    if (loaders[name]) setTimeout(loaders[name], 200);
  }
}

// Hook vào window.showPanel SAU KHI tất cả load xong
window.addEventListener('load', function() {
  var _orig = window.showPanel;
  window.showPanel = function(name, btn) {
    if (_orig) _orig(name, btn);
    // Trigger loader cho TẤT CẢ iframe panels (SIEM + mới)
    var allIframePanels = [
      'correlation','soar','logsources','threatintel','ueba','assets',
      'netflow','scheduler','ai_analyst','users','threathunt','vulnmgmt',
      'swinventory','p4compliance','cicd','integrations','settings'
    ];
    if (allIframePanels.indexOf(name) >= 0) {
      setTimeout(function(){ _siemShowPanel(name); }, 100);
    }
  };
});

// 3. Helper: gửi token vào 1 frame
function _sendToken(frame) {
  var tk = window.TOKEN || '';
  if (!tk || tk.length < 50) return;
  try { frame.contentWindow.postMessage({type:'vsp:token', token: tk}, '*'); } catch(e) {}
}

// 4. Helper: gửi token + data vào frame theo panel id
function _postFrame(panelId, data) {
  var frame = document.querySelector('#' + panelId + ' iframe');
  if (!frame) return;
  _sendToken(frame);
  if (data) try { frame.contentWindow.postMessage(data, '*'); } catch(e) {}
}

// 5. Loaders
async function loadCorrelation() {
  if (!await ensureToken()) return;
  var h = {Authorization: 'Bearer ' + window.TOKEN};
  var [rules, incidents] = await Promise.all([
    fetch('/api/v1/correlation/rules',    {headers:h}).then(r=>r.json()).catch(()=>({rules:[]})),
    fetch('/api/v1/correlation/incidents',{headers:h}).then(r=>r.json()).catch(()=>({incidents:[]})),
  ]);
  var badge = document.getElementById('badge-incidents');
  if (badge) badge.textContent = incidents.total ?? (incidents.incidents||[]).length ?? 0;
  _postFrame('panel-correlation', {type:'vsp:data', rules, incidents});
}

async function loadSOAR() {
  if (!await ensureToken()) return;
  var h = {Authorization: 'Bearer ' + window.TOKEN};
  var [playbooks, runs] = await Promise.all([
    fetch('/api/v1/soar/playbooks',    {headers:h}).then(r=>r.json()).catch(()=>({playbooks:[]})),
    fetch('/api/v1/soar/runs?limit=20',{headers:h}).then(r=>r.json()).catch(()=>({runs:[]})),
  ]);
  _postFrame('panel-soar', {type:'vsp:data', playbooks, runs});
}

async function loadLogSources() {
  if (!await ensureToken()) return;
  var h = {Authorization: 'Bearer ' + window.TOKEN};
  var [sources, stats] = await Promise.all([
    fetch('/api/v1/logs/sources',{headers:h}).then(r=>r.json()).catch(()=>({sources:[]})),
    fetch('/api/v1/logs/stats',  {headers:h}).then(r=>r.json()).catch(()=>({})),
  ]);
  _postFrame('panel-logsources', {type:'vsp:data', sources, stats});
}

async function loadThreatIntel() {
  if (!await ensureToken()) return;
  var h = {Authorization: 'Bearer ' + window.TOKEN};
  var [iocs, feeds, matches] = await Promise.all([
    fetch('/api/v1/ti/iocs?limit=20',{headers:h}).then(r=>r.json()).catch(()=>({iocs:[]})),
    fetch('/api/v1/ti/feeds',        {headers:h}).then(r=>r.json()).catch(()=>({feeds:[]})),
    fetch('/api/v1/ti/matches',      {headers:h}).then(r=>r.json()).catch(()=>({matches:[]})),
  ]);
  _postFrame('panel-threatintel', {type:'vsp:data', iocs, feeds, matches});
}

async function loadUEBA() {
  if (!await ensureToken()) return;
  _postFrame('panel-ueba', null);
}

async function loadAssetsPanel() {
  if (!await ensureToken()) return;
  _postFrame('panel-assets', null);
}

// 6. Parent: lắng nghe iframe xin token — chỉ reply khi có JWT thật
window.addEventListener('message', function(e) {
  if (!e.data || e.data.type !== 'vsp:request_token') return;
  var tk = window.TOKEN || '';
  if (!tk || tk.length < 50 || tk.split('.').length !== 3) return;
  // Reply chỉ cho iframe gửi request
  document.querySelectorAll('iframe').forEach(function(fr) {
    try { fr.contentWindow.postMessage({type:'vsp:token', token: tk}, '*'); } catch(ex) {}
  });
});

// 7. Sau khi login xong → gọi loader của active panel
(function() {
  var _sent = false;
  var _poll = setInterval(function() {
    var tk = window.TOKEN || '';
    if (!tk || tk.length < 50 || tk.split('.').length !== 3) return;
    if (_sent) { clearInterval(_poll); return; }
    _sent = true;
    clearInterval(_poll);
    // Broadcast token
    document.querySelectorAll('iframe').forEach(function(fr) {
      try { fr.contentWindow.postMessage({type:'vsp:token', token: tk}, '*'); } catch(ex) {}
    });
    // Gọi loader cho panel đang active
    var active = document.querySelector('.nav-item.active');
    if (active) {
      var onclick = active.getAttribute('onclick') || '';
      var m = onclick.match(/showPanel\(['"](\w+)['"]/);
      if (m) {
        var loaders = {correlation:loadCorrelation,soar:loadSOAR,logsources:loadLogSources,
                       threatintel:loadThreatIntel,ueba:loadUEBA,assets:loadAssetsPanel};
        if (loaders[m[1]]) setTimeout(loaders[m[1]], 500);
      }
    }
  }, 500);
})();

// 8. SSE auto-trigger
window._siemAutoTrigger = async function(msg) {
  if (!msg || msg.type !== 'scan_complete' || msg.gate !== 'FAIL') return;
  if (!await ensureToken()) return;
  fetch('/api/v1/soar/trigger', {
    method:'POST',
    headers:{Authorization:'Bearer '+window.TOKEN,'Content-Type':'application/json'},
    body: JSON.stringify({trigger:'gate_fail', gate:msg.gate,
      severity:msg.max_severity||'HIGH', run_id:msg.rid, findings:msg.total_findings}),
  }).then(r=>r.json()).then(d=>{
    if (d.triggered>0 && typeof showToast==='function')
      showToast('SOAR: '+d.triggered+' playbook(s) triggered','info');
  }).catch(()=>{});
};

// 9. Quick search
(function() {
  if (typeof QS_PANELS === 'undefined') return;
  if (QS_PANELS.some(function(p){return p.p==='correlation';})) return;
  QS_PANELS.push(
    {name:'Correlation engine', icon:'◆', p:'correlation', desc:'Cross-source rules · incidents'},
    {name:'SOAR playbooks',     icon:'▶', p:'soar',        desc:'Automated response workflows'  },
    {name:'Log ingestion',      icon:'⊞', p:'logsources',  desc:'Syslog · CEF · agent sources'  },
    {name:'Threat intelligence',icon:'◈', p:'threatintel', desc:'IOC · CVE enrichment · MITRE'  },
    {name:'UEBA analytics',     icon:'◉', p:'ueba',        desc:'Behavioral baseline · anomalies'},
    {name:'Asset inventory',    icon:'◫', p:'assets',      desc:'CMDB · risk scoring · coverage' }
  );
})();

console.log('VSP SIEM patch loaded ✓ — correlation | soar | logsources | threatintel | ueba | assets');


// Download SIEM PDF report
window._downloadSIEMReport = async function() {
  if (!window.TOKEN) return;
  var a = document.createElement('a');
  a.href = '/api/v1/siem/report.pdf';
  a.download = 'vsp_siem_report_' + new Date().toISOString().slice(0,10) + '.pdf';
  // Need auth header — use fetch + blob
  fetch('/api/v1/siem/report.pdf', {
    headers: {Authorization: 'Bearer ' + window.TOKEN}
  }).then(r => r.blob()).then(blob => {
    var url = URL.createObjectURL(blob);
    a.href = url;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }).catch(e => console.error('Download failed:', e));
};

window._downloadSIEMExcel = function() {
  if (!window.TOKEN) return;
  fetch('/api/v1/siem/report.xlsx', {
    headers: {Authorization: 'Bearer ' + window.TOKEN}
  }).then(r => r.blob()).then(blob => {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vsp_siem_' + new Date().toISOString().slice(0,10) + '.xlsx';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
  });
};

// Theme sync — broadcast theme change to all SIEM iframes
(function() {
  function _broadcastTheme() {
    var theme = document.documentElement.getAttribute('data-theme') || 'dark';
    document.querySelectorAll('iframe').forEach(function(fr) {
      try { fr.contentWindow.postMessage({type:'vsp:theme', theme:theme}, '*'); } catch(e) {}
    });
  }
  // Observe theme changes
  var observer = new MutationObserver(function(muts) {
    muts.forEach(function(m) {
      if (m.attributeName === 'data-theme') _broadcastTheme();
    });
  });
  observer.observe(document.documentElement, {attributes: true});
  // Handle theme requests from iframes
  window.addEventListener('message', function(e) {
    if (e.data && e.data.type === 'vsp:request_theme') {
      var theme = document.documentElement.getAttribute('data-theme') || 'dark';
      document.querySelectorAll('iframe').forEach(function(fr) {
        try { fr.contentWindow.postMessage({type:'vsp:theme', theme:theme}, '*'); } catch(e) {}
      });
    }
  });
  // Initial broadcast after load
  setTimeout(_broadcastTheme, 1000);
})();
