/* VSP PRO — CWPP module realapi patch
   Override window.VSP_PRO.modules.cwpp.render to fetch real Trivy data
   from /api/v1/container/images. Falls back to mock if API fails. */
(function(){
'use strict';
if (!window.VSP_PRO || !window.VSP_PRO.modules || !window.VSP_PRO.modules.cwpp){
  console.warn('[VSP-PRO-CWPP] VSP_PRO not loaded yet, skipping patch');
  return;
}

var PRO = window.VSP_PRO;
var cwpp = PRO.modules.cwpp;
var origRender = cwpp.render;

// Helper — auth-aware fetch with token from various locations
function fetchAPI(path){
  var token = localStorage.getItem('TOKEN') ||
              localStorage.getItem('vsp_token') ||
              window.TOKEN || '';
  var headers = { 'Accept': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(path, { headers: headers, credentials: 'same-origin' })
    .then(function(r){
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
}

cwpp.render = function(root){
  // Show loading state
  root.innerHTML = '<div style="padding:40px;text-align:center;color:#7d8aa0">' +
    '<div style="font-size:11px;letter-spacing:1px">SCANNING WITH TRIVY...</div>' +
    '<div style="margin-top:8px;font-size:10px">Fetching real CVE data from /api/v1/container/images</div>' +
    '</div>';

  fetchAPI('/api/v1/container/images')
    .then(function(images){
      if (!Array.isArray(images) || images.length === 0){
        // No data yet — offer seed
        root.innerHTML =
          '<div style="padding:40px;text-align:center">' +
          '<div style="font-size:13px;color:#cbd5e1;margin-bottom:16px">No images scanned yet</div>' +
          '<button class="pro-btn" onclick="VSP_PRO.cwppSeed()">Seed 4 demo images →</button>' +
          '<button class="pro-btn ghost" style="margin-left:8px" onclick="VSP_PRO.cwppShowMock()">Show mock data</button>' +
          '<div style="margin-top:20px;font-size:10px;color:#7d8aa0">' +
          '  Or POST {"ref":"&lt;image&gt;"} to /api/v1/container/scan' +
          '</div></div>';
        return;
      }
      renderRealImages(root, images);
    })
    .catch(function(err){
      console.warn('[VSP-PRO-CWPP] API fail, falling back to mock:', err.message);
      origRender.call(cwpp, root);
      // Add a banner at top
      var banner = document.createElement('div');
      banner.style.cssText = 'padding:8px 14px;background:#3f1d1d;border-left:3px solid #ef4444;' +
                             'color:#fca5a5;font-size:11px;margin-bottom:12px;border-radius:4px';
      banner.textContent = 'API offline — showing mock data. Backend: ' + err.message;
      root.insertBefore(banner, root.firstChild);
    });
};

function renderRealImages(root, images){
  // Compute aggregate KPIs
  var totalImg = images.length;
  var totalCrit = 0, totalHigh = 0, totalSigned = 0, totalSBOM = 0;
  images.forEach(function(img){
    totalCrit += (img.crit || 0);
    totalHigh += (img.high || 0);
    if (img.signed) totalSigned++;
    if (img.sbom_attested) totalSBOM++;
  });

  var html = '';

  // KPI strip
  html += '<div class="pro-kpi-row">';
  html += kpi('Images',         totalImg,                      'cyan');
  html += kpi('CRITICAL CVE',   totalCrit,                     'red');
  html += kpi('HIGH CVE',       totalHigh,                     'amber');
  html += kpi('Signed (cosign)',totalSigned + '/' + totalImg,  totalSigned === totalImg ? 'green' : 'amber');
  html += kpi('SBOM attested',  totalSBOM + '/' + totalImg,    totalSBOM === totalImg ? 'green' : 'amber');
  html += '</div>';

  // Action buttons
  html += '<div style="margin:14px 0;display:flex;gap:8px;flex-wrap:wrap">';
  html += '<button class="pro-btn" onclick="VSP_PRO.cwppScanNew()">+ Scan new image</button>';
  html += '<button class="pro-btn ghost" onclick="VSP_PRO.cwppRefresh()">↻ Refresh</button>';
  html += '<button class="pro-btn ghost" onclick="VSP_PRO.cwppSeed()">+ Seed 4 demo</button>';
  html += '</div>';

  // Image table
  html += '<div class="pro-section-h">Images & vulnerabilities (live from Trivy)</div>';
  html += '<table class="pro-table"><thead><tr>';
  html += '<th>Image</th><th>OS</th><th>Size</th><th>Layers</th>';
  html += '<th class="num">CRIT</th><th class="num">HIGH</th><th class="num">MED</th><th class="num">LOW</th>';
  html += '<th>Status</th><th>Scanned</th><th>Action</th></tr></thead><tbody>';

  images.forEach(function(img){
    var critPill = img.crit > 0 ? '<span class="pill red">' + img.crit + '</span>' : '<span class="pro-mono">0</span>';
    var highPill = img.high > 0 ? '<span class="pill amber">' + img.high + '</span>' : '<span class="pro-mono">0</span>';
    var statusPill = img.status === 'ok' ? '<span class="pill ok">scanned</span>' :
                     img.status === 'scanning' ? '<span class="pill info">scanning…</span>' :
                     '<span class="pill red">' + (img.status || 'unknown') + '</span>';
    var when = img.scanned_at ? new Date(img.scanned_at).toLocaleTimeString() : '-';
    html += '<tr>';
    html += '<td><strong>' + esc(img.ref) + '</strong></td>';
    html += '<td><span class="pill muted">' + esc(img.os || '?') + ' ' + esc(img.os_version || '') + '</span></td>';
    html += '<td class="pro-mono">' + (img.size_mb || 0) + ' MB</td>';
    html += '<td class="pro-mono">' + (img.layers || 0) + '</td>';
    html += '<td class="num">' + critPill + '</td>';
    html += '<td class="num">' + highPill + '</td>';
    html += '<td class="num pro-mono">' + (img.med || 0) + '</td>';
    html += '<td class="num pro-mono">' + (img.low || 0) + '</td>';
    html += '<td>' + statusPill + '</td>';
    html += '<td class="pro-mono" style="font-size:10px">' + when + '</td>';
    html += '<td><button class="pro-btn ghost" onclick="VSP_PRO.cwppShowCVEs(\'' +
            esc(img.id) + '\')">View ' + (img.total_cve || 0) + ' CVEs →</button></td>';
    html += '</tr>';
  });
  html += '</tbody></table>';

  root.innerHTML = html;
}

function kpi(label, val, tone){
  var bg = { red: '#7f1d1d', amber: '#78350f', green: '#14532d', cyan: '#155e75', muted: '#1f2937' }[tone] || '#1f2937';
  return '<div class="pro-kpi" style="background:linear-gradient(180deg,' + bg + '22,transparent)">' +
    '<div class="pro-kpi-l">' + label + '</div>' +
    '<div class="pro-kpi-v">' + val + '</div>' +
    '</div>';
}

function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
  });
}

// Action handlers — attach to global PRO object
PRO.cwppRefresh = function(){
  var host = document.getElementById('pro-body');
  if (host) cwpp.render(host);
};

// FIX 2026-05-07: do NOT pre-fill Authorization with an empty token.
// The auto-wrapper in vsp_upgrade_v100.js only injects a real Bearer token
// when the request has NO existing Authorization header. Sending "Bearer "
// (empty) blocks that wrapper AND falls through CSRF bypass → 403.
// Same fix applies to cwppShowCVEs further below.
PRO.cwppSeed = function(){
  fetch('/api/v1/container/seed', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' }
  }).then(function(r){
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(data){
    alert('Seeded: ' + (data.images || []).join(', ') + '\nScans running. Click Refresh in 30s.');
    setTimeout(PRO.cwppRefresh, 5000);
  }).catch(function(err){
    alert('Seed failed: ' + err.message);
  });
};

PRO.cwppScanNew = function(){
  var ref = prompt('Image to scan (e.g. nginx:1.25-alpine):');
  if (!ref) return;
  fetch('/api/v1/container/scan', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ref: ref })
  }).then(function(r){
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(data){
    alert('Scan started: ' + ref + '\nID: ' + data.id + '\nClick Refresh in 30-60s.');
    setTimeout(PRO.cwppRefresh, 5000);
  }).catch(function(err){
    alert('Scan failed: ' + err.message);
  });
};

PRO.cwppShowMock = function(){
  var host = document.getElementById('pro-body');
  if (host) origRender.call(cwpp, host);
};

PRO.cwppShowCVEs = function(imageID){
  fetch('/api/v1/container/scan/' + encodeURIComponent(imageID))
    .then(function(r){ return r.json(); })
    .then(function(data){
      var vulns = data.vulnerabilities || [];
      var msg = 'Image: ' + data.image.ref + '\n\nTop 10 CVEs:\n';
      vulns.slice(0, 10).forEach(function(v){
        msg += '  • ' + v.cve + ' [' + v.severity + '] ' + v.library + '@' + v.installed + '\n';
      });
      if (vulns.length > 10) msg += '\n... and ' + (vulns.length - 10) + ' more';
      alert(msg);
    });
};

(window.VSP_DEBUG && console.log('[VSP-PRO-CWPP] Patched — module cwpp now uses real Trivy API'));
})();
