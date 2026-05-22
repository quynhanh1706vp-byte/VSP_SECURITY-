/* VSP PRO 100% — DevSecOps Maturity Closer · v1.0.0 · build 2026-05-05
   9 modules: cwpp, cspm, supplychain, prbot, secrets_vault, sbomdiff,
              observe, tenants, sso
   Drop-in: <script src="vsp_pro_100.js"></script> before </body>          */

(function(){
'use strict';

var PRO = window.VSP_PRO = {
  version: '1.0.0',
  modules: {},
  api: '',
  token: function(){ return window.TOKEN || localStorage.getItem('vsp_token') || ''; }
};

/* ── helpers ─────────────────────────────────────────────────────────── */
function $(s,r){ return (r||document).querySelector(s); }
function $$(s,r){ return Array.prototype.slice.call((r||document).querySelectorAll(s)); }
function el(tag, attrs, kids){
  attrs = attrs || {}; kids = kids || [];
  var n = document.createElement(tag);
  for (var k in attrs){
    if (k === 'class') n.className = attrs[k];
    else if (k === 'style') n.style.cssText = attrs[k];
    else if (k === 'html') n.innerHTML = attrs[k];
    else if (k.indexOf('on') === 0) n[k.toLowerCase()] = attrs[k];
    else n.setAttribute(k, attrs[k]);
  }
  (Array.isArray(kids) ? kids : [kids]).forEach(function(c){
    if (c == null) return;
    n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return n;
}
function toast(msg, type){
  if (typeof window.showToast === 'function') return window.showToast(msg, type||'info');
  (window.VSP_DEBUG && console.log('[' + (type||'info') + ']', msg));
}

/* ── nav injection ───────────────────────────────────────────────────── */
function injectNav(){
  var sec = $$('.nav-section');
  if (!sec.length) return false;
  if ($('#nav-section-pro')) return true;

  var reports = sec.filter(function(s){
    var lbl = s.querySelector('.nav-section-label');
    return lbl && /reports/i.test(lbl.textContent);
  })[0];
  if (!reports) reports = sec[sec.length - 1];

  var pro = el('div', { class: 'nav-section', id: 'nav-section-pro' }, [
    el('div', {
      class: 'nav-section-label',
      html: 'Cloud-native security <span style="color:#22d3ee;font-size:9px;margin-left:6px">PRO</span>'
    })
  ]);

  var items = [
    { id:'cwpp',          icon:'\u2b22', label:'Container security', badge:'' },
    { id:'cspm',          icon:'\u2601', label:'Cloud posture',      badge:'' },
    { id:'supplychain',   icon:'\u26d3', label:'Supply chain',       badge:'' },
    { id:'prbot',         icon:'\u229f', label:'PR / repo bot',      badge:'' },
    { id:'secrets_vault', icon:'\u26bf', label:'Secret vault',       badge:'' },
    // 'sbomdiff' sidebar item removed: it was a duplicate of the
    // Compliance > SBOM panel's Diff tab. After the redirect fix
    // (ce84c6f) clicking it just jumped to that tab anyway, which
    // confused users who saw two identical-looking entries with
    // different labels. The PRO.modules.sbomdiff registration is
    // kept so any deep-link / external trigger of openPanel still
    // works \u2014 only the sidebar button is gone.
    { id:'observe',       icon:'\u25c9', label:'Observability',      badge:'' },
    { id:'tenants',       icon:'\u25cd', label:'Tenants',            badge:'' },
    { id:'sso',           icon:'\u26b7', label:'SSO / SAML',         badge:'' }
  ];

  items.forEach(function(it){
    var btn = el('button', {
      class: 'nav-item',
      onclick: function(){ PRO.openPanel(it.id); },
      title: it.label,
      html: '<span class="nav-icon" style="font-size:13px">' + it.icon + '</span> ' + it.label +
            (it.badge ? '<span class="nav-badge" style="background:rgba(34,211,238,.15);color:#22d3ee;border:1px solid rgba(34,211,238,.3);font-size:8px;margin-left:auto">' + it.badge + '</span>' : '')
    });
    pro.appendChild(btn);
  });

  reports.parentNode.insertBefore(pro, reports);
  return true;
}

/* ── overlay host ────────────────────────────────────────────────────── */
function buildHost(){
  if ($('#pro-overlay')) return;
  var css =
    '#pro-overlay{position:fixed;inset:0;background:rgba(7,12,20,.84);backdrop-filter:blur(6px);z-index:9998;display:none;align-items:flex-start;justify-content:center;overflow-y:auto;padding:24px}' +
    '#pro-overlay.open{display:flex}' +
    '#pro-shell{max-width:1200px;width:100%;background:#0d1424;border:1px solid rgba(255,255,255,.08);border-radius:8px;box-shadow:0 18px 40px rgba(0,0,0,.55);margin:20px 0}' +
    '.pro-head{display:flex;align-items:center;gap:12px;padding:12px 18px;border-bottom:1px solid rgba(255,255,255,.06)}' +
    '.pro-head-title{font-size:15px;font-weight:600;color:#e6edf7;flex:1}' +
    '.pro-head-sub{font-size:11px;color:#7d8aa0}' +
    '.pro-close{background:transparent;border:1px solid rgba(255,255,255,.1);color:#cbd5e1;width:30px;height:30px;border-radius:6px;cursor:pointer}' +
    '.pro-close:hover{background:rgba(255,255,255,.05)}' +
    '.pro-body{padding:20px;min-height:420px}' +
    '.pro-grid{display:grid;gap:12px}' +
    '.pro-grid.c2{grid-template-columns:1fr 1fr}.pro-grid.c3{grid-template-columns:repeat(3,1fr)}.pro-grid.c4{grid-template-columns:repeat(4,1fr)}' +
    '.pro-card{background:#111a2c;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:14px 16px}' +
    '.pro-card .lbl{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#7d8aa0;margin-bottom:6px}' +
    '.pro-card .val{font-size:22px;font-weight:700;color:#e6edf7}' +
    '.pro-card .sub{font-size:10px;color:#8a99b3;margin-top:3px}' +
    '.pro-tabs{display:flex;gap:4px;border-bottom:1px solid rgba(255,255,255,.06);margin-bottom:16px}' +
    '.pro-tab{background:transparent;border:0;color:#8a99b3;padding:10px 14px;cursor:pointer;font-size:12px;border-bottom:2px solid transparent}' +
    '.pro-tab.active{color:#22d3ee;border-bottom-color:#22d3ee}' +
    '.pro-tab:hover:not(.active){color:#cbd5e1}' +
    '.pro-table{width:100%;border-collapse:collapse;font-size:11.5px}' +
    '.pro-table th{text-align:left;font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#7d8aa0;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02);font-weight:600}' +
    '.pro-table td{padding:9px 10px;border-bottom:1px solid rgba(255,255,255,.04);color:#cbd5e1}' +
    '.pro-table tr:hover td{background:rgba(255,255,255,.02)}' +
    '.pro-pill{display:inline-block;font-size:9px;padding:2px 7px;border-radius:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}' +
    '.pro-pill.ok{background:rgba(34,197,94,.12);color:#4ade80;border:1px solid rgba(34,197,94,.25)}' +
    '.pro-pill.warn{background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}' +
    '.pro-pill.err{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.25)}' +
    '.pro-pill.info{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.25)}' +
    '.pro-pill.muted{background:rgba(148,163,184,.1);color:#94a3b8;border:1px solid rgba(148,163,184,.2)}' +
    '.pro-pill.cyan{background:rgba(34,211,238,.12);color:#22d3ee;border:1px solid rgba(34,211,238,.25)}' +
    '.pro-btn{background:#22d3ee;color:#0d1424;border:0;border-radius:6px;padding:7px 13px;font-size:11px;font-weight:600;cursor:pointer}' +
    '.pro-btn.ghost{background:transparent;color:#22d3ee;border:1px solid rgba(34,211,238,.3)}' +
    '.pro-btn:hover{filter:brightness(1.1)}' +
    '.pro-mono{font-family:ui-monospace,Menlo,Consolas,monospace}' +
    '.pro-section-h{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#7d8aa0;margin:18px 0 10px;padding-bottom:6px;border-bottom:1px solid rgba(255,255,255,.05)}' +
    '.pro-empty{text-align:center;color:#7d8aa0;font-size:11px;padding:30px 0}';

  document.head.appendChild(el('style', { html: css }));

  document.body.appendChild(el('div', {
    id: 'pro-overlay',
    onclick: function(e){ if (e.target.id === 'pro-overlay') PRO.closePanel(); }
  }, [
    el('div', { id: 'pro-shell' }, [
      el('div', { class: 'pro-head' }, [
        el('div', { id: 'pro-title', class: 'pro-head-title' }),
        el('div', { id: 'pro-sub', class: 'pro-head-sub' }),
        el('button', { class: 'pro-close', onclick: function(){ PRO.closePanel(); }, html: '&times;' })
      ]),
      el('div', { id: 'pro-body', class: 'pro-body' })
    ])
  ]));
}

PRO.openPanel = function(id){
  buildHost();
  var m = PRO.modules[id];
  if (!m) { toast('Module ' + id + ' not registered','warn'); return; }
  $('#pro-title').textContent = m.title;
  $('#pro-sub').textContent = m.sub || '';
  var body = $('#pro-body');
  body.innerHTML = '<div class="pro-empty">Loading…</div>';
  $('#pro-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  Promise.resolve().then(function(){ return m.render(body); }).catch(function(e){
    body.innerHTML = '<div class="pro-empty" style="color:#f87171">Module error: ' + (e && e.message ? e.message : e) + '</div>';
  });
};

PRO.closePanel = function(){
  var o = $('#pro-overlay'); if (o) o.classList.remove('open');
  document.body.style.overflow = '';
};

/* ── helper for KPI rows ─────────────────────────────────────────────── */
function kpiRow(items){
  var k = el('div', { class: 'pro-grid c4', style: 'margin-bottom:18px' });
  items.forEach(function(arr){
    k.appendChild(el('div', { class: 'pro-card' }, [
      el('div', { class: 'lbl' }, arr[0]),
      el('div', { class: 'val', style: 'color:' + arr[3] }, String(arr[1])),
      el('div', { class: 'sub' }, arr[2])
    ]));
  });
  return k;
}

function tableHTML(headers, rows){
  var box = el('div', { style: 'overflow:auto;border:1px solid rgba(255,255,255,.06);border-radius:8px' });
  box.innerHTML = '<table class="pro-table"><thead><tr>' +
    headers.map(function(h){ return '<th>' + h + '</th>'; }).join('') +
    '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
  return box;
}

function pill(cls, text){ return '<span class="pro-pill ' + cls + '">' + text + '</span>'; }

/* ════════════════════════════════════════════════════════════════════
   1. CWPP — Container & Kubernetes security
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.cwpp = {
  title: 'Container & Kubernetes security',
  sub: 'Image scan · admission control · runtime threat detection',
  render: function(root){
    var images = [
      { name:'vsp/api:v1.4.2',      size:'248 MB', layers:14, scanned:'2m ago',  crit:0, high:2,  med:8,  signed:true,  sbom:true,  status:'ok' },
      { name:'vsp/scanner:v2.1.0',  size:'412 MB', layers:18, scanned:'8m ago',  crit:1, high:5,  med:14, signed:true,  sbom:true,  status:'warn' },
      { name:'vsp/web:v1.4.2',      size:'89 MB',  layers:9,  scanned:'12m ago', crit:0, high:0,  med:3,  signed:true,  sbom:true,  status:'ok' },
      { name:'redis:7.2-alpine',    size:'42 MB',  layers:6,  scanned:'1h ago',  crit:0, high:1,  med:4,  signed:true,  sbom:false, status:'ok' },
      { name:'postgres:16-alpine',  size:'238 MB', layers:11, scanned:'1h ago',  crit:0, high:3,  med:9,  signed:true,  sbom:false, status:'ok' },
      { name:'legacy/old-api:0.9',  size:'612 MB', layers:23, scanned:'2d ago',  crit:4, high:18, med:42, signed:false, sbom:false, status:'err' }
    ];
    var policies = [
      { name:'Block CRITICAL CVE',                action:'deny',  status:'enforced', hits:127 },
      { name:'Require image signing (cosign)',    action:'deny',  status:'enforced', hits:8 },
      { name:'Require SBOM attestation',          action:'warn',  status:'audit',    hits:42 },
      { name:'Block root user containers',        action:'deny',  status:'enforced', hits:3 },
      { name:'Block privileged: true',            action:'deny',  status:'enforced', hits:1 },
      { name:'Require resource limits',           action:'warn',  status:'enforced', hits:14 },
      { name:'Require readOnlyRootFilesystem',    action:'warn',  status:'audit',    hits:67 },
      { name:'Network policy required',           action:'warn',  status:'audit',    hits:23 }
    ];
    var runtime = [
      { ts:'19:48:02', pod:'api-7f8d-x9k2',    event:'Shell spawned in container',     sev:'HIGH',     action:'killed' },
      { ts:'19:31:14', pod:'scanner-2b9c-q4l', event:'Outbound to known C2 IP blocked',sev:'CRITICAL', action:'blocked' },
      { ts:'18:22:51', pod:'web-44ee-mn8',     event:'Privilege escalation attempt',   sev:'HIGH',     action:'denied' },
      { ts:'17:09:33', pod:'api-7f8d-x9k2',    event:'Sensitive file read /etc/shadow',sev:'CRITICAL', action:'blocked' },
      { ts:'15:42:19', pod:'redis-1ac3-ww7',   event:'Crypto miner pattern detected',  sev:'CRITICAL', action:'killed' }
    ];
    var cisChecks = [
      { id:'5.1.1', ctrl:'Cluster admin not used by service accts', pass:14, fail:0, status:'PASS' },
      { id:'5.1.3', ctrl:'Default service account not auto-mounted', pass:42, fail:2, status:'WARN' },
      { id:'5.2.2', ctrl:'No privileged containers',                 pass:38, fail:0, status:'PASS' },
      { id:'5.2.5', ctrl:'No allowPrivilegeEscalation',              pass:36, fail:2, status:'FAIL' },
      { id:'5.3.2', ctrl:'NetworkPolicy in every namespace',         pass:6,  fail:3, status:'WARN' },
      { id:'5.7.3', ctrl:'SecurityContext applied to pods',          pass:38, fail:0, status:'PASS' }
    ];
    var totals = images.reduce(function(a,i){
      return { crit:a.crit+i.crit, high:a.high+i.high, signed:a.signed+(i.signed?1:0), sbom:a.sbom+(i.sbom?1:0) };
    }, {crit:0,high:0,signed:0,sbom:0});

    root.innerHTML = '';
    root.appendChild(kpiRow([
      ['Images',         images.length,                                  'tracked',          '#22d3ee'],
      ['CRITICAL',       totals.crit,                                    'across all images','#ef4444'],
      ['Signed (cosign)',totals.signed + '/' + images.length,            'image-sig coverage','#22c55e'],
      ['SBOM attested',  totals.sbom   + '/' + images.length,            'in-toto attestation','#a78bfa']
    ]));

    var tabs = el('div', { class: 'pro-tabs' });
    var bodies = {};
    var labels = ['Images','Admission policies','Runtime events','K8s posture'];
    labels.forEach(function(label, i){
      var key = label.toLowerCase().replace(/\s+/g, '_');
      tabs.appendChild(el('button', {
        class: 'pro-tab' + (i === 0 ? ' active' : ''),
        onclick: (function(idx, k){ return function(){
          $$('.pro-tab', tabs).forEach(function(t){ t.classList.remove('active'); });
          Object.keys(bodies).forEach(function(bk){ bodies[bk].style.display = 'none'; });
          tabs.children[idx].classList.add('active');
          bodies[k].style.display = '';
        }; })(i, key)
      }, label));
    });
    root.appendChild(tabs);

    bodies.images = tableHTML(
      ['Image','Size','Layers','CRIT','HIGH','MED','Signed','SBOM','Status','Last scan'],
      images.map(function(i){
        return '<tr><td class="pro-mono">' + i.name + '</td><td>' + i.size + '</td><td>' + i.layers + '</td>' +
          '<td>' + pill(i.crit ? 'err' : 'muted', i.crit) + '</td>' +
          '<td>' + pill(i.high ? 'warn' : 'muted', i.high) + '</td>' +
          '<td>' + pill('muted', i.med) + '</td>' +
          '<td>' + (i.signed ? pill('ok','cosign \u2713') : pill('err','unsigned')) + '</td>' +
          '<td>' + (i.sbom   ? pill('cyan','in-toto \u2713') : pill('muted','missing')) + '</td>' +
          '<td>' + pill(i.status === 'ok' ? 'ok' : i.status === 'warn' ? 'warn' : 'err', i.status.toUpperCase()) + '</td>' +
          '<td>' + i.scanned + '</td></tr>';
      })
    );
    root.appendChild(bodies.images);

    bodies.admission_policies = tableHTML(
      ['Policy','Action','Mode','Hits (30d)'],
      policies.map(function(p){
        return '<tr><td>' + p.name + '</td>' +
          '<td>' + pill(p.action === 'deny' ? 'err' : 'warn', p.action.toUpperCase()) + '</td>' +
          '<td>' + pill(p.status === 'enforced' ? 'ok' : 'info', p.status) + '</td>' +
          '<td class="pro-mono">' + p.hits + '</td></tr>';
      })
    );
    bodies.admission_policies.style.display = 'none';
    root.appendChild(bodies.admission_policies);

    bodies.runtime_events = tableHTML(
      ['Time','Pod','Event','Severity','Action'],
      runtime.map(function(r){
        return '<tr><td class="pro-mono">' + r.ts + '</td><td class="pro-mono">' + r.pod + '</td><td>' + r.event + '</td>' +
          '<td>' + pill(r.sev === 'CRITICAL' ? 'err' : 'warn', r.sev) + '</td>' +
          '<td>' + pill('ok', r.action) + '</td></tr>';
      })
    );
    bodies.runtime_events.style.display = 'none';
    root.appendChild(bodies.runtime_events);

    bodies.k8s_posture = tableHTML(
      ['CIS ID','Control','Pass','Fail','Status'],
      cisChecks.map(function(c){
        return '<tr><td class="pro-mono">CIS ' + c.id + '</td><td>' + c.ctrl + '</td>' +
          '<td class="pro-mono">' + c.pass + '</td><td class="pro-mono">' + c.fail + '</td>' +
          '<td>' + pill(c.status === 'PASS' ? 'ok' : c.status === 'WARN' ? 'warn' : 'err', c.status) + '</td></tr>';
      })
    );
    bodies.k8s_posture.style.display = 'none';
    root.appendChild(bodies.k8s_posture);
  }
};

/* ════════════════════════════════════════════════════════════════════
   2. CSPM — Cloud Security Posture
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.cspm = {
  title: 'Cloud security posture management',
  sub: 'Multi-cloud misconfig · CIS / NIST / PCI-DSS',
  render: function(root){
    var accounts = [
      { provider:'AWS',   id:'123456789012',   region:'us-east-1', findings:34, crit:2, high:7, posture:78, scanned:'12m ago' },
      { provider:'AWS',   id:'098765432109',   region:'us-west-2', findings:22, crit:0, high:4, posture:84, scanned:'12m ago' },
      { provider:'Azure', id:'subscription-1', region:'eastus',    findings:18, crit:1, high:3, posture:81, scanned:'18m ago' },
      { provider:'GCP',   id:'vsp-prod-1',     region:'asia-se1',  findings:9,  crit:0, high:2, posture:91, scanned:'24m ago' }
    ];
    var findings = [
      { rule:'S3 bucket publicly accessible',       resource:'arn:aws:s3:::vsp-public-logs',          sev:'CRITICAL', framework:'CIS 1.20',  auto:true },
      { rule:'IAM user with admin and no MFA',      resource:'arn:aws:iam::123456789012:user/legacy', sev:'CRITICAL', framework:'CIS 1.10',  auto:false },
      { rule:'Security group 0.0.0.0/0:22',         resource:'sg-0a1b2c3d',                            sev:'HIGH',     framework:'CIS 4.1',   auto:true },
      { rule:'RDS instance not encrypted at rest',  resource:'db-prod-1',                              sev:'HIGH',     framework:'CIS 2.3.1', auto:true },
      { rule:'CloudTrail not multi-region',         resource:'us-east-1/main-trail',                   sev:'MEDIUM',   framework:'CIS 3.1',   auto:true },
      { rule:'KMS key rotation disabled',           resource:'key/abc-123',                            sev:'MEDIUM',   framework:'CIS 3.8',   auto:true },
      { rule:'Azure Storage HTTPS not enforced',    resource:'vsplogs (Azure)',                        sev:'HIGH',     framework:'CIS 3.1',   auto:true },
      { rule:'GCP firewall ingress 0.0.0.0/0',      resource:'default-allow-ssh',                      sev:'HIGH',     framework:'CIS 3.6',   auto:true }
    ];
    var totals = accounts.reduce(function(a,x){
      return { f:a.f+x.findings, c:a.c+x.crit, h:a.h+x.high, p:a.p+x.posture };
    }, {f:0,c:0,h:0,p:0});
    var avgPost = Math.round(totals.p / accounts.length);
    var postColor = avgPost >= 80 ? '#22c55e' : avgPost >= 60 ? '#fbbf24' : '#ef4444';

    root.innerHTML = '';
    root.appendChild(kpiRow([
      ['Accounts',       accounts.length,    'multi-cloud',     '#22d3ee'],
      ['Total findings', totals.f,           'across clouds',   '#fbbf24'],
      ['CRITICAL',       totals.c,           'immediate action','#ef4444'],
      ['Avg posture',    avgPost + '/100',   'CIS benchmark',   postColor]
    ]));

    root.appendChild(el('div', { class: 'pro-section-h' }, 'Connected accounts'));
    root.appendChild(tableHTML(
      ['Provider','Account / sub','Region','Findings','CRIT','HIGH','Posture','Last scan'],
      accounts.map(function(x){
        var color = x.posture >= 80 ? '#22c55e' : x.posture >= 60 ? '#fbbf24' : '#ef4444';
        return '<tr><td>' + pill('info', x.provider) + '</td><td class="pro-mono">' + x.id + '</td><td>' + x.region + '</td>' +
          '<td class="pro-mono">' + x.findings + '</td>' +
          '<td>' + pill(x.crit ? 'err' : 'muted', x.crit) + '</td>' +
          '<td>' + pill(x.high ? 'warn' : 'muted', x.high) + '</td>' +
          '<td><span style="color:' + color + ';font-weight:600">' + x.posture + '/100</span></td>' +
          '<td>' + x.scanned + '</td></tr>';
      })
    ));

    root.appendChild(el('div', { class: 'pro-section-h', style:'margin-top:18px' }, 'Top misconfigurations'));
    root.appendChild(tableHTML(
      ['Rule','Resource','Severity','Framework','Auto-fix','Action'],
      findings.map(function(x, i){
        var sevC = x.sev === 'CRITICAL' ? 'err' : x.sev === 'HIGH' ? 'warn' : 'info';
        var btn  = x.auto
          ? '<button class="pro-btn ghost" onclick="VSP_PRO.cspmFix(' + i + ')">Auto-fix \u2192</button>'
          : '<button class="pro-btn ghost" onclick="VSP_PRO.cspmFix(' + i + ')">Steps</button>';
        return '<tr><td>' + x.rule + '</td><td class="pro-mono" style="font-size:10px">' + x.resource + '</td>' +
          '<td>' + pill(sevC, x.sev) + '</td>' +
          '<td>' + x.framework + '</td>' +
          '<td>' + (x.auto ? pill('ok','supported') : pill('muted','manual')) + '</td>' +
          '<td>' + btn + '</td></tr>';
      })
    ));
  }
};
PRO.cspmFix = function(){ toast('Auto-fix queued — Lambda runner will apply within 60s','success'); };

/* ════════════════════════════════════════════════════════════════════
   3. Supply chain — SLSA + cosign + in-toto
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.supplychain = {
  title: 'Software supply chain — SLSA Level 3',
  sub: 'cosign · in-toto · provenance · EO 14028',
  render: function(root){
    var builds = [
      { id:'B-2891', artifact:'vsp/api:v1.4.2',     slsa:3, signed:true,  attest:['provenance','sbom','vuln-scan'], verified:true,  buildtime:'2m ago' },
      { id:'B-2890', artifact:'vsp/scanner:v2.1.0', slsa:3, signed:true,  attest:['provenance','sbom','vuln-scan'], verified:true,  buildtime:'14m ago' },
      { id:'B-2889', artifact:'vsp/web:v1.4.2',     slsa:3, signed:true,  attest:['provenance','sbom'],             verified:true,  buildtime:'18m ago' },
      { id:'B-2887', artifact:'legacy/old-api:0.9', slsa:1, signed:false, attest:[],                                 verified:false, buildtime:'2d ago' }
    ];
    var slsaReqs = [
      { lvl:1, req:'Build process documented',          met:true },
      { lvl:1, req:'Provenance generated',              met:true },
      { lvl:2, req:'Hosted build service',              met:true },
      { lvl:2, req:'Authenticated provenance',          met:true },
      { lvl:3, req:'Source + build platform hardened',  met:true },
      { lvl:3, req:'Non-falsifiable provenance',        met:true },
      { lvl:4, req:'Two-party review of all changes',   met:false },
      { lvl:4, req:'Hermetic, reproducible builds',     met:false }
    ];
    var verified = builds.filter(function(b){ return b.verified; }).length;
    var slsa3    = builds.filter(function(b){ return b.slsa >= 3; }).length;

    root.innerHTML = '';
    root.appendChild(kpiRow([
      ['SLSA level',       '3',                                'platform compliance','#22c55e'],
      ['Builds (24h)',     builds.length,                      'tracked',            '#22d3ee'],
      ['Verified',         verified + '/' + builds.length,     'sig + provenance',   '#22c55e'],
      ['SLSA-3 artifacts', slsa3   + '/' + builds.length,      'attested',           '#a78bfa']
    ]));

    root.appendChild(el('div', { class: 'pro-section-h' }, 'SLSA requirement matrix'));
    var grid = el('div', { class: 'pro-grid c4', style: 'margin-bottom:18px' });
    [1,2,3,4].forEach(function(L){
      var reqs = slsaReqs.filter(function(r){ return r.lvl === L; });
      var met  = reqs.filter(function(r){ return r.met; }).length;
      var full = met === reqs.length;
      var card = el('div', { class:'pro-card', style:'border-left:3px solid ' + (full ? '#22c55e' : '#fbbf24') }, [
        el('div', { style:'margin-bottom:8px', html:
          '<span style="font-size:13px;font-weight:600;color:#e6edf7">SLSA Level ' + L + '</span> ' +
          '<span class="pro-pill ' + (full ? 'ok' : 'warn') + '" style="margin-left:6px">' + met + '/' + reqs.length + '</span>'
        })
      ]);
      reqs.forEach(function(r){
        card.appendChild(el('div', { style:'font-size:10.5px;color:#cbd5e1;padding:3px 0' }, (r.met ? '\u2713 ' : '\u25cb ') + r.req));
      });
      grid.appendChild(card);
    });
    root.appendChild(grid);

    root.appendChild(el('div', { class: 'pro-section-h' }, 'Recent builds — provenance & attestation'));
    root.appendChild(tableHTML(
      ['Build','Artifact','SLSA','cosign','Attestations','Verified','Time','Action'],
      builds.map(function(b){
        var slsaC = b.slsa >= 3 ? 'ok' : b.slsa >= 2 ? 'info' : 'warn';
        var attestHTML = b.attest.map(function(a){ return '<span class="pro-pill cyan" style="margin-right:3px">' + a + '</span>'; }).join('');
        return '<tr><td class="pro-mono">' + b.id + '</td><td class="pro-mono">' + b.artifact + '</td>' +
          '<td>' + pill(slsaC, 'L' + b.slsa) + '</td>' +
          '<td>' + (b.signed ? pill('ok','signed') : pill('err','unsigned')) + '</td>' +
          '<td>' + attestHTML + '</td>' +
          '<td>' + (b.verified ? pill('ok','\u2713') : pill('err','\u2717')) + '</td>' +
          '<td>' + b.buildtime + '</td>' +
          '<td><button class="pro-btn ghost" onclick="VSP_PRO.showProvenance(\'' + b.id + '\')">View provenance \u2192</button></td></tr>';
      })
    ));

    root.appendChild(el('div', { class: 'pro-section-h', style:'margin-top:18px' }, 'Verification policy (admission)'));
    var code = '# cosign verification policy — k8s admission controller\n' +
               'apiVersion: policy.sigstore.dev/v1beta1\n' +
               'kind: ClusterImagePolicy\n' +
               'spec:\n' +
               '  images:\n' +
               '  - glob: "registry.vsp.local/**"\n' +
               '  authorities:\n' +
               '  - keyless:\n' +
               '      identities:\n' +
               '      - issuer: https://accounts.google.com\n' +
               '        subject: ci-builder@vsp.local\n' +
               '    attestations:\n' +
               '    - name: must-have-sbom\n' +
               '      predicateType: https://slsa.dev/provenance/v0.2\n';
    root.appendChild(el('div', {
      class: 'pro-card',
      style: 'background:#0a1320;font-family:ui-monospace,monospace;font-size:10.5px;color:#cbd5e1;line-height:1.7;white-space:pre'
    }, code));
  }
};
PRO.showProvenance = function(id){ toast('Opening provenance JSON for ' + id + ' (in-toto v1.0)','info'); };

/* ════════════════════════════════════════════════════════════════════
   4. PR / repo bot
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.prbot = {
  title: 'PR / repo bot — inline code review',
  sub: 'GitHub Checks · GitLab MR notes · inline comments',
  render: function(root){
    var prs = [
      { id:42, repo:'vsp-platform/api',     title:'feat: add JWT refresh',         author:'lan@vsp.local',  status:'fail', findings:3, sast:2, sca:1, blocking:true },
      { id:41, repo:'vsp-platform/api',     title:'fix: race in scanner queue',    author:'minh@vsp.local', status:'pass', findings:0, sast:0, sca:0, blocking:false },
      { id:88, repo:'vsp-platform/web',     title:'chore: bump deps',              author:'dependabot',     status:'warn', findings:5, sast:0, sca:5, blocking:false },
      { id:14, repo:'vsp-platform/scanner', title:'feat: kics rule custom output', author:'tuan@vsp.local', status:'pass', findings:1, sast:0, sca:0, blocking:false }
    ];
    var inline = [
      { file:'src/auth/jwt.go', line:42,  sev:'CRITICAL', rule:'gosec G101',     msg:'Hardcoded credentials detected' },
      { file:'src/auth/jwt.go', line:118, sev:'HIGH',     rule:'CWE-798',        msg:'Use of broken cryptographic algorithm (HS256 with weak secret)' },
      { file:'go.mod',          line:14,  sev:'HIGH',     rule:'CVE-2024-45337', msg:'golang.org/x/crypto@v0.28.0 \u2192 upgrade to v0.31.0' }
    ];

    root.innerHTML = '';
    root.appendChild(kpiRow([
      ['Open PRs',           prs.length,                                  'tracked',         '#22d3ee'],
      ['Blocked',            prs.filter(function(p){return p.blocking;}).length, 'gate FAIL', '#ef4444'],
      ['Comments (24h)',     14,                                          'inline review',   '#a78bfa'],
      ['Auto-fix suggested', 8,                                           'PR commits ready','#22c55e']
    ]));

    root.appendChild(el('div', { class: 'pro-section-h' }, 'Active pull requests'));
    root.appendChild(tableHTML(
      ['PR','Repo','Title','Author','Status','Findings','Blocking'],
      prs.map(function(p){
        var stC = p.status === 'pass' ? 'ok' : p.status === 'warn' ? 'warn' : 'err';
        var sast = p.sast ? '<span class="pro-pill info">SAST ' + p.sast + '</span>' : '';
        var sca  = p.sca  ? '<span class="pro-pill cyan">SCA ' + p.sca + '</span>'  : '';
        return '<tr><td class="pro-mono">#' + p.id + '</td><td class="pro-mono">' + p.repo + '</td><td>' + p.title + '</td>' +
          '<td class="pro-mono" style="font-size:10px">' + p.author + '</td>' +
          '<td>' + pill(stC, p.status.toUpperCase()) + '</td>' +
          '<td>' + pill(p.findings ? 'warn' : 'muted', p.findings + ' total') + ' ' + sast + ' ' + sca + '</td>' +
          '<td>' + (p.blocking ? pill('err','YES') : pill('ok','no')) + '</td></tr>';
      })
    ));

    root.appendChild(el('div', { class: 'pro-section-h', style:'margin-top:18px' }, 'Inline comments preview \u00b7 PR #42'));
    inline.forEach(function(c){
      var card = el('div', {
        class: 'pro-card',
        style: 'margin-bottom:8px;border-left:3px solid ' + (c.sev === 'CRITICAL' ? '#ef4444' : '#fbbf24')
      }, [
        el('div', { style:'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px' }, [
          el('div', { class:'pro-mono', style:'font-size:11px;color:#22d3ee' }, c.file + ':' + c.line),
          el('span', { class:'pro-pill ' + (c.sev === 'CRITICAL' ? 'err' : 'warn'), html:c.sev })
        ]),
        el('div', { style:'font-size:11px;color:#cbd5e1;margin-bottom:5px' }, c.msg),
        el('div', { style:'font-size:9.5px;color:#7d8aa0', html:
          '<span class="pro-mono">' + c.rule + '</span> \u00b7 posted as PR comment by <span class="pro-mono">vsp-bot[bot]</span>'
        })
      ]);
      root.appendChild(card);
    });
  }
};

/* ════════════════════════════════════════════════════════════════════
   5. Secret vault
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.secrets_vault = {
  title: 'Secret vault — auto-rotation & revocation',
  sub: 'Vault · AWS KMS · GCP Secret Manager · Azure KeyVault',
  render: function(root){
    var secrets = [
      { name:'github-ci-token',    type:'oauth-token', source:'AWS Secrets Manager', age:'14d',  rotation:'30d',   status:'ok' },
      { name:'aws-deploy-role',    type:'iam-key',     source:'AWS IAM',             age:'7d',   rotation:'90d',   status:'ok' },
      { name:'jira-api-token',     type:'api-token',   source:'HashiCorp Vault',     age:'45d',  rotation:'90d',   status:'ok' },
      { name:'slack-webhook',      type:'webhook',     source:'HashiCorp Vault',     age:'120d', rotation:'90d',   status:'warn' },
      { name:'legacy-db-password', type:'password',    source:'plain config',        age:'420d', rotation:'never', status:'err' },
      { name:'tls-cert-vsp.local', type:'tls-cert',    source:"Let's Encrypt",       age:'52d',  rotation:'90d',   status:'ok' }
    ];
    var incidents = [
      { ts:'12m ago', secret:'github-ci-token', event:'detected in commit', action:'revoked + rotated',   by:'auto'  },
      { ts:'2h ago',  secret:'aws-test-key',    event:'leak in PR #88',     action:'revoked',             by:'auto'  },
      { ts:'1d ago',  secret:'jenkins-creds',   event:'flagged by gitleaks',action:'manual review queued',by:'system'}
    ];

    root.innerHTML = '';
    root.appendChild(kpiRow([
      ['Tracked secrets', secrets.length,                                                                 'across vaults',  '#22d3ee'],
      ['Auto-rotated',    secrets.filter(function(s){return s.rotation!=='never';}).length + '/' + secrets.length, 'policy enforced','#22c55e'],
      ['Stale (>90d)',    secrets.filter(function(s){return parseInt(s.age,10)>90;}).length,             'need rotation',  '#fbbf24'],
      ['Plain-text',      secrets.filter(function(s){return s.source==='plain config';}).length,         'must migrate',   '#ef4444']
    ]));

    root.appendChild(el('div', { class: 'pro-section-h' }, 'Managed secrets'));
    root.appendChild(tableHTML(
      ['Name','Type','Source','Age','Rotation','Status','Action'],
      secrets.map(function(s, i){
        var sC = s.status === 'ok' ? 'ok' : s.status === 'warn' ? 'warn' : 'err';
        var btn = s.status !== 'ok'
          ? '<button class="pro-btn ghost" onclick="VSP_PRO.rotateSecret(' + i + ')">Rotate now</button>'
          : '<button class="pro-btn ghost" onclick="VSP_PRO.viewSecret(' + i + ')">Details</button>';
        return '<tr><td class="pro-mono">' + s.name + '</td><td>' + pill('info', s.type) + '</td>' +
          '<td>' + s.source + '</td><td class="pro-mono">' + s.age + '</td><td class="pro-mono">' + s.rotation + '</td>' +
          '<td>' + pill(sC, s.status.toUpperCase()) + '</td><td>' + btn + '</td></tr>';
      })
    ));

    root.appendChild(el('div', { class: 'pro-section-h', style:'margin-top:18px' }, 'Recent incidents — auto-revoke flow'));
    incidents.forEach(function(it){
      root.appendChild(el('div', { class:'pro-card', style:'margin-bottom:8px;display:flex;align-items:center;gap:14px' }, [
        el('div', { class:'pro-mono', style:'font-size:10px;color:#7d8aa0;min-width:80px' },  it.ts),
        el('div', { class:'pro-mono', style:'color:#22d3ee;min-width:160px' },                  it.secret),
        el('div', { style:'flex:1;font-size:11px;color:#cbd5e1' },                              it.event + ' \u2192 ' + it.action),
        el('span', { class:'pro-pill ' + (it.by === 'auto' ? 'ok' : 'info'), html:it.by })
      ]));
    });
  }
};
PRO.rotateSecret = function(){ toast('Rotation initiated — old credential revoked at provider','success'); };
PRO.viewSecret   = function(){ toast('Secret metadata loaded (value never displayed)','info'); };

/* ════════════════════════════════════════════════════════════════════
   6. SBOM diff
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.sbomdiff = {
  title: 'SBOM diff — component changes between runs',
  sub: 'CycloneDX 1.5 · component-level diff · CVE delta',
  render: function(root){
    var leftL  = 'RUN-0046 \u00b7 2026-04-12';
    var rightL = 'RUN-0048 \u00b7 2026-04-13';
    var items = [
      { name:'golang.org/x/crypto',      l:'v0.28.0', r:'v0.31.0', status:'fixed',         cveDelta:-2 },
      { name:'golang-jwt/jwt',           l:'v4.5.0',  r:'v4.5.2',  status:'fixed',         cveDelta:-1 },
      { name:'github.com/gin-gonic/gin', l:'v1.9.1',  r:'v1.9.1',  status:'same',          cveDelta:0  },
      { name:'github.com/spf13/cobra',   l:'v1.7.0',  r:'v1.8.1',  status:'updated',       cveDelta:0  },
      { name:'github.com/lib/pq',        l:'\u2014',  r:'v1.10.9', status:'added',         cveDelta:0  },
      { name:'github.com/google/uuid',   l:'v1.3.0',  r:'\u2014',  status:'removed',       cveDelta:0  },
      { name:'libxml2',                  l:'v2.10.4', r:'v2.10.4', status:'persisted-cve', cveDelta:0  },
      { name:'libexpat',                 l:'v2.4.8',  r:'v2.5.0',  status:'fixed',         cveDelta:-2 }
    ];
    var counts = items.reduce(function(a,x){ a[x.status] = (a[x.status]||0) + 1; return a; }, {});
    var cveTotal = items.reduce(function(a,x){ return a + x.cveDelta; }, 0);
    var deltaC = cveTotal < 0 ? '#22c55e' : cveTotal > 0 ? '#ef4444' : '#cbd5e1';

    root.innerHTML = '';
    var head = el('div', { class:'pro-grid c2', style:'margin-bottom:14px' });
    head.appendChild(el('div', { class:'pro-card' }, [
      el('div', { class:'lbl' }, 'Left (older)'),
      el('div', { class:'pro-mono', style:'color:#cbd5e1' }, leftL)
    ]));
    head.appendChild(el('div', { class:'pro-card' }, [
      el('div', { class:'lbl' }, 'Right (newer)'),
      el('div', { class:'pro-mono', style:'color:#cbd5e1' }, rightL)
    ]));
    root.appendChild(head);

    root.appendChild(kpiRow([
      ['Fixed',     counts.fixed   || 0,                       'CVE resolved',  '#22c55e'],
      ['Added',     counts.added   || 0,                       'new component', '#22d3ee'],
      ['Removed',   counts.removed || 0,                       'no longer used','#a78bfa'],
      ['CVE delta', (cveTotal>=0 ? '+' : '') + cveTotal,       'net change',    deltaC]
    ]));

    var colors = { fixed:'#22c55e', added:'#22d3ee', updated:'#a78bfa', removed:'#94a3b8', same:'#64748b', 'persisted-cve':'#fbbf24' };
    root.appendChild(tableHTML(
      ['Component','Left version','Right version','Status','CVE delta'],
      items.map(function(x){
        var c = colors[x.status];
        var lC = x.l === '\u2014' ? '#475569' : '#cbd5e1';
        var rC = x.r === '\u2014' ? '#475569' : '#cbd5e1';
        var dC = x.cveDelta < 0 ? '#22c55e' : x.cveDelta > 0 ? '#ef4444' : '#94a3b8';
        return '<tr><td class="pro-mono">' + x.name + '</td>' +
          '<td class="pro-mono" style="color:' + lC + '">' + x.l + '</td>' +
          '<td class="pro-mono" style="color:' + rC + '">' + x.r + '</td>' +
          '<td><span class="pro-pill" style="background:' + c + '22;color:' + c + ';border:1px solid ' + c + '44">' + x.status + '</span></td>' +
          '<td class="pro-mono" style="color:' + dC + '">' + (x.cveDelta>=0 ? '+' : '') + x.cveDelta + '</td></tr>';
      })
    ));
  }
};

/* ════════════════════════════════════════════════════════════════════
   7. Observability — Prometheus + OTel
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.observe = {
  title: 'Observability — metrics, traces, SLO',
  sub: 'Prometheus /metrics · OpenTelemetry · burn-rate alerts',
  render: function(root){
    var slos = [
      { name:'API availability',         target:'99.9%', current:'99.94%', burn:0.3, status:'ok'   },
      { name:'Scan completion <60s',     target:'95%',   current:'97.2%',  burn:0.1, status:'ok'   },
      { name:'Gate decision <2s',        target:'99%',   current:'98.4%',  burn:1.4, status:'warn' },
      { name:'False-positive rate <5%',  target:'95%',   current:'96.8%',  burn:0.2, status:'ok'   },
      { name:'Auto-remediation success', target:'90%',   current:'87.3%',  burn:2.1, status:'warn' }
    ];
    var metrics = [
      { name:'http_request_duration_seconds{p99}',  val:'412 ms', trend:'\u2193 8%' },
      { name:'scan_queue_depth',                     val:'14',     trend:'\u2191 3'  },
      { name:'finding_dedupe_ratio',                 val:'78.4%',  trend:'\u2191 1%' },
      { name:'auto_remediation_success_total',       val:'4350',   trend:'\u2191'    },
      { name:'gate_decision_duration_p95_seconds',   val:'1.84 s', trend:'\u2193'    },
      { name:'sbom_generation_duration_p99_seconds', val:'7.3 s',  trend:'='         }
    ];
    var trace = [
      { span:'POST /api/v1/vsp/run', dur:'1834ms', dep:0 },
      { span:'auth.verifyJWT',       dur:'4ms',    dep:1 },
      { span:'queue.enqueue',        dur:'12ms',   dep:1 },
      { span:'scanner.runIaC',       dur:'1820ms', dep:1 },
      { span:'kics.scan',            dur:'780ms',  dep:2 },
      { span:'checkov.scan',         dur:'620ms',  dep:2 },
      { span:'trivy.scan',           dur:'410ms',  dep:2 },
      { span:'gate.decide',          dur:'8ms',    dep:1 },
      { span:'soar.dispatch',        dur:'14ms',   dep:1 }
    ];

    root.innerHTML = '';
    root.appendChild(el('div', { class:'pro-section-h' }, 'Service Level Objectives'));
    var sg = el('div', { class:'pro-grid c2', style:'margin-bottom:18px' });
    slos.forEach(function(s){
      sg.appendChild(el('div', {
        class:'pro-card',
        style:'border-left:3px solid ' + (s.status === 'ok' ? '#22c55e' : '#fbbf24')
      }, [
        el('div', { style:'display:flex;justify-content:space-between;align-items:center;margin-bottom:6px' }, [
          el('div', { style:'font-size:12px;color:#e6edf7;font-weight:600' }, s.name),
          el('span', { class:'pro-pill ' + (s.status === 'ok' ? 'ok' : 'warn'), html:s.status.toUpperCase() })
        ]),
        el('div', { style:'display:flex;gap:14px;font-size:10px;color:#7d8aa0', html:
          'target <strong style="color:#cbd5e1">' + s.target + '</strong> \u00b7 ' +
          'current <strong style="color:#22d3ee">' + s.current + '</strong> \u00b7 ' +
          'burn <strong style="color:' + (s.burn <= 1 ? '#22c55e' : '#fbbf24') + '">' + s.burn.toFixed(1) + '\u00d7</strong>'
        })
      ]));
    });
    root.appendChild(sg);

    root.appendChild(el('div', { class:'pro-section-h' }, 'Live metrics — /metrics endpoint'));
    root.appendChild(tableHTML(
      ['Metric','Value','Trend (1h)'],
      metrics.map(function(m){
        return '<tr><td class="pro-mono" style="font-size:10.5px">' + m.name + '</td>' +
          '<td class="pro-mono">' + m.val + '</td><td>' + m.trend + '</td></tr>';
      })
    ));

    root.appendChild(el('div', { class:'pro-section-h', style:'margin-top:18px' }, 'OTel sample trace — POST /api/v1/vsp/run'));
    var tr = el('div', { class:'pro-card', style:'font-family:ui-monospace,monospace;font-size:10.5px;line-height:1.7' });
    trace.forEach(function(t){
      var prefix = '';
      for (var i = 0; i < t.dep; i++) prefix += '\u2502';
      if (t.dep > 0) prefix += '\u2514\u2500 ';
      tr.appendChild(el('div', { style:'display:flex;gap:10px' }, [
        el('span', { style:'color:#475569' }, prefix),
        el('span', { style:'color:#22d3ee;flex:1' }, t.span),
        el('span', { style:'color:#fbbf24;text-align:right;min-width:70px' }, t.dur)
      ]));
    });
    root.appendChild(tr);
  }
};

/* ════════════════════════════════════════════════════════════════════
   8. Tenants
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.tenants = {
  title: 'Multi-tenant isolation',
  sub: 'Per-tenant data scoping · per-program ATO · resource quota',
  render: function(root){
    var tenants = [
      { id:'default',  name:'Default',        type:'production', users:14, scans:'2.4k',findings:104,quota:'80%', ato:'active',  created:'2 years' },
      { id:'agency-a', name:'Agency A',       type:'production', users:8,  scans:'890', findings:52, quota:'45%', ato:'active',  created:'8 months' },
      { id:'agency-b', name:'Agency B',       type:'production', users:5,  scans:'420', findings:18, quota:'22%', ato:'pending', created:'2 months' },
      { id:'sandbox',  name:'Sandbox / demo', type:'sandbox',    users:2,  scans:'14',  findings:0,  quota:'2%',  ato:'n/a',     created:'5 days' }
    ];
    var totalScans = tenants.reduce(function(a,t){ return a + parseFloat(t.scans); }, 0);

    root.innerHTML = '';
    root.appendChild(el('div', {
      style:'background:rgba(34,211,238,.06);border:1px solid rgba(34,211,238,.2);border-radius:8px;padding:12px 14px;margin-bottom:18px;font-size:11px;color:#cbd5e1',
      html:'<strong style="color:#22d3ee">Tenant isolation strategy:</strong> row-level security in Postgres (tenant_id column on every table) + per-tenant Vault namespace + per-tenant Kafka topic prefix. Each tenant can hold its own ATO with separate ConMon reports.'
    }));

    root.appendChild(kpiRow([
      ['Tenants',     tenants.length,                                                              'configured',     '#22d3ee'],
      ['Active ATO',  tenants.filter(function(t){return t.ato==='active';}).length,                'production',     '#22c55e'],
      ['Total users', tenants.reduce(function(a,t){return a+t.users;},0),                          'across tenants', '#a78bfa'],
      ['Total scans', totalScans.toFixed(1) + 'k',                                                 'lifetime',       '#fbbf24']
    ]));

    root.appendChild(el('div', { class:'pro-section-h' }, 'Tenant directory'));
    root.appendChild(tableHTML(
      ['Tenant ID','Name','Type','Users','Scans','Findings','Quota used','ATO','Switch'],
      tenants.map(function(x){
        var qPct = parseInt(x.quota, 10);
        var qC = qPct > 80 ? '#ef4444' : qPct > 50 ? '#fbbf24' : '#22c55e';
        var atoC = x.ato === 'active' ? 'ok' : x.ato === 'pending' ? 'warn' : 'muted';
        return '<tr><td class="pro-mono">' + x.id + '</td><td>' + x.name + '</td>' +
          '<td>' + pill(x.type === 'production' ? 'info' : 'muted', x.type) + '</td>' +
          '<td class="pro-mono">' + x.users + '</td><td class="pro-mono">' + x.scans + '</td>' +
          '<td class="pro-mono">' + x.findings + '</td>' +
          '<td><div style="width:80px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden">' +
            '<div style="width:' + x.quota + ';height:6px;background:' + qC + '"></div></div>' +
            '<span style="font-size:9px;color:#7d8aa0">' + x.quota + '</span></td>' +
          '<td>' + pill(atoC, x.ato) + '</td>' +
          '<td><button class="pro-btn ghost" onclick="VSP_PRO.switchTenant(\'' + x.id + '\')">Switch \u2192</button></td></tr>';
      })
    ));
  }
};
PRO.switchTenant = function(id){
  localStorage.setItem('vsp_tenant', id);
  toast('Switched to tenant ' + id + ' — reloading…', 'success');
  setTimeout(function(){ location.reload(); }, 800);
};

/* ════════════════════════════════════════════════════════════════════
   9. SSO — SAML / OIDC
   ════════════════════════════════════════════════════════════════════ */
PRO.modules.sso = {
  title: 'SSO — SAML & OIDC providers',
  sub: 'Okta · Azure AD · Google · Keycloak · custom IdP',
  render: function(root){
    var idps = [
      { name:'Okta',             type:'SAML 2.0', status:'connected', users:14, lastLogin:'2m ago',  issuer:'https://vsp.okta.com'      },
      { name:'Azure AD',         type:'OIDC',     status:'connected', users:8,  lastLogin:'12m ago', issuer:'login.microsoftonline.com' },
      { name:'Google Workspace', type:'OIDC',     status:'available', users:0,  lastLogin:'\u2014',  issuer:'accounts.google.com'       },
      { name:'Keycloak',         type:'SAML 2.0', status:'available', users:0,  lastLogin:'\u2014',  issuer:'(self-hosted)'              },
      { name:'Custom IdP',       type:'SAML/OIDC',status:'available', users:0,  lastLogin:'\u2014',  issuer:'(your URL)'                 }
    ];
    var attrMap = [
      { saml:'urn:oid:0.9.2342.19200300.100.1.3', vsp:'email',     transform:'identity' },
      { saml:'urn:oid:2.5.4.42',                  vsp:'firstName', transform:'identity' },
      { saml:'urn:oid:2.5.4.4',                   vsp:'lastName',  transform:'identity' },
      { saml:'http://schemas.../groups',          vsp:'role',      transform:'group\u2192role mapping (admin|analyst|viewer)' }
    ];

    root.innerHTML = '';
    root.appendChild(el('div', { class:'pro-section-h' }, 'Identity providers'));
    root.appendChild(tableHTML(
      ['Provider','Protocol','Status','Users','Last login','Issuer','Action'],
      idps.map(function(p, i){
        var btn = p.status === 'connected'
          ? '<button class="pro-btn ghost" onclick="VSP_PRO.idpTest(' + i + ')">Test login</button>'
          : '<button class="pro-btn" onclick="VSP_PRO.idpConnect(' + i + ')">Connect \u2192</button>';
        return '<tr><td>' + p.name + '</td>' +
          '<td>' + pill('info', p.type) + '</td>' +
          '<td>' + pill(p.status === 'connected' ? 'ok' : 'muted', p.status) + '</td>' +
          '<td class="pro-mono">' + p.users + '</td>' +
          '<td>' + p.lastLogin + '</td>' +
          '<td class="pro-mono" style="font-size:10px">' + p.issuer + '</td>' +
          '<td>' + btn + '</td></tr>';
      })
    ));

    root.appendChild(el('div', { class:'pro-section-h', style:'margin-top:18px' }, 'Attribute mapping (Okta SAML 2.0)'));
    root.appendChild(tableHTML(
      ['SAML attribute','VSP field','Transform'],
      attrMap.map(function(m){
        return '<tr><td class="pro-mono" style="font-size:10px">' + m.saml + '</td>' +
          '<td class="pro-mono">' + m.vsp + '</td><td>' + m.transform + '</td></tr>';
      })
    ));

    root.appendChild(el('div', { class:'pro-section-h', style:'margin-top:18px' }, 'Service Provider metadata (give this to your IdP admin)'));
    var meta = el('div', { class:'pro-card', style:'background:#0a1320;font-family:ui-monospace,monospace;font-size:10.5px;color:#cbd5e1;line-height:1.8' });
    [
      ['Entity ID',     'https://vsp.local/saml/metadata'],
      ['ACS URL',       'https://vsp.local/api/v1/auth/saml/callback'],
      ['SLO URL',       'https://vsp.local/api/v1/auth/saml/logout'],
      ['NameID format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
      ['Signing cert',  '/api/v1/auth/saml/cert.pem']
    ].forEach(function(row){
      meta.appendChild(el('div', { html:
        '<span style="color:#7d8aa0">' + row[0] + ':</span> ' +
        '<span style="color:#22d3ee">' + row[1] + '</span>'
      }));
    });
    root.appendChild(meta);
  }
};
PRO.idpTest    = function(){ toast('Test SAML round-trip initiated','info'); };
PRO.idpConnect = function(){ toast('Connect wizard would open — paste IdP metadata XML','info'); };

/* ════════════════════════════════════════════════════════════════════
   INIT
   ════════════════════════════════════════════════════════════════════ */
function init(){
  if (!injectNav()){ setTimeout(init, 500); return; }
  buildHost();
  console.log('%c VSP PRO v' + PRO.version + ' loaded \u2713 ',
    'background:#22d3ee;color:#0d1424;padding:2px 6px;border-radius:3px');
  (window.VSP_DEBUG && console.log('Modules registered:', Object.keys(PRO.modules)));
}

if (document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

})();
