#!/usr/bin/env bash
# ============================================================
#  VSP SIEM — Deploy script
#  Usage: bash vsp_siem_deploy.sh [target_dir]
#  Default target: ./static/panels
# ============================================================
set -euo pipefail

TARGET="${1:-./static/panels}"
mkdir -p "$TARGET"

echo "▶ Deploying VSP SIEM panels to $TARGET"

# ── SOAR Playbook Engine ─────────────────────────────────────
cat > "$TARGET/soar.html" << 'SOAR_EOF'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VSP — SOAR</title>
<style>
:root{--bg:#0a0c10;--bg2:#111318;--surface:#1e2128;--border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.12);--t1:#e8eaf0;--t2:#9aa3b8;--t3:#5a6278;--t4:#3a3f52;--red:#ef4444;--red2:rgba(239,68,68,0.12);--amber:#f59e0b;--amber2:rgba(245,158,11,0.12);--green:#22c55e;--green2:rgba(34,197,94,0.12);--blue:#3b82f6;--blue2:rgba(59,130,246,0.12);--cyan:#06b6d4;--cyan2:rgba(6,182,212,0.12);--purple:#8b5cf6;--purple2:rgba(139,92,246,0.12);--orange:#f97316;--orange2:rgba(249,115,22,0.12);--font-mono:'JetBrains Mono','Fira Mono',monospace;--font-ui:'Inter','Segoe UI',sans-serif}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:13px}
body{background:var(--bg);color:var(--t1);font-family:var(--font-ui);line-height:1.5;min-height:100vh}
.app{display:grid;grid-template-rows:52px 1fr;height:100vh;overflow:hidden}
.topbar{border-bottom:1px solid var(--border);background:var(--bg2);display:flex;align-items:center;padding:0 20px;gap:16px}
.topbar-title{font-size:15px;font-weight:700;letter-spacing:-.02em}
.topbar-sub{font-size:11px;color:var(--t3);font-family:var(--font-mono)}
.topbar-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.main{display:grid;grid-template-columns:300px 1fr;overflow:hidden}
.sidebar{border-right:1px solid var(--border);background:var(--bg2);overflow-y:auto;padding:10px}
.content{overflow-y:auto;padding:16px;background:var(--bg)}
.pill{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-family:var(--font-mono);padding:2px 7px;border-radius:3px;font-weight:600;border:1px solid transparent}
.pill-red{background:var(--red2);color:var(--red);border-color:rgba(239,68,68,.25)}
.pill-amber{background:var(--amber2);color:var(--amber);border-color:rgba(245,158,11,.25)}
.pill-green{background:var(--green2);color:var(--green);border-color:rgba(34,197,94,.25)}
.pill-blue{background:var(--blue2);color:var(--blue);border-color:rgba(59,130,246,.25)}
.pill-cyan{background:var(--cyan2);color:var(--cyan);border-color:rgba(6,182,212,.25)}
.pill-purple{background:var(--purple2);color:var(--purple);border-color:rgba(139,92,246,.25)}
.pill-gray{background:rgba(255,255,255,.06);color:var(--t2);border-color:var(--border2)}
.btn{font-size:11px;font-weight:500;padding:5px 12px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t1);cursor:pointer;transition:background .15s}
.btn:hover{background:var(--surface)}
.btn-primary{background:var(--blue2);border-color:rgba(59,130,246,.4);color:var(--blue)}
.btn-primary:hover{background:rgba(59,130,246,.2)}
.btn-run{background:var(--purple2);border-color:rgba(139,92,246,.4);color:var(--purple)}
.btn-run:hover{background:rgba(139,92,246,.2)}
.btn-danger{background:var(--red2);border-color:rgba(239,68,68,.4);color:var(--red)}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:12px}
.card-head{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--border)}
.card-title{font-size:12px;font-weight:600;letter-spacing:.02em}
.card-body{padding:12px 14px}
.pb-item{padding:10px 11px;border-radius:8px;margin-bottom:6px;border:1px solid transparent;cursor:pointer;transition:background .15s,border-color .15s;position:relative}
.pb-item:hover{background:var(--surface);border-color:var(--border)}
.pb-item.active{background:var(--surface);border-color:var(--blue)}
.pb-item-name{font-size:12px;font-weight:600;margin-bottom:3px}
.pb-item-desc{font-size:11px;color:var(--t3);margin-bottom:6px;line-height:1.4}
.pb-item-meta{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.pb-dot{width:6px;height:6px;border-radius:50%;position:absolute;top:12px;right:12px}
.step-wrap{position:relative;padding-left:28px;margin-bottom:4px}
.step-line{position:absolute;left:10px;top:28px;bottom:-4px;width:1px;background:var(--border)}
.step-dot-num{position:absolute;left:5px;top:10px;width:11px;height:11px;border-radius:50%;border:2px solid var(--border2);background:var(--bg);display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:700;color:var(--t3)}
.step-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px;transition:border-color .15s}
.step-card.running{border-color:var(--blue);animation:pb 1.5s infinite}
.step-card.done{border-color:var(--green)}
.step-card.failed{border-color:var(--red)}
.step-card.skip{opacity:.4}
@keyframes pb{0%,100%{border-color:var(--blue)}50%{border-color:rgba(59,130,246,.3)}}
.step-hdr{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.step-type{font-size:9px;font-family:var(--font-mono);padding:1px 5px;border-radius:3px}
.step-name{font-size:12px;font-weight:600;flex:1}
.step-desc{font-size:11px;color:var(--t3);margin-bottom:6px}
.step-config{font-size:10px;font-family:var(--font-mono);color:var(--t3);background:var(--bg);padding:6px 8px;border-radius:5px;border:1px solid var(--border);white-space:pre-wrap;word-break:break-all}
.step-out{font-size:10px;font-family:var(--font-mono);background:var(--bg);padding:6px 8px;border-radius:5px;border:1px solid var(--border);margin-top:6px;color:var(--green);white-space:pre-wrap;display:none}
.step-out.show{display:block}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:11px 13px}
.stat-lbl{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.stat-val{font-size:22px;font-weight:700;font-family:var(--font-mono)}
.stat-sub{font-size:10px;color:var(--t3);margin-top:2px}
.run-item{display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid var(--border);font-size:11px;cursor:pointer;transition:background .12s}
.run-item:hover{background:var(--surface)}
.run-item:last-child{border-bottom:none}
.run-id{font-family:var(--font-mono);color:var(--t3);font-size:10px;flex-shrink:0;width:90px}
.run-pb{flex:1;font-weight:500}
.run-ts{font-family:var(--font-mono);font-size:10px;color:var(--t3)}
.run-dur{font-family:var(--font-mono);font-size:10px;color:var(--t3);width:44px;text-align:right}
.form-group{margin-bottom:10px}
.form-label{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;display:block}
.form-ctrl{width:100%;background:var(--bg);border:1px solid var(--border2);color:var(--t1);padding:6px 9px;border-radius:6px;font-size:12px;font-family:var(--font-ui);outline:none;transition:border-color .15s}
.form-ctrl:focus{border-color:var(--blue)}
select.form-ctrl option{background:var(--bg2)}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:12px;width:min(520px,95vw);max-height:85vh;overflow-y:auto}
.modal-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border)}
.modal-title{font-size:14px;font-weight:700}
.modal-body{padding:16px}
.modal-footer{padding:12px 16px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end}
.modal-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;padding:2px}
.run-log{font-size:10px;font-family:var(--font-mono);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px;max-height:180px;overflow-y:auto;line-height:1.7}
.ll{display:flex;gap:8px}
.ll-ts{color:var(--t4);flex-shrink:0}
.ll-INFO{color:var(--cyan)}.ll-DONE{color:var(--green)}.ll-ERROR{color:var(--red)}.ll-WARN{color:var(--amber)}.ll-SKIP{color:var(--t4)}
.slbl{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.08em;font-family:var(--font-mono);margin:14px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.spinner{width:14px;height:14px;border-radius:50%;border:2px solid var(--border2);border-top-color:var(--blue);animation:spin .6s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.trig-chip{display:inline-flex;align-items:center;gap:5px;font-size:10px;font-family:var(--font-mono);padding:3px 8px;border-radius:4px;background:var(--surface);border:1px solid var(--border2);color:var(--t2);margin:2px}
</style>
</head>
<body>
<div class="app">
<header class="topbar">
  <div>
    <div class="topbar-title">SOAR — Playbook engine</div>
    <div class="topbar-sub">Security orchestration, automation &amp; response · VSP v2.0</div>
  </div>
  <div class="topbar-right">
    <span class="pill pill-green">&#9679; Engine live</span>
    <button class="btn btn-primary" onclick="openNewPlaybook()">+ New playbook</button>
  </div>
</header>
<div class="main">
<aside class="sidebar">
  <div class="slbl" style="margin-top:4px">Playbooks</div>
  <div id="pb-list"></div>
</aside>
<div class="content">
  <div class="stat-grid">
    <div class="stat-card"><div class="stat-lbl">Total</div><div class="stat-val" id="s-total">6</div><div class="stat-sub">4 enabled</div></div>
    <div class="stat-card"><div class="stat-lbl">Runs today</div><div class="stat-val" style="color:var(--cyan)" id="s-runs">12</div><div class="stat-sub">live</div></div>
    <div class="stat-card"><div class="stat-lbl">Success rate</div><div class="stat-val" style="color:var(--green)" id="s-rate">91%</div><div class="stat-sub">30 days</div></div>
    <div class="stat-card"><div class="stat-lbl">Avg response</div><div class="stat-val" style="color:var(--amber)" id="s-mtr">38s</div><div class="stat-sub">time to action</div></div>
  </div>
  <div id="detail-panel"><div style="text-align:center;padding:40px;color:var(--t3);font-size:12px">&#8592; Select a playbook</div></div>
  <div class="card" id="run-history-card">
    <div class="card-head"><div class="card-title">Run history</div><button class="btn" onclick="loadRunHistory()">&#8635; Refresh</button></div>
    <div id="run-history"></div>
  </div>
</div>
</div>
</div>

<div class="modal-overlay" id="new-pb-modal">
  <div class="modal">
    <div class="modal-head"><div class="modal-title">New playbook</div><button class="modal-close" onclick="closeModal('new-pb-modal')">&#10005;</button></div>
    <div class="modal-body">
      <div class="form-group"><label class="form-label">Name</label><input class="form-ctrl" id="np-name" placeholder="e.g. Gate FAIL auto-response"></div>
      <div class="form-group"><label class="form-label">Description</label><input class="form-ctrl" id="np-desc" placeholder="What does this playbook do?"></div>
      <div class="form-group"><label class="form-label">Trigger event</label>
        <select class="form-ctrl" id="np-trigger">
          <option value="gate_fail">Gate FAIL</option>
          <option value="critical_finding">Critical finding detected</option>
          <option value="sla_breach">SLA breach</option>
          <option value="secret_detected">Secret/credential detected</option>
          <option value="score_drop">Score drop &gt; 20</option>
          <option value="manual">Manual only</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label">Severity filter</label>
        <select class="form-ctrl" id="np-sev">
          <option value="any">Any severity</option>
          <option value="CRITICAL">Critical only</option>
          <option value="HIGH">High and above</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label">Template</label>
        <select class="form-ctrl" id="np-template">
          <option value="notify">Notify only (Slack + email)</option>
          <option value="ticket">Create Jira ticket</option>
          <option value="block">Block CI pipeline</option>
          <option value="full">Full response (notify + ticket + block)</option>
          <option value="custom">Custom (empty)</option>
        </select>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeModal('new-pb-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="createPlaybook()">Create &#8594;</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="run-modal">
  <div class="modal">
    <div class="modal-head"><div class="modal-title" id="run-modal-title">Run playbook</div><button class="modal-close" onclick="closeModal('run-modal')">&#10005;</button></div>
    <div class="modal-body">
      <div class="form-group"><label class="form-label">Context (JSON)</label>
        <textarea class="form-ctrl" id="run-ctx" rows="4" style="resize:vertical;font-family:var(--font-mono);font-size:11px">{"trigger":"manual","severity":"CRITICAL","finding_id":"38c5ee0d","run_id":"RID_SCHED_20260329_194714_0"}</textarea>
      </div>
      <div id="run-modal-log" style="display:none;margin-top:10px">
        <div class="slbl" style="margin-top:0">Execution log</div>
        <div class="run-log" id="run-log-output"></div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeModal('run-modal')">Close</button>
      <button class="btn btn-run" id="run-btn" onclick="executePlaybook()">&#9654; Execute</button>
    </div>
  </div>
</div>

<script>
const STEP_TYPES={condition:{label:'Condition',color:'var(--amber)',bg:'rgba(245,158,11,.12)'},notify:{label:'Notify',color:'var(--cyan)',bg:'rgba(6,182,212,.12)'},ticket:{label:'Ticket',color:'var(--purple)',bg:'rgba(139,92,246,.12)'},webhook:{label:'Webhook',color:'var(--blue)',bg:'rgba(59,130,246,.12)'},block:{label:'Block CI',color:'var(--red)',bg:'rgba(239,68,68,.12)'},enrich:{label:'Enrich',color:'var(--green)',bg:'rgba(34,197,94,.12)'},wait:{label:'Wait',color:'var(--t3)',bg:'rgba(255,255,255,.05)'},remediate:{label:'Remediate',color:'var(--orange)',bg:'rgba(249,115,22,.12)'}};
const TPLS={notify:[{type:'condition',name:'Check severity',desc:'Proceed if severity ≥ threshold',config:'severity IN [CRITICAL, HIGH]'},{type:'notify',name:'Slack alert',desc:'Post to #security-alerts',config:'channel: #security-alerts\nmsg: "{{severity}} in {{run_id}}: {{message}}"'},{type:'notify',name:'Email SOC',desc:'Send email to soc@agency.gov',config:'to: soc@agency.gov\nsubject: "[VSP ALERT] {{severity}} — {{rule_id}}"'}],ticket:[{type:'condition',name:'Check ticket exists',desc:'Skip if already open',config:'existing_ticket = null'},{type:'enrich',name:'Fetch CVE details',desc:'Pull CVSS, EPSS from NVD',config:'source: NVD\nfields: [cvss, epss, kev, vector]'},{type:'ticket',name:'Create Jira ticket',desc:'Open in VSP-SECURITY',config:'project: VSP-SECURITY\npriority: P1\nlabels: [security, automated]'}],block:[{type:'condition',name:'Gate is FAIL',desc:'Only block on FAIL',config:'gate = FAIL'},{type:'block',name:'Block CI pipeline',desc:'Set pipeline to failed via API',config:'provider: github\nstatus: failure\ncontext: vsp/gate\ndescription: "Gate FAIL — {{total_findings}} findings"'},{type:'notify',name:'Notify developer',desc:'Comment on PR',config:'target: pr_comment\nbody: "🚨 Gate FAIL — {{critical}} critical findings."'}],full:[{type:'condition',name:'Check gate + severity',desc:'FAIL with CRITICAL/HIGH',config:'gate = FAIL AND severity IN [CRITICAL, HIGH]'},{type:'enrich',name:'Enrich findings',desc:'Add CVE context, EPSS scores',config:'source: NVD,OSV\nfields: [cvss, epss, kev]'},{type:'block',name:'Block CI pipeline',desc:'Fail the pipeline check',config:'provider: github\nstatus: failure\ncontext: vsp/gate'},{type:'ticket',name:'Create Jira ticket',desc:'Open P1 ticket',config:'project: VSP-SECURITY\npriority: P1\nauto_assign: security-team'},{type:'notify',name:'Slack — critical',desc:'Alert #security-alerts',config:'channel: #security-alerts\nping: @security-oncall'},{type:'notify',name:'Email leadership',desc:'Send exec summary to CISO',config:'to: ciso@agency.gov\ntemplate: executive_summary'},{type:'remediate',name:'Auto-assign findings',desc:'Assign to on-call',config:'assignee: security-oncall\npriority: P1\nstatus: in_progress'}],custom:[]};
let PLAYBOOKS=[{id:'pb-001',name:'Gate FAIL auto-response',enabled:true,trigger:'gate_fail',sev:'any',desc:'Full automated response: block CI, create ticket, notify team',steps:TPLS.full.map((s,i)=>({...s,id:'s'+i,status:'idle'})),runs:47,success:44,last:'2m ago',tags:['ci','jira','slack','email']},{id:'pb-002',name:'Critical finding notify',enabled:true,trigger:'critical_finding',sev:'CRITICAL',desc:'Immediate Slack + email on critical finding',steps:TPLS.notify.map((s,i)=>({...s,id:'s'+i,status:'idle'})),runs:12,success:12,last:'18m ago',tags:['slack','email']},{id:'pb-003',name:'SLA breach escalation',enabled:true,trigger:'sla_breach',sev:'any',desc:'Escalate to leadership on SLA breach',steps:[{id:'s0',type:'condition',name:'Check breach duration',desc:'Escalate only if >24h',config:'breach_age > 24h',status:'idle'},{id:'s1',type:'ticket',name:'Create escalation ticket',desc:'P0 ticket in VSP-ESCALATION',config:'project: VSP-ESCALATION\npriority: P0',status:'idle'},{id:'s2',type:'notify',name:'Email CISO',desc:'Escalation notice',config:'to: [ciso@agency.gov, director@agency.gov]',status:'idle'}],runs:3,success:3,last:'2h ago',tags:['email','jira']},{id:'pb-004',name:'Secret detection lockdown',enabled:true,trigger:'secret_detected',sev:'CRITICAL',desc:'Credentials found: block CI, create P0 ticket, page on-call',steps:[{id:'s0',type:'block',name:'Block all pipelines',desc:'Immediately fail all CI',config:'scope: repo\nstatus: failure',status:'idle'},{id:'s1',type:'ticket',name:'Create P0 ticket',desc:'Urgent ticket for credential rotation',config:'project: VSP-SECURITY\npriority: P0\nlabels: [credential-leak]',status:'idle'},{id:'s2',type:'notify',name:'Page on-call',desc:'PagerDuty alert',config:'service: pagerduty\nseverity: critical',status:'idle'},{id:'s3',type:'webhook',name:'Trigger rotation',desc:'Call secrets management API',config:'url: https://vault.internal/v1/rotate\nmethod: POST',status:'idle'}],runs:2,success:2,last:'3h ago',tags:['ci','pagerduty','vault']},{id:'pb-005',name:'Score drop alert',enabled:false,trigger:'score_drop',sev:'any',desc:'Alert when score drops >20 points',steps:TPLS.notify.map((s,i)=>({...s,id:'s'+i,status:'idle'})),runs:0,success:0,last:'never',tags:['slack']},{id:'pb-006',name:'Jira-only triage',enabled:false,trigger:'gate_fail',sev:'HIGH',desc:'Create Jira ticket only for low-priority fails',steps:TPLS.ticket.map((s,i)=>({...s,id:'s'+i,status:'idle'})),runs:8,success:7,last:'1d ago',tags:['jira']}];
const RUN_HISTORY=[{id:'RUN-0048',pb:'Gate FAIL auto-response',status:'success',ts:'19:47:32',dur:'12s',trigger:'gate_fail'},{id:'RUN-0047',pb:'Critical finding notify',status:'success',ts:'19:31:14',dur:'4s',trigger:'critical_finding'},{id:'RUN-0046',pb:'Gate FAIL auto-response',status:'success',ts:'17:16:44',dur:'15s',trigger:'gate_fail'},{id:'RUN-0045',pb:'Secret detection lockdown',status:'success',ts:'16:52:01',dur:'8s',trigger:'secret_detected'},{id:'RUN-0044',pb:'Gate FAIL auto-response',status:'failed',ts:'16:34:22',dur:'31s',trigger:'gate_fail'},{id:'RUN-0043',pb:'SLA breach escalation',status:'success',ts:'14:10:05',dur:'6s',trigger:'sla_breach'},{id:'RUN-0042',pb:'Jira-only triage',status:'success',ts:'12:48:33',dur:'9s',trigger:'gate_fail'},{id:'RUN-0041',pb:'Critical finding notify',status:'success',ts:'11:22:17',dur:'3s',trigger:'critical_finding'}];
let activePB=null,isRunning=false;
const TL=t=>({gate_fail:'Gate FAIL',critical_finding:'Critical finding',sla_breach:'SLA breach',secret_detected:'Secret detected',score_drop:'Score drop',manual:'Manual'}[t]||t);
const ST=(s)=>({running:'<div class="spinner" style="display:inline-block;vertical-align:middle;width:12px;height:12px"></div>',done:'&#10003;',failed:'&#10007;',skip:'&#8594;',idle:''}[s]||'');
function renderList(){document.getElementById('pb-list').innerHTML=PLAYBOOKS.map(pb=>`<div class="pb-item ${activePB?.id===pb.id?'active':''}" onclick="selectPB('${pb.id}')"><div class="pb-dot" style="background:${pb.enabled?'var(--green)':'var(--t4)'}"></div><div class="pb-item-name">${pb.name}</div><div class="pb-item-desc">${pb.desc}</div><div class="pb-item-meta"><span class="pill ${pb.enabled?'pill-green':'pill-gray'}">${pb.enabled?'enabled':'disabled'}</span><span class="pill pill-gray">${TL(pb.trigger)}</span><span class="pill pill-cyan">${pb.runs} runs</span></div></div>`).join('')}
function selectPB(id){activePB=PLAYBOOKS.find(p=>p.id===id);renderList();renderDetail()}
function renderDetail(){
  const pb=activePB;if(!pb)return;
  const rate=pb.runs>0?Math.round(pb.success/pb.runs*100):0;
  document.getElementById('detail-panel').innerHTML=`<div class="card"><div class="card-head"><div><div class="card-title" style="font-size:14px;margin-bottom:3px">${pb.name}</div><div style="font-size:11px;color:var(--t3)">${pb.desc}</div></div><div style="display:flex;gap:7px;align-items:center"><button class="btn" onclick="togglePB('${pb.id}')">${pb.enabled?'Disable':'Enable'}</button><button class="btn btn-run" onclick="openRunModal('${pb.id}')">&#9654; Run now</button></div></div><div class="card-body"><div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px"><div style="background:var(--surface);border-radius:7px;padding:9px 11px"><div class="stat-lbl">Trigger</div><div style="font-size:12px;font-weight:600;color:var(--amber)">${TL(pb.trigger)}</div></div><div style="background:var(--surface);border-radius:7px;padding:9px 11px"><div class="stat-lbl">Severity</div><div style="font-size:12px;font-weight:600">${pb.sev}</div></div><div style="background:var(--surface);border-radius:7px;padding:9px 11px"><div class="stat-lbl">Total runs</div><div style="font-size:12px;font-weight:600;color:var(--cyan)">${pb.runs}</div></div><div style="background:var(--surface);border-radius:7px;padding:9px 11px"><div class="stat-lbl">Success rate</div><div style="font-size:12px;font-weight:600;color:${rate>=90?'var(--green)':rate>=70?'var(--amber)':'var(--red)'}">${rate}%</div></div></div><div style="margin-bottom:14px"><div class="slbl" style="margin-top:0">Integrations</div>${pb.tags.map(t=>`<span class="trig-chip">${t}</span>`).join('')}</div><div class="slbl">Steps (${pb.steps.length})</div><div id="steps-container">${renderSteps(pb)}</div></div></div>`;
}
function renderSteps(pb){return pb.steps.map((s,i)=>{const st=STEP_TYPES[s.type]||STEP_TYPES.webhook;return`<div class="step-wrap">${i<pb.steps.length-1?'<div class="step-line"></div>':''}<div class="step-dot-num" style="border-color:${s.status!=='idle'?st.color:'var(--border2)'}">${i+1}</div><div class="step-card ${s.status!=='idle'?s.status:''}" id="step-${s.id}"><div class="step-hdr"><span class="step-type" style="background:${st.bg};color:${st.color}">${st.label}</span><span class="step-name">${s.name}</span><span id="si-${s.id}">${ST(s.status)}</span></div><div class="step-desc">${s.desc}</div><div class="step-config">${s.config}</div><div class="step-out ${s.output?'show':''}" id="out-${s.id}">${s.output||''}</div></div></div>`}).join('')}
function togglePB(id){const pb=PLAYBOOKS.find(p=>p.id===id);if(pb)pb.enabled=!pb.enabled;renderList();renderDetail()}
function openRunModal(id){activePB=PLAYBOOKS.find(p=>p.id===id);document.getElementById('run-modal-title').textContent='Run: '+activePB.name;document.getElementById('run-modal-log').style.display='none';document.getElementById('run-log-output').innerHTML='';document.getElementById('run-btn').disabled=false;document.getElementById('run-btn').textContent='▶ Execute';document.getElementById('run-modal').classList.add('open')}
function closeModal(id){document.getElementById(id).classList.remove('open')}
function refreshStep(s){const el=document.getElementById('step-'+s.id);if(!el)return;el.className='step-card '+(s.status!=='idle'?s.status:'');const si=document.getElementById('si-'+s.id);if(si)si.innerHTML=ST(s.status);const out=document.getElementById('out-'+s.id);if(out&&s.output){out.textContent=s.output;out.className='step-out show'}}
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function executePlaybook(){
  if(isRunning)return;isRunning=true;const pb=activePB;if(!pb)return;
  pb.steps.forEach(s=>{s.status='idle';s.output=''});renderDetail();
  const btn=document.getElementById('run-btn');btn.disabled=true;btn.innerHTML='<div class="spinner" style="display:inline-block;vertical-align:middle"></div> Running…';
  const logEl=document.getElementById('run-log-output');document.getElementById('run-modal-log').style.display='block';logEl.innerHTML='';
  const log=(lv,msg)=>{const ts=new Date().toLocaleTimeString('en-GB',{hour12:false});logEl.innerHTML+=`<div class="ll"><span class="ll-ts">${ts}</span><span class="ll-${lv} ll-${lv}">${lv}</span><span style="color:var(--t2)">${msg}</span></div>`;logEl.scrollTop=logEl.scrollHeight};
  const runId='RUN-'+String(Math.floor(Math.random()*9000)+1000);
  log('INFO',`Starting: ${pb.name} [${runId}]`);await delay(400);
  const outs={condition:'PASS — condition met',notify:'SENT — delivery confirmed',ticket:'CREATED — VSP-SEC-'+Math.floor(Math.random()*900+100),webhook:'HTTP 200 — {"status":"ok"}',block:'BLOCKED — pipeline set to failure',enrich:'ENRICHED — CVSS 9.1 · EPSS 0.72 · KEV: YES',wait:'WAITED — delay complete',remediate:'ASSIGNED — findings → security-oncall'};
  for(let i=0;i<pb.steps.length;i++){
    const s=pb.steps[i];log('INFO',`Step ${i+1}/${pb.steps.length}: ${s.name}`);s.status='running';refreshStep(s);await delay(600+Math.random()*500);
    if(Math.random()<0.04){s.status='failed';s.output='ERROR — connection timeout';log('ERROR','Step failed: '+s.name);refreshStep(s);for(let j=i+1;j<pb.steps.length;j++){pb.steps[j].status='skip';log('SKIP','Skipping: '+pb.steps[j].name);refreshStep(pb.steps[j]);}break}
    s.status='done';s.output=outs[s.type]||'OK';log('DONE',`${s.name} → ${s.output}`);refreshStep(s);await delay(150);
  }
  const ok=pb.steps.every(s=>s.status==='done');
  if(ok){log('DONE',`Playbook complete — all ${pb.steps.length} steps succeeded`);pb.runs++;pb.success++}else{log('WARN','Finished with errors');pb.runs++}
  btn.disabled=false;btn.textContent='▶ Execute';isRunning=false;renderList();loadRunHistory();
}
function openNewPlaybook(){document.getElementById('np-name').value='';document.getElementById('np-desc').value='';document.getElementById('new-pb-modal').classList.add('open')}
function createPlaybook(){
  const name=document.getElementById('np-name').value.trim();if(!name)return;
  const desc=document.getElementById('np-desc').value.trim()||'Custom playbook';
  const trigger=document.getElementById('np-trigger').value;const sev=document.getElementById('np-sev').value;
  const tpl=document.getElementById('np-template').value;
  const steps=(TPLS[tpl]||[]).map((s,i)=>({...s,id:'s'+i,status:'idle'}));
  PLAYBOOKS.unshift({id:'pb-'+Date.now(),name,desc,trigger,sev,enabled:true,steps,runs:0,success:0,last:'never',tags:[tpl]});
  closeModal('new-pb-modal');renderList();selectPB(PLAYBOOKS[0].id);
}
function loadRunHistory(){document.getElementById('run-history').innerHTML=RUN_HISTORY.map(r=>`<div class="run-item"><span class="run-id">${r.id}</span><span class="run-pb">${r.pb}</span><span class="pill ${r.status==='success'?'pill-green':'pill-red'}">${r.status}</span><span class="pill pill-gray">${TL(r.trigger)}</span><span class="run-ts">${r.ts}</span><span class="run-dur">${r.dur}</span></div>`).join('')}
window.addEventListener('message',e=>{if(e.data?.type==='vsp:data'&&e.data.playbooks){PLAYBOOKS=[...e.data.playbooks.map(p=>({...p,steps:(p.steps||[]).map((s,i)=>({...s,id:'s'+i,status:'idle'}))})),...PLAYBOOKS.filter(x=>!e.data.playbooks.find(y=>y.id===x.id))];renderList()}});
renderList();loadRunHistory();selectPB('pb-001');
</script>
</body>
</html>
SOAR_EOF

echo "✓ soar.html written ($(wc -c < "$TARGET/soar.html") bytes)"

# ── Log Ingestion Pipeline ────────────────────────────────────
cat > "$TARGET/log_pipeline.html" << 'LOG_EOF'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VSP — Log ingestion</title>
<style>
:root{--bg:#0a0c10;--bg2:#111318;--surface:#1e2128;--border:rgba(255,255,255,.07);--border2:rgba(255,255,255,.12);--t1:#e8eaf0;--t2:#9aa3b8;--t3:#5a6278;--t4:#3a3f52;--red:#ef4444;--red2:rgba(239,68,68,.12);--amber:#f59e0b;--amber2:rgba(245,158,11,.12);--green:#22c55e;--green2:rgba(34,197,94,.12);--blue:#3b82f6;--blue2:rgba(59,130,246,.12);--cyan:#06b6d4;--cyan2:rgba(6,182,212,.12);--purple:#8b5cf6;--purple2:rgba(139,92,246,.12);--teal:#14b8a6;--teal2:rgba(20,184,166,.12);--orange:#f97316;--orange2:rgba(249,115,22,.12);--font-mono:'JetBrains Mono','Fira Mono',monospace;--font-ui:'Inter','Segoe UI',sans-serif}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:13px}
body{background:var(--bg);color:var(--t1);font-family:var(--font-ui);line-height:1.5;padding:20px 24px}
h1{font-size:18px;font-weight:700;letter-spacing:-.03em;margin-bottom:2px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.topbar-right{display:flex;gap:8px;align-items:center}
.btn{font-size:11px;font-weight:500;padding:5px 12px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t1);cursor:pointer;transition:background .15s}
.btn:hover{background:var(--surface)}
.btn-primary{background:var(--blue2);border-color:rgba(59,130,246,.4);color:var(--blue)}
.btn-primary:hover{background:rgba(59,130,246,.2)}
.btn-danger{background:var(--red2);border-color:rgba(239,68,68,.4);color:var(--red)}
.pill{display:inline-block;font-size:10px;font-family:var(--font-mono);padding:2px 6px;border-radius:3px;font-weight:600;border:1px solid transparent}
.pill-green{background:var(--green2);color:var(--green);border-color:rgba(34,197,94,.3)}
.pill-red{background:var(--red2);color:var(--red);border-color:rgba(239,68,68,.3)}
.pill-amber{background:var(--amber2);color:var(--amber);border-color:rgba(245,158,11,.3)}
.pill-blue{background:var(--blue2);color:var(--blue);border-color:rgba(59,130,246,.3)}
.pill-cyan{background:var(--cyan2);color:var(--cyan);border-color:rgba(6,182,212,.3)}
.pill-gray{background:rgba(255,255,255,.06);color:var(--t2);border-color:var(--border2)}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:14px}
.card-head{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--border)}
.card-title{font-size:12px;font-weight:600}
.card-sub{font-size:11px;color:var(--t3);margin-top:1px}
.card-body{padding:12px 14px}
.kpi-row{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:11px 13px}
.kpi-lbl{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.kpi-val{font-size:20px;font-weight:700;font-family:var(--font-mono)}
.kpi-sub{font-size:10px;color:var(--t3);margin-top:2px}
.alert-strip{display:flex;align-items:center;gap:10px;background:var(--red2);border:1px solid rgba(239,68,68,.25);border-radius:7px;padding:8px 12px;margin-bottom:14px;font-size:11px}
.pipe-flow{display:flex;align-items:center;overflow-x:auto;padding:14px;background:var(--bg);border-radius:8px;border:1px solid var(--border);scrollbar-width:thin}
.pipe-stage{flex-shrink:0;display:flex;flex-direction:column;align-items:center;gap:5px;min-width:90px;padding:0 6px}
.pipe-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:15px;border:1px solid}
.pipe-lbl{font-size:10px;font-family:var(--font-mono);color:var(--t2);text-align:center}
.pipe-sub{font-size:9px;color:var(--t3);font-family:var(--font-mono);text-align:center}
.pipe-arr{flex-shrink:0;color:var(--t4);font-size:16px;padding:0 2px;align-self:center;margin-bottom:22px}
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:14px}
.tab{padding:8px 14px;font-size:11px;font-weight:500;cursor:pointer;color:var(--t3);border-bottom:2px solid transparent;transition:color .15s}
.tab:hover{color:var(--t1)}
.tab.active{color:var(--t1);border-bottom-color:var(--blue)}
.src-tbl{width:100%;border-collapse:collapse}
.src-tbl th{text-align:left;font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;padding:6px 10px;border-bottom:1px solid var(--border);font-family:var(--font-mono)}
.src-tbl td{padding:9px 10px;border-bottom:1px solid var(--border);font-size:11px;vertical-align:middle}
.src-tbl tr:last-child td{border-bottom:none}
.src-tbl tr{cursor:pointer;transition:background .12s}
.src-tbl tr:hover td{background:var(--surface)}
.src-name{font-weight:600;font-size:12px;margin-bottom:2px}
.src-host{font-size:10px;color:var(--t3);font-family:var(--font-mono)}
.log-stream{font-family:var(--font-mono);font-size:10px;line-height:1.8;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 10px;height:240px;overflow-y:auto;scrollbar-width:thin}
.ll{display:flex;gap:10px}
.ll-ts{color:var(--t4);flex-shrink:0}
.ll-src{flex-shrink:0;width:72px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--t3)}
.ll-sev{flex-shrink:0;width:54px;font-weight:700}
.ll-msg{color:var(--t2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.CRITICAL{color:var(--red)}.HIGH{color:var(--orange)}.MEDIUM{color:var(--amber)}.LOW{color:var(--green)}.INFO{color:var(--cyan)}
.bar-chart{display:flex;gap:2px;align-items:flex-end;height:80px}
.bar{flex:1;border-radius:2px 2px 0 0;min-width:8px;cursor:default}
.norm-rule{display:flex;align-items:center;gap:10px;padding:7px 10px;border-bottom:1px solid var(--border);font-size:11px}
.norm-rule:last-child{border-bottom:none}
.form-group{margin-bottom:10px}
.form-label{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;display:block}
.form-ctrl{width:100%;background:var(--bg);border:1px solid var(--border2);color:var(--t1);padding:6px 9px;border-radius:6px;font-size:12px;font-family:var(--font-ui);outline:none;transition:border-color .15s}
.form-ctrl:focus{border-color:var(--blue)}
select.form-ctrl option{background:var(--bg2)}
textarea.form-ctrl{font-family:var(--font-mono);font-size:10px;resize:vertical}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:12px;width:min(540px,95vw);max-height:85vh;overflow-y:auto}
.modal-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border)}
.modal-title{font-size:14px;font-weight:700}
.modal-body{padding:16px}
.modal-footer{padding:12px 16px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end}
.modal-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.sdot{width:7px;height:7px;border-radius:50%;display:inline-block}
.sdot-ok{background:var(--green)}.sdot-warn{background:var(--amber)}.sdot-err{background:var(--red)}.sdot-idle{background:var(--t4)}
</style>
</head>
<body>
<div class="topbar">
  <div><h1>Log ingestion pipeline</h1><div style="font-size:11px;color:var(--t3);font-family:var(--font-mono)">Syslog · CEF · JSON · LEEF · Netflow · agent · normalization</div></div>
  <div class="topbar-right">
    <span class="pill pill-green">&#9679; Pipeline live</span>
    <button class="btn btn-primary" onclick="openAddSource()">+ Add source</button>
    <button class="btn" id="pause-btn" onclick="togglePause()">&#9646;&#9646; Pause</button>
  </div>
</div>

<div class="alert-strip" id="alert-strip">
  <span style="color:var(--red);font-size:14px;flex-shrink:0">&#9888;</span>
  <span style="flex:1"><strong>1 source offline:</strong> Windows Event Log agent on <span style="font-family:var(--font-mono)">10.0.1.45</span> — last heartbeat 14m ago. Auto-reconnect in progress.</span>
  <button class="btn btn-danger" style="flex-shrink:0" onclick="this.closest('.alert-strip').style.display='none'">Dismiss</button>
</div>

<div class="kpi-row">
  <div class="kpi"><div class="kpi-lbl">Events / min</div><div class="kpi-val" style="color:var(--cyan)" id="k-eps">3,284</div><div class="kpi-sub" id="k-eps-sub">across 8 sources</div></div>
  <div class="kpi"><div class="kpi-lbl">Events today</div><div class="kpi-val" id="k-today">4.7M</div><div class="kpi-sub">since 00:00 UTC</div></div>
  <div class="kpi"><div class="kpi-lbl">Parse rate</div><div class="kpi-val" style="color:var(--green)" id="k-parse">99.2%</div><div class="kpi-sub">0.8% errors</div></div>
  <div class="kpi"><div class="kpi-lbl">Sources</div><div class="kpi-val" id="k-sources">8</div><div class="kpi-sub"><span style="color:var(--green)">7 ok</span> · <span style="color:var(--red)">1 err</span></div></div>
  <div class="kpi"><div class="kpi-lbl">Queue depth</div><div class="kpi-val" style="color:var(--amber)" id="k-queue">127</div><div class="kpi-sub">events pending</div></div>
</div>

<div class="card">
  <div class="card-head"><div><div class="card-title">Pipeline architecture</div><div class="card-sub">data flow: source → VSP findings</div></div></div>
  <div class="card-body" style="padding:8px 14px 14px"><div class="pipe-flow" id="pipe-flow"></div></div>
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('sources',this)">Sources</div>
  <div class="tab" onclick="switchTab('normalizer',this)">Normalizer</div>
  <div class="tab" onclick="switchTab('stream',this)">Live stream</div>
  <div class="tab" onclick="switchTab('throughput',this)">Throughput</div>
</div>

<div id="tab-sources">
  <div class="card" style="margin-bottom:0">
    <div class="card-head"><div><div class="card-title">Active sources</div><div class="card-sub" id="src-count-lbl">8 configured</div></div><div style="display:flex;gap:7px"><button class="btn" onclick="renderSources()">&#8635;</button><button class="btn btn-primary" onclick="openAddSource()">+ Add source</button></div></div>
    <table class="src-tbl"><thead><tr><th style="width:24px"></th><th>Source</th><th>Protocol</th><th>Format</th><th>Events/min</th><th>Last event</th><th>Parse rate</th><th>Status</th><th></th></tr></thead><tbody id="sources-tbody"></tbody></table>
  </div>
</div>

<div id="tab-normalizer" style="display:none">
  <div class="card" style="margin-bottom:14px">
    <div class="card-head"><div><div class="card-title">Field normalization rules</div><div class="card-sub">raw fields → VSP common schema</div></div><button class="btn btn-primary">+ Add mapping</button></div>
    <div id="norm-rules-el"></div>
  </div>
  <div class="card" style="margin-bottom:0">
    <div class="card-head"><div class="card-title">Enrichment pipeline</div><div class="card-sub">applied after normalization</div></div>
    <div class="card-body" id="enrich-el"></div>
  </div>
</div>

<div id="tab-stream" style="display:none">
  <div class="card" style="margin-bottom:0">
    <div class="card-head">
      <div><div class="card-title">Live event stream</div><div class="card-sub" id="stream-count">— events shown</div></div>
      <div style="display:flex;gap:7px;align-items:center">
        <select id="stream-src-f" class="form-ctrl" style="width:140px" onchange="renderStream()"><option value="">All sources</option></select>
        <select id="stream-sev-f" class="form-ctrl" style="width:100px" onchange="renderStream()"><option value="">All sev.</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
        <label style="display:flex;align-items:center;gap:5px;font-size:11px;color:var(--t2);cursor:pointer"><input type="checkbox" id="autoscroll-cb" checked style="accent-color:var(--cyan)"> Auto-scroll</label>
        <button class="btn" onclick="streamEvents=[];renderStream()">Clear</button>
      </div>
    </div>
    <div class="log-stream" id="log-stream"></div>
  </div>
</div>

<div id="tab-throughput" style="display:none">
  <div class="grid2">
    <div class="card" style="margin-bottom:0">
      <div class="card-head"><div class="card-title">Events/min — last 30 windows</div></div>
      <div class="card-body"><div class="bar-chart" id="bar-eps"></div><div style="display:flex;justify-content:space-between;margin-top:4px"><span style="font-size:10px;color:var(--t3)">-30m</span><span style="font-size:10px;color:var(--t3)">now</span></div></div>
    </div>
    <div class="card" style="margin-bottom:0">
      <div class="card-head"><div class="card-title">Parse errors/min — last 30 windows</div></div>
      <div class="card-body"><div class="bar-chart" id="bar-err"></div><div style="display:flex;justify-content:space-between;margin-top:4px"><span style="font-size:10px;color:var(--t3)">-30m</span><span style="font-size:10px;color:var(--t3)">now</span></div></div>
    </div>
  </div>
  <div class="card" style="margin-top:14px;margin-bottom:0">
    <div class="card-head"><div class="card-title">Source throughput</div></div>
    <div class="card-body" id="tp-breakdown"></div>
  </div>
</div>

<div class="modal-overlay" id="add-source-modal">
  <div class="modal">
    <div class="modal-head"><div class="modal-title">Add log source</div><button class="modal-close" onclick="closeModal('add-source-modal')">&#10005;</button></div>
    <div class="modal-body">
      <div class="grid2">
        <div class="form-group"><label class="form-label">Source name</label><input class="form-ctrl" id="ns-name" placeholder="e.g. Production nginx"></div>
        <div class="form-group"><label class="form-label">Protocol</label>
          <select class="form-ctrl" id="ns-proto" onchange="updatePortHint()">
            <option value="syslog-udp">Syslog UDP</option><option value="syslog-tcp">Syslog TCP</option>
            <option value="syslog-tls">Syslog TLS</option><option value="cef">CEF over syslog</option>
            <option value="leef">LEEF</option><option value="http-json">HTTP/JSON webhook</option>
            <option value="agent">VSP agent</option><option value="s3">AWS S3 (CloudTrail)</option>
            <option value="kafka">Kafka topic</option>
          </select>
        </div>
        <div class="form-group"><label class="form-label">Host / endpoint</label><input class="form-ctrl" id="ns-host" placeholder="10.0.1.50"></div>
        <div class="form-group"><label class="form-label">Port</label><input class="form-ctrl" id="ns-port" placeholder="514" type="number"></div>
      </div>
      <div class="form-group"><label class="form-label">Log format</label>
        <select class="form-ctrl" id="ns-format">
          <option>syslog-rfc3164</option><option>syslog-rfc5424</option><option>cef-v25</option>
          <option>leef-2.0</option><option>json-raw</option><option>aws-cloudtrail</option>
          <option>windows-evtx</option><option>netflow-v9</option><option>custom</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label">Tags (comma-separated)</label><input class="form-ctrl" id="ns-tags" placeholder="linux, auth, prod"></div>
      <div id="ns-hint" style="font-size:10px;color:var(--t3);font-family:var(--font-mono);margin-bottom:8px">Default port: 514 (UDP syslog)</div>
    </div>
    <div class="modal-footer"><button class="btn" onclick="closeModal('add-source-modal')">Cancel</button><button class="btn btn-primary" onclick="addSource()">Add source &#8594;</button></div>
  </div>
</div>

<script>
const PIPE_STAGES=[{icon:'&#8680;',lbl:'Receive',sub:'UDP/TCP/TLS',c:'var(--cyan)',bg:'var(--cyan2)'},{icon:'&#9783;',lbl:'Buffer',sub:'in-memory queue',c:'var(--blue)',bg:'var(--blue2)'},{icon:'&#9634;',lbl:'Parse',sub:'format decode',c:'var(--purple)',bg:'var(--purple2)'},{icon:'&#8644;',lbl:'Normalize',sub:'common schema',c:'var(--amber)',bg:'var(--amber2)'},{icon:'&#9672;',lbl:'Enrich',sub:'GeoIP · IOC · ASN',c:'var(--teal)',bg:'var(--teal2)'},{icon:'&#9826;',lbl:'Filter',sub:'drop noise',c:'var(--orange)',bg:'var(--orange2)'},{icon:'&#9654;',lbl:'Route',sub:'rules engine',c:'var(--green)',bg:'var(--green2)'},{icon:'&#9635;',lbl:'Store',sub:'VSP event DB',c:'var(--t2)',bg:'rgba(255,255,255,.06)'}];
let SOURCES=[{id:'src-001',name:'Linux syslog (prod)',host:'10.0.1.10',proto:'syslog-udp',port:514,format:'syslog-rfc3164',eps:842,last:'0s',pr:99.8,status:'ok',tags:['linux','auth']},{id:'src-002',name:'Nginx access log',host:'10.0.1.11',proto:'syslog-tcp',port:514,format:'json-raw',eps:1240,last:'0s',pr:100,status:'ok',tags:['web','nginx']},{id:'src-003',name:'AWS CloudTrail',host:'s3://logs',proto:'s3',port:0,format:'aws-cloudtrail',eps:64,last:'4s',pr:98.1,status:'ok',tags:['aws']},{id:'src-004',name:'Windows Event Log',host:'10.0.1.45',proto:'agent',port:8514,format:'windows-evtx',eps:0,last:'14m',pr:0,status:'err',tags:['windows']},{id:'src-005',name:'Firewall (Palo Alto)',host:'10.0.2.1',proto:'syslog-tls',port:6514,format:'cef-v25',eps:380,last:'1s',pr:99.5,status:'ok',tags:['firewall']},{id:'src-006',name:'VSP scan engine',host:'127.0.0.1',proto:'http-json',port:8922,format:'json-raw',eps:28,last:'2s',pr:100,status:'ok',tags:['vsp']},{id:'src-007',name:'GitHub audit log',host:'api.github',proto:'http-json',port:443,format:'json-raw',eps:12,last:'8s',pr:97.2,status:'ok',tags:['git']},{id:'src-008',name:'Kubernetes events',host:'10.0.3.1',proto:'agent',port:8514,format:'json-raw',eps:718,last:'1s',pr:98.8,status:'warn',tags:['k8s']}];
const NORM_RULES=[{from:'src_ip',to:'source.ip',hits:'98.4k'},{from:'sourceIPAddress',to:'source.ip',hits:'12.1k'},{from:'msg',to:'message',hits:'142k'},{from:'pri',to:'event.severity',hits:'98.4k'},{from:'hostname',to:'host.name',hits:'98.4k'},{from:'process',to:'process.name',hits:'78.2k'},{from:'eventName',to:'event.action',hits:'12.1k'},{from:'userIdentity.arn',to:'user.id',hits:'8.4k'}];
const ENRICH=[{name:'GeoIP lookup',desc:'Add geo coords + country to source.ip',s:'ok'},{name:'ASN lookup',desc:'Enrich source.ip with ASN / org name',s:'ok'},{name:'IOC match',desc:'Check against TI feeds',s:'ok'},{name:'User enrichment',desc:'Join user.id with LDAP/AD',s:'warn'},{name:'Host CMDB',desc:'Add host.role and host.env from asset DB',s:'ok'}];
let EPS_DATA=Array.from({length:30},()=>Math.round(2800+Math.random()*900));
let ERR_DATA=Array.from({length:30},()=>Math.round(Math.random()*18));
let streamEvents=[],streamPaused=false,currentTab='sources';

function renderPipe(){document.getElementById('pipe-flow').innerHTML=PIPE_STAGES.map((s,i)=>`<div class="pipe-stage"><div class="pipe-icon" style="background:${s.bg};border-color:${s.c};color:${s.c}">${s.icon}</div><div class="pipe-lbl">${s.lbl}</div><div class="pipe-sub">${s.sub}</div></div>${i<PIPE_STAGES.length-1?'<div class="pipe-arr">&#8594;</div>':''}`).join('')}
function renderSources(){
  document.getElementById('src-count-lbl').textContent=SOURCES.length+' configured';
  document.getElementById('sources-tbody').innerHTML=SOURCES.map(s=>{
    const dc=s.status==='ok'?'sdot-ok':s.status==='warn'?'sdot-warn':s.status==='err'?'sdot-err':'sdot-idle';
    const pc=s.pr>=99?'var(--green)':s.pr>=95?'var(--amber)':'var(--red)';
    return`<tr><td><span class="sdot ${dc}"></span></td><td><div class="src-name">${s.name}</div><div class="src-host">${s.host}${s.port?':'+s.port:''}</div></td><td><span class="pill pill-gray">${s.proto}</span></td><td><span class="pill pill-blue" style="font-size:9px">${s.format}</span></td><td style="font-family:var(--font-mono);color:${s.eps>0?'var(--cyan)':'var(--t4)'}">${s.eps.toLocaleString()}</td><td style="font-family:var(--font-mono);font-size:10px;color:var(--t3)">${s.last}</td><td style="font-family:var(--font-mono);color:${pc}">${s.pr}%</td><td><span class="pill ${s.status==='ok'?'pill-green':s.status==='warn'?'pill-amber':'pill-red'}">${s.status}</span></td><td><div style="display:flex;gap:5px"><button class="btn" style="padding:3px 7px;font-size:10px" onclick="event.stopPropagation();testSrc('${s.id}')">Test</button><button class="btn btn-danger" style="padding:3px 7px;font-size:10px" onclick="event.stopPropagation();removeSrc('${s.id}')">&#10005;</button></div></td></tr>`;
  }).join('');
  document.getElementById('k-sources').textContent=SOURCES.length;
  populateSrcFilter();
}
function testSrc(id){const s=SOURCES.find(x=>x.id===id);if(s){s.status='ok';s.last='0s'}renderSources()}
function removeSrc(id){if(!confirm('Remove this source?'))return;const i=SOURCES.findIndex(s=>s.id===id);if(i>=0)SOURCES.splice(i,1);renderSources()}
function renderNorm(){
  const el=document.getElementById('norm-rules-el');if(!el)return;
  el.innerHTML=NORM_RULES.map(r=>`<div class="norm-rule"><span style="font-family:var(--font-mono);color:var(--amber);flex:1">${r.from}</span><span style="color:var(--t4);flex-shrink:0">&#8594;</span><span style="font-family:var(--font-mono);color:var(--cyan);flex:1">${r.to}</span><span style="font-family:var(--font-mono);font-size:10px;color:var(--t3)">${r.hits}</span></div>`).join('');
  const ep=document.getElementById('enrich-el');if(!ep)return;
  ep.innerHTML=`<div style="display:flex;flex-direction:column;gap:8px">${ENRICH.map(e=>`<div style="display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--surface);border-radius:7px;border:1px solid var(--border)"><span class="sdot ${e.s==='ok'?'sdot-ok':e.s==='warn'?'sdot-warn':'sdot-err'}"></span><div style="flex:1"><div style="font-size:12px;font-weight:600">${e.name}</div><div style="font-size:11px;color:var(--t3)">${e.desc}</div></div><span class="pill ${e.s==='ok'?'pill-green':e.s==='warn'?'pill-amber':'pill-red'}">${e.s}</span></div>`).join('')}</div>`;
}
const SEVS=['CRITICAL','HIGH','HIGH','MEDIUM','MEDIUM','MEDIUM','LOW','LOW','INFO','INFO','INFO'];
const MSGS=[s=>`Failed password for root from ${rip()} port ${Math.floor(Math.random()*60000)+1024} ssh2`,s=>`GET /api/v1/findings HTTP/1.1 200 ${Math.floor(Math.random()*5000)+200}`,s=>`AssumeRole: arn:aws:iam::${Math.floor(Math.random()*9e11+1e11)}:role/admin from ${rip()}`,s=>`KICS: Found ${Math.floor(Math.random()*10)+1} HIGH findings in main.tf`,s=>`Connection from ${rip()} to 10.0.0.1:443`,s=>`User admin@vsp.local authenticated successfully`,s=>`CVE-2024-${Math.floor(Math.random()*90000)+10000} detected in dependency`,s=>`k8s: Pod security-scanner restarted (exit code 1)`,s=>`API key exposed in commit ${Math.random().toString(16).slice(2,10)}`,s=>`S3 bucket set to public-read`];
function rip(){return[10,0,Math.floor(Math.random()*4),Math.floor(Math.random()*254)+1].join('.')}
function genEv(){const sev=SEVS[Math.floor(Math.random()*SEVS.length)];const src=SOURCES[Math.floor(Math.random()*SOURCES.length)].name;const msg=MSGS[Math.floor(Math.random()*MSGS.length)](src);const ts=new Date().toLocaleTimeString('en-GB',{hour12:false});return{ts,src,sev,msg}}
function addEv(ev){streamEvents.push(ev);if(streamEvents.length>500)streamEvents.shift()}
function renderStream(){
  const el=document.getElementById('log-stream');if(!el)return;
  const sf=(document.getElementById('stream-src-f')||{}).value||'';
  const sv=(document.getElementById('stream-sev-f')||{}).value||'';
  const filtered=streamEvents.filter(e=>(!sf||e.src===sf)&&(!sv||e.sev===sv)).slice(-80);
  document.getElementById('stream-count').textContent=filtered.length+' events shown';
  el.innerHTML=filtered.map(e=>`<div class="ll"><span class="ll-ts">${e.ts}</span><span class="ll-src">${e.src.split(' ')[0]}</span><span class="ll-sev ${e.sev}">${e.sev}</span><span class="ll-msg">${e.msg}</span></div>`).join('');
  if((document.getElementById('autoscroll-cb')||{}).checked)el.scrollTop=el.scrollHeight;
}
function populateSrcFilter(){const sel=document.getElementById('stream-src-f');if(!sel)return;sel.innerHTML='<option value="">All sources</option>'+SOURCES.map(s=>`<option value="${s.name}">${s.name}</option>`).join('')}
function renderBarChart(id,data,color){const el=document.getElementById(id);if(!el)return;const max=Math.max(...data)||1;el.innerHTML=data.map(v=>`<div class="bar" style="height:${Math.round(v/max*74)+4}px;background:${color};opacity:.75;flex:1" title="${v}"></div>`).join('')}
function renderTpBreakdown(){const el=document.getElementById('tp-breakdown');if(!el)return;const tot=SOURCES.reduce((a,b)=>a+b.eps,0)||1;el.innerHTML=SOURCES.map(s=>{const pct=Math.round(s.eps/tot*100);return`<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="font-size:11px;width:160px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.name}</span><div style="flex:1;height:6px;border-radius:3px;background:var(--border)"><div style="width:${pct}%;height:6px;border-radius:3px;background:${s.status==='ok'?'var(--cyan)':s.status==='warn'?'var(--amber)':'var(--red)'}"></div></div><span style="font-family:var(--font-mono);font-size:10px;color:var(--t3);width:60px;text-align:right">${s.eps.toLocaleString()}/m</span><span style="font-size:10px;color:var(--t3);width:28px;text-align:right">${pct}%</span></div>`}).join('')}
function openAddSource(){document.getElementById('add-source-modal').classList.add('open')}
function closeModal(id){document.getElementById(id).classList.remove('open')}
function updatePortHint(){const v=document.getElementById('ns-proto').value;const m={'syslog-udp':'Default: 514 (UDP)','syslog-tcp':'Default: 514 (TCP)','syslog-tls':'Default: 6514 (TLS)','http-json':'Default: 8080 (HTTP)','agent':'Default: 8514 (VSP agent)','kafka':'Default: 9092 (Kafka)','s3':'No port — AWS SDK'};document.getElementById('ns-hint').textContent=m[v]||'';const p={'syslog-udp':514,'syslog-tcp':514,'syslog-tls':6514,'http-json':8080,'agent':8514,'kafka':9092};document.getElementById('ns-port').value=p[v]||''}
function addSource(){const name=document.getElementById('ns-name').value.trim();if(!name)return;const host=document.getElementById('ns-host').value.trim()||'0.0.0.0';const proto=document.getElementById('ns-proto').value;const port=parseInt(document.getElementById('ns-port').value)||514;const format=document.getElementById('ns-format').value;const tags=document.getElementById('ns-tags').value.split(',').map(t=>t.trim()).filter(Boolean);SOURCES.push({id:'src-'+Date.now(),name,host,proto,port,format,eps:0,last:'never',pr:0,status:'ok',tags});closeModal('add-source-modal');renderSources()}
function togglePause(){streamPaused=!streamPaused;document.getElementById('pause-btn').textContent=streamPaused?'▶ Resume':'❚❚ Pause'}
function switchTab(name,el){currentTab=name;['sources','normalizer','stream','throughput'].forEach(t=>{const d=document.getElementById('tab-'+t);if(d)d.style.display=t===name?'':'none'});document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));if(el)el.classList.add('active');if(name==='normalizer')renderNorm();if(name==='stream'){populateSrcFilter();renderStream()}if(name==='throughput'){renderBarChart('bar-eps',EPS_DATA,'var(--cyan)');renderBarChart('bar-err',ERR_DATA,'var(--red)');renderTpBreakdown()}}
let _tick=0;
setInterval(()=>{_tick++;SOURCES.forEach(s=>{if(s.status==='err')return;s.eps=Math.max(0,s.eps+Math.round(Math.random()*40-20));s.last=Math.floor(Math.random()*3)+'s'});const tot=SOURCES.reduce((a,b)=>a+b.eps,0);document.getElementById('k-eps').textContent=tot.toLocaleString();if(!streamPaused){const n=Math.floor(Math.random()*4)+1;for(let i=0;i<n;i++)addEv(genEv());if(currentTab==='stream')renderStream()}if(_tick%6===0){EPS_DATA.push(tot);if(EPS_DATA.length>30)EPS_DATA.shift();ERR_DATA.push(Math.round(Math.random()*15));if(ERR_DATA.length>30)ERR_DATA.shift();if(currentTab==='sources')renderSources();if(currentTab==='throughput'){renderBarChart('bar-eps',EPS_DATA,'var(--cyan)');renderBarChart('bar-err',ERR_DATA,'var(--red)');renderTpBreakdown()}}const q=Math.max(0,127+Math.round(Math.random()*60-30));const qel=document.getElementById('k-queue');qel.textContent=q;qel.style.color=q>200?'var(--red)':q>100?'var(--amber)':'var(--green)'},1500);
window.addEventListener('message',e=>{if(e.data?.type==='vsp:data'&&e.data.sources){SOURCES=[...e.data.sources.map(s=>({...s,eps:s.events_per_min||0,pr:s.parse_rate||0,last:s.last_event||'?'}))];renderSources()}});
renderPipe();renderSources();for(let i=0;i<40;i++)addEv(genEv());renderStream();
</script>
</body>
</html>
LOG_EOF

echo "✓ log_pipeline.html written ($(wc -c < "$TARGET/log_pipeline.html") bytes)"

# ── Integration patch snippet ─────────────────────────────────
cat > "$TARGET/vsp_siem_patch.js" << 'PATCH_EOF'
/* ================================================================
   VSP SIEM INTEGRATION PATCH
   Paste this into your main index.html <script> section,
   AFTER all existing VSP patch scripts.
================================================================ */

// 1. Register SIEM panels in PANEL_META
Object.assign(typeof PANEL_META !== 'undefined' ? PANEL_META : {}, {
  correlation: { title:'Correlation engine', sub:'VSP / SIEM / Event correlation · incidents' },
  soar:        { title:'SOAR playbooks',     sub:'VSP / SIEM / Orchestration & automation'   },
  logsources:  { title:'Log ingestion',      sub:'VSP / SIEM / Sources · parsers · stream'   },
  threatintel: { title:'Threat intelligence',sub:'VSP / SIEM / IOC · CVE enrichment · MITRE' },
});

// 2. Hook showPanel to load SIEM data
(function() {
  const _prev = window.showPanel;
  window.showPanel = function(name, btn) {
    if (_prev) _prev(name, btn);
    const loaders = { correlation: loadCorrelation, soar: loadSOAR, logsources: loadLogSources, threatintel: loadThreatIntel };
    if (loaders[name]) setTimeout(loaders[name], 200);
  };
})();

// 3. SIEM panel loaders
async function loadCorrelation() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const [rules, incidents] = await Promise.all([
    fetch('/api/v1/correlation/rules',   { headers: h }).then(r => r.json()).catch(() => ({ rules: [] })),
    fetch('/api/v1/correlation/incidents',{ headers: h }).then(r => r.json()).catch(() => ({ incidents: [] })),
  ]);
  const badge = document.getElementById('badge-incidents');
  if (badge) badge.textContent = incidents.total ?? (incidents.incidents || []).length ?? 0;
  _postToFrame('panel-correlation', { type: 'vsp:data', rules, incidents });
}

async function loadSOAR() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const [playbooks, runs] = await Promise.all([
    fetch('/api/v1/soar/playbooks',    { headers: h }).then(r => r.json()).catch(() => ({ playbooks: [] })),
    fetch('/api/v1/soar/runs?limit=20',{ headers: h }).then(r => r.json()).catch(() => ({ runs: [] })),
  ]);
  _postToFrame('panel-soar', { type: 'vsp:data', playbooks, runs });
}

async function loadLogSources() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const [sources, stats] = await Promise.all([
    fetch('/api/v1/logs/sources',{ headers: h }).then(r => r.json()).catch(() => ({ sources: [] })),
    fetch('/api/v1/logs/stats',  { headers: h }).then(r => r.json()).catch(() => {}),
  ]);
  _postToFrame('panel-logsources', { type: 'vsp:data', sources, stats });
}

async function loadThreatIntel() {
  if (!await ensureToken()) return;
  const h = { Authorization: 'Bearer ' + window.TOKEN };
  const [iocs, feeds, matches] = await Promise.all([
    fetch('/api/v1/ti/iocs?limit=20',{ headers: h }).then(r => r.json()).catch(() => ({ iocs: [] })),
    fetch('/api/v1/ti/feeds',        { headers: h }).then(r => r.json()).catch(() => ({ feeds: [] })),
    fetch('/api/v1/ti/matches',      { headers: h }).then(r => r.json()).catch(() => ({ matches: [] })),
  ]);
  _postToFrame('panel-threatintel', { type: 'vsp:data', iocs, feeds, matches });
}

function _postToFrame(panelId, data) {
  const frame = document.querySelector('#' + panelId + ' iframe');
  if (frame && frame.contentWindow) frame.contentWindow.postMessage(data, '*');
}

// 4. Auto-trigger SOAR from SSE gate FAIL events
//    (wire into your existing SSE onmessage handler)
window._siemAutoTrigger = async function(msg) {
  if (msg.type === 'scan_complete' && msg.gate === 'FAIL') {
    if (!await ensureToken()) return;
    fetch('/api/v1/soar/trigger', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + window.TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ trigger: 'gate_fail', gate: msg.gate, severity: msg.max_severity || 'HIGH', run_id: msg.rid, findings: msg.total_findings }),
    }).then(r => r.json()).then(d => {
      if (d.triggered > 0 && typeof showToast === 'function') showToast('SOAR: ' + d.triggered + ' playbook(s) triggered', 'info');
    }).catch(() => {});
  }
};

// 5. Add SIEM panels to quick search
(function() {
  const siemPanels = [
    { name:'Correlation engine', icon:'◆', p:'correlation', desc:'Cross-source rules · incidents' },
    { name:'SOAR playbooks',     icon:'▶', p:'soar',        desc:'Automated response workflows'   },
    { name:'Log ingestion',      icon:'⊞', p:'logsources',  desc:'Syslog · CEF · agent sources'   },
    { name:'Threat intelligence',icon:'◈', p:'threatintel', desc:'IOC · CVE enrichment · MITRE'   },
  ];
  if (typeof QS_PANELS !== 'undefined') QS_PANELS.push(...siemPanels);
})();

console.log('VSP SIEM patch loaded ✓ — correlation | soar | logsources | threatintel');
PATCH_EOF

echo "✓ vsp_siem_patch.js written ($(wc -c < "$TARGET/vsp_siem_patch.js") bytes)"

# ── Print HTML to add to index.html ──────────────────────────
cat << 'NAV_EOF'

════════════════════════════════════════════════════════════════
  STEP 2: Add to sidebar nav (inside <nav class="nav">)
════════════════════════════════════════════════════════════════

<div class="nav-section">
  <div class="nav-section-label">SIEM</div>
  <button class="nav-item" onclick="showPanel('correlation',this)">
    <span class="nav-icon">◆</span> Correlation
    <span class="nav-badge" id="badge-incidents">0</span>
  </button>
  <button class="nav-item" onclick="showPanel('soar',this)">
    <span class="nav-icon">▶</span> SOAR
  </button>
  <button class="nav-item" onclick="showPanel('logsources',this)">
    <span class="nav-icon">⊞</span> Log ingestion
  </button>
  <button class="nav-item" onclick="showPanel('threatintel',this)">
    <span class="nav-icon">◈</span> Threat intel
  </button>
</div>

════════════════════════════════════════════════════════════════
  STEP 3: Add panels to #content div
════════════════════════════════════════════════════════════════

<div id="panel-correlation" class="panel">
  <iframe src="/panels/correlation.html" style="width:100%;height:calc(100vh - 52px);border:none"></iframe>
</div>
<div id="panel-soar" class="panel">
  <iframe src="/panels/soar.html" style="width:100%;height:calc(100vh - 52px);border:none"></iframe>
</div>
<div id="panel-logsources" class="panel">
  <iframe src="/panels/log_pipeline.html" style="width:100%;height:calc(100vh - 52px);border:none"></iframe>
</div>
<div id="panel-threatintel" class="panel">
  <iframe src="/panels/threat_intel.html" style="width:100%;height:calc(100vh - 52px);border:none"></iframe>
</div>

════════════════════════════════════════════════════════════════
  STEP 4: Add to existing SSE onmessage handler
════════════════════════════════════════════════════════════════

  // Inside src.onmessage = (e) => { ... }
  // After existing handling, add:
  if (typeof window._siemAutoTrigger === 'function') {
    window._siemAutoTrigger(msg);
  }

════════════════════════════════════════════════════════════════
NAV_EOF

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Done! Files written to: $TARGET"
echo "  soar.html        — SOAR playbook engine"
echo "  log_pipeline.html — Log ingestion pipeline"
echo "  vsp_siem_patch.js — JS patch (add to index.html)"
echo ""
echo "  Quick start:"
echo "  bash vsp_siem_deploy.sh /path/to/vsp/static/panels"
echo "════════════════════════════════════════════════════════════════"
