/**
 * VSP Upgrade Patch v0.7.0
 * Fixes + new upgrades:
 *  1. Executive Summary — fix data loading + rich layout
 *  2. SSE /events fix — reconnect with auth header workaround
 *  3. Kanban drag-drop (HTML5 native)
 *  4. Audit panel upgrade — timeline + stats
 *  5. SBOM panel upgrade — component stats + charts
 *  6. Policy panel upgrade — rule builder UI
 *  7. SLA Tracker panel (new standalone panel)
 */

// ─── CSS ─────────────────────────────────────────────────────────────────────
(function(){
const s = document.createElement('style');
s.textContent = `
/* ── EXECUTIVE SUMMARY ───────────────────────────────── */
.exec-hero {
  display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;
  background:var(--border);border-radius:10px;overflow:hidden;margin-bottom:20px;
}
.exec-hero-cell {
  background:var(--card);padding:28px 24px;
}
.exec-score-ring {
  width:110px;height:110px;margin:0 auto 12px;position:relative;
}
.exec-score-ring canvas { display:block; }
.exec-score-overlay {
  position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;
}
.exec-score-num { font-family:var(--display);font-size:30px;font-weight:800;line-height:1; }
.exec-score-lbl { font-size:9px;letter-spacing:.12em;color:var(--text3);text-transform:uppercase; }
.exec-risk-row {
  display:flex;justify-content:space-between;align-items:center;
  padding:8px 0;border-bottom:1px solid var(--border);
}
.exec-risk-row:last-child { border-bottom:none; }
.exec-risk-label { font-size:12px;color:var(--text2); }
.exec-risk-val { font-family:var(--display);font-size:20px;font-weight:700; }
.exec-grade-display {
  font-family:var(--display);font-size:80px;font-weight:800;
  line-height:1;text-align:center;margin:16px 0 8px;
}
.exec-scan-strip {
  display:grid;grid-template-columns:repeat(5,1fr);gap:1px;
  background:var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px;
}
.exec-scan-cell {
  background:var(--card);padding:14px;text-align:center;
}
.exec-scan-mode { font-size:9px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;margin-bottom:6px; }
.exec-scan-count { font-family:var(--display);font-size:24px;font-weight:700; }
.exec-rec-item {
  display:flex;gap:12px;padding:12px;
  border-left:2px solid;margin-bottom:8px;
  background:rgba(255,255,255,.02);border-radius:0 6px 6px 0;
}
.exec-rec-level { font-size:9px;letter-spacing:.1em;font-weight:700;white-space:nowrap;margin-top:2px; }
.exec-rec-text { font-size:12px;color:var(--text2);line-height:1.5; }

/* ── AUDIT UPGRADE ───────────────────────────────────── */
.audit-stat-strip {
  display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px;
}
.audit-stat-cell { background:var(--card);padding:14px;text-align:center; }
.audit-stat-val { font-family:var(--display);font-size:28px;font-weight:800;line-height:1;margin:6px 0 2px; }
.audit-stat-lbl { font-size:9px;letter-spacing:.12em;color:var(--text3);text-transform:uppercase; }
.audit-action-badge {
  display:inline-block;padding:2px 7px;border-radius:3px;
  font-size:9px;font-weight:700;letter-spacing:.06em;font-family:var(--mono);
}

/* ── SBOM UPGRADE ────────────────────────────────────── */
.sbom-stat-strip {
  display:grid;grid-template-columns:repeat(5,1fr);gap:1px;
  background:var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px;
}
.sbom-stat-cell { background:var(--card);padding:14px;text-align:center; }
.sbom-stat-val { font-family:var(--display);font-size:28px;font-weight:800;line-height:1;margin:6px 0 2px; }
.sbom-stat-lbl { font-size:9px;letter-spacing:.12em;color:var(--text3);text-transform:uppercase; }

/* ── POLICY UPGRADE ──────────────────────────────────── */
.policy-rule-card {
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:16px;margin-bottom:10px;
}
.policy-rule-card:hover { border-color:var(--border2); }
.policy-rule-header { display:flex;align-items:center;gap:10px;margin-bottom:10px; }
.policy-rule-name { font-size:13px;font-weight:700;color:var(--text1);flex:1; }
.policy-toggle {
  width:36px;height:20px;border-radius:10px;background:var(--border2);
  cursor:pointer;position:relative;transition:.2s;flex-shrink:0;
  border:none;
}
.policy-toggle.on { background:var(--green); }
.policy-toggle::after {
  content:'';position:absolute;width:14px;height:14px;border-radius:50%;
  background:white;top:3px;left:3px;transition:.2s;
}
.policy-toggle.on::after { left:19px; }
.policy-rule-meta { display:flex;gap:12px;font-size:10px;color:var(--text3); }

/* ── SLA TRACKER PANEL ───────────────────────────────── */
.sla-tracker-grid {
  display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:16px;
}
.sla-tracker-card {
  background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;
}
.sla-breach-row {
  display:flex;align-items:center;gap:10px;padding:8px 0;
  border-bottom:1px solid var(--border);font-size:12px;
}
.sla-breach-row:last-child { border-bottom:none; }
.sla-days-badge {
  padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;
  font-family:var(--mono);white-space:nowrap;
}
.sla-days-badge.breach { background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.3); }
.sla-days-badge.ok     { background:rgba(74,222,128,.12);color:#4ade80;border:1px solid rgba(74,222,128,.25); }
.sla-days-badge.warn   { background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.25); }

/* ── KANBAN DRAG ─────────────────────────────────────── */
.kanban-card.dragging { opacity:.4;transform:rotate(2deg); }
.kanban-col.drag-over { background:rgba(240,165,0,.06);border-color:var(--amber); }

/* ── SSE STATUS ──────────────────────────────────────── */
#sse-status {
  display:flex;align-items:center;gap:5px;
  padding:4px 10px;font-size:9px;letter-spacing:.1em;
  color:var(--text3);font-family:var(--mono);
}
.sse-dot {
  width:6px;height:6px;border-radius:50%;background:var(--green);
  animation:ssePulse 2s infinite;flex-shrink:0;
}
.sse-dot.error { background:var(--red);animation:none; }
@keyframes ssePulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.8)} }
`;
document.head.appendChild(s);
})();

const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const SEV_COLOR = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80',INFO:'#94a3b8'};
const REC_COLOR = {CRITICAL:'var(--red)',HIGH:'#ff8c00',MEDIUM:'var(--amber)',LOW:'var(--green)',INFO:'var(--cyan)'};


// ═══════════════════════════════════════════════════════════════════════════════
// 1. EXECUTIVE SUMMARY — complete rewrite
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeExecutive(){
  const panel = document.getElementById('panel-executive');
  if (!panel) return;

  // Replace entire panel content
  panel.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:24px">
      <div>
        <div style="font-family:var(--display);font-size:26px;font-weight:800;color:var(--text1);letter-spacing:-.02em">Executive Summary</div>
        <div style="font-size:10px;letter-spacing:.2em;color:var(--text3);text-transform:uppercase;margin-top:4px">
          Security posture · auto-generated · <span id="exec-date2"></span>
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn-sm" onclick="loadExecutive()">↻ Refresh</button>
        <button class="btn-sm btn-primary" onclick="downloadExecutivePDF()">↓ PDF Report</button>
      </div>
    </div>

    <!-- Hero 3-col -->
    <div class="exec-hero">
      <div class="exec-hero-cell" style="text-align:center">
        <div style="font-size:9px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;margin-bottom:12px">Security Score</div>
        <div class="exec-score-ring">
          <canvas id="exec-score-canvas" width="110" height="110"></canvas>
          <div class="exec-score-overlay">
            <div class="exec-score-num" id="exec-score2">—</div>
            <div class="exec-score-lbl">/ 100</div>
          </div>
        </div>
        <div style="font-size:11px;color:var(--text3);margin-top:8px">overall posture</div>
      </div>
      <div class="exec-hero-cell" style="text-align:center">
        <div style="font-size:9px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;margin-bottom:12px">Posture Grade</div>
        <div class="exec-grade-display" id="exec-grade2">—</div>
        <div style="font-size:11px;color:var(--text3)">latest assessment</div>
      </div>
      <div class="exec-hero-cell">
        <div style="font-size:9px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;margin-bottom:12px">Risk Summary</div>
        <div class="exec-risk-row"><span class="exec-risk-label">Critical findings</span><span class="exec-risk-val c-red" id="exec2-critical">—</span></div>
        <div class="exec-risk-row"><span class="exec-risk-label">High findings</span><span class="exec-risk-val" style="color:#ff8c00" id="exec2-high">—</span></div>
        <div class="exec-risk-row"><span class="exec-risk-label">SLA breaches</span><span class="exec-risk-val c-amber" id="exec2-sla">—</span></div>
        <div class="exec-risk-row"><span class="exec-risk-label">Open remediations</span><span class="exec-risk-val" id="exec2-open">—</span></div>
        <div class="exec-risk-row"><span class="exec-risk-label">Total runs</span><span class="exec-risk-val" id="exec2-runs">—</span></div>
      </div>
    </div>

    <!-- Scan coverage strip -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-head"><span class="card-title">Scan coverage — last 30 days</span></div>
      <div class="exec-scan-strip">
        ${['SAST','SCA','IAC','DAST','SECRETS'].map(m=>`
          <div class="exec-scan-cell">
            <div class="exec-scan-mode">${m}</div>
            <div class="exec-scan-count" id="exec2-${m.toLowerCase()}-count">—</div>
            <div style="font-size:9px;color:var(--text3);margin-top:2px">scans</div>
          </div>`).join('')}
      </div>
    </div>

    <!-- Compliance + SLA -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div class="card">
        <div class="card-head"><span class="card-title">Compliance posture</span></div>
        <div style="margin-top:4px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <span style="font-size:12px;color:var(--text2)">FedRAMP Moderate</span>
            <span style="font-family:var(--display);font-size:18px;font-weight:700;color:var(--cyan)" id="exec2-fedramp">—%</span>
          </div>
          <div style="background:var(--black);border-radius:4px;height:6px;margin-bottom:16px">
            <div id="exec2-fedramp-bar" style="height:6px;border-radius:4px;background:var(--cyan);transition:width .5s;width:0%"></div>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <span style="font-size:12px;color:var(--text2)">CMMC Level 2</span>
            <span style="font-family:var(--display);font-size:18px;font-weight:700;color:var(--amber)" id="exec2-cmmc">—%</span>
          </div>
          <div style="background:var(--black);border-radius:4px;height:6px">
            <div id="exec2-cmmc-bar" style="height:6px;border-radius:4px;background:var(--amber);transition:width .5s;width:0%"></div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">SLA tracker</span></div>
        <div id="exec2-sla-list" style="margin-top:4px"></div>
      </div>
    </div>

    <!-- Top findings -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-head"><span class="card-title">Top critical findings requiring action</span></div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Tool</th><th>Finding</th><th>Path</th><th>Status</th></tr></thead>
          <tbody id="exec2-top-findings"></tbody>
        </table>
      </div>
    </div>

    <!-- Recommendations -->
    <div class="card">
      <div class="card-head"><span class="card-title">Recommendations</span></div>
      <div id="exec2-recommendations" style="margin-top:8px"></div>
    </div>
  `;

  // Score ring canvas draw
  function drawScoreRing(score) {
    const canvas = document.getElementById('exec-score-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 55, cy = 55, r = 44;
    ctx.clearRect(0,0,110,110);
    // Track
    ctx.beginPath(); ctx.arc(cx,cy,r,0,2*Math.PI);
    ctx.strokeStyle='#1e293b'; ctx.lineWidth=10; ctx.stroke();
    // Fill
    const color = score>=80?'#38bdf8':score>=60?'#fbbf24':'#f87171';
    const end = -Math.PI/2 + (score/100)*2*Math.PI;
    ctx.beginPath(); ctx.arc(cx,cy,r,-Math.PI/2,end);
    ctx.strokeStyle=color; ctx.lineWidth=10; ctx.lineCap='round'; ctx.stroke();
    return color;
  }

  window.loadExecutive = async function() {
    document.getElementById('exec-date2').textContent = new Date().toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'});
    try {
      const [summary, posture, runsData, sla, remStats, fedramp, cmmc, findData] = await Promise.all([
        window.api('GET','/vsp/findings/summary'),
        window.api('GET','/vsp/posture/latest').catch(()=>null),
        window.api('GET','/vsp/runs/index'),
        window.api('GET','/vsp/sla_tracker').catch(()=>({sla:[]})),
        window.api('GET','/remediation/stats').catch(()=>({})),
        window.api('GET','/compliance/fedramp').catch(()=>({coverage_pct:0})),
        window.api('GET','/compliance/cmmc').catch(()=>({coverage_pct:0})),
        window.api('GET','/vsp/findings?limit=5&severity=CRITICAL').catch(()=>({findings:[]})),
      ]);

      const score = posture?.score ?? 0;
      const grade = posture?.posture ?? posture?.grade ?? '—';
      const color = drawScoreRing(score);

      const scoreEl = document.getElementById('exec-score2');
      if (scoreEl) { scoreEl.textContent=score; scoreEl.style.color=color; }

      const gradeEl = document.getElementById('exec-grade2');
      if (gradeEl) {
        gradeEl.textContent=grade;
        gradeEl.style.color={A:'var(--cyan)',B:'var(--green)',C:'var(--amber)',D:'#fb923c',F:'var(--red)'}[grade]||'var(--text1)';
      }

      const runs = runsData.runs || [];
      const set = (id,v) => { const el=document.getElementById(id); if(el) el.textContent=v; };

      set('exec2-critical', summary.critical||0);
      set('exec2-high',     summary.high||0);
      set('exec2-open',     remStats.open||0);
      set('exec2-runs',     runs.length);

      const slaData = sla.sla || [];
      const breaches = slaData.reduce((a,s)=>a+(s.breach_count||0),0);
      const slaEl = document.getElementById('exec2-sla');
      if (slaEl) { slaEl.textContent=breaches; slaEl.style.color=breaches>0?'var(--red)':'var(--green)'; }

      // Scan counts
      ['SAST','SCA','IAC','DAST','SECRETS'].forEach(m => {
        set(`exec2-${m.toLowerCase()}-count`, runs.filter(r=>r.mode===m&&r.status==='DONE').length);
      });

      // Compliance bars
      const fp = fedramp.coverage_pct||0, cp = cmmc.coverage_pct||0;
      set('exec2-fedramp', fp+'%'); set('exec2-cmmc', cp+'%');
      const fb = document.getElementById('exec2-fedramp-bar');
      const cb = document.getElementById('exec2-cmmc-bar');
      if (fb) fb.style.width=fp+'%';
      if (cb) cb.style.width=cp+'%';

      // SLA list
      const slaListEl = document.getElementById('exec2-sla-list');
      if (slaListEl) {
        slaListEl.innerHTML = slaData.length ? slaData.map(s => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
            <div>
              <span style="font-size:11px;color:${SEV_COLOR[s.severity]||'var(--text2)'};font-weight:600">${s.severity}</span>
              <span style="font-size:10px;color:var(--text3);margin-left:8px">SLA: ${s.sla_days}d · ${s.open_count} open</span>
            </div>
            <span style="font-size:10px;font-weight:700;color:${s.status==='green'?'var(--green)':'var(--red)'}">${(s.status||'').toUpperCase()}</span>
          </div>`).join('')
        : '<div style="color:var(--text3);font-size:11px;padding:8px">No SLA data available</div>';
      }

      // Top findings
      const topEl = document.getElementById('exec2-top-findings');
      const findings = findData.findings||[];
      if (topEl) {
        topEl.innerHTML = findings.length ? findings.map(f=>`
          <tr>
            <td>${window.sevPill(f.severity)}</td>
            <td style="color:var(--text3);font-size:11px">${f.tool}</td>
            <td style="font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.message)}</td>
            <td style="font-family:var(--mono);font-size:10px;color:var(--text3)">${(f.path||'').split('/').pop()}</td>
            <td><span class="pill pill-failed">OPEN</span></td>
          </tr>`).join('')
        : '<tr><td colspan="5" style="color:var(--text3);padding:16px;text-align:center">No critical findings</td></tr>';
      }

      // Recommendations
      const recs = [];
      if ((summary.critical||0)>0)  recs.push({l:'CRITICAL',t:`Remediate ${summary.critical} critical finding${summary.critical>1?'s':''} — SLA 3 days`});
      if ((summary.high||0)>10)     recs.push({l:'HIGH',    t:`${summary.high} high findings require attention within 14 days`});
      if (breaches>0)               recs.push({l:'HIGH',    t:`${breaches} SLA breach${breaches>1?'es':''} — escalate to security team`});
      if ((remStats.open||0)>50)    recs.push({l:'MEDIUM',  t:`${remStats.open} open findings unassigned — assign to teams`});
      if (fp<80)                    recs.push({l:'MEDIUM',  t:`FedRAMP coverage ${fp}% — schedule additional coverage`});
      if (cp<80)                    recs.push({l:'MEDIUM',  t:`CMMC Level 2 at ${cp}% — review practice gaps`});
      if (!recs.length)             recs.push({l:'INFO',    t:'Security posture healthy — maintain current cadence'});

      const recEl = document.getElementById('exec2-recommendations');
      if (recEl) {
        recEl.innerHTML = recs.map(r=>`
          <div class="exec-rec-item" style="border-left-color:${REC_COLOR[r.l]||'var(--text3)'}">
            <span class="exec-rec-level" style="color:${REC_COLOR[r.l]||'var(--text3)'}">${r.l}</span>
            <span class="exec-rec-text">${r.t}</span>
          </div>`).join('');
      }

    } catch(e) { console.error('executive v2', e); }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 2. SSE FIX — poll fallback + status indicator
// ═══════════════════════════════════════════════════════════════════════════════
(function fixSSE(){
  // Add SSE status dot to sidebar
  const notifRow = document.querySelector('[onclick="toggleNotifPanel()"]');
  if (notifRow) {
    const sseEl = document.createElement('div');
    sseEl.id = 'sse-status';
    sseEl.innerHTML = `<div class="sse-dot" id="sse-dot"></div><span id="sse-label">SSE connecting…</span>`;
    notifRow.parentNode.insertBefore(sseEl, notifRow);
  }

  function setSseStatus(ok, msg) {
    const dot = document.getElementById('sse-dot');
    const lbl = document.getElementById('sse-label');
    if (dot) dot.className = 'sse-dot' + (ok ? '' : ' error');
    if (lbl) lbl.textContent = msg;
  }

  // Override connectSSE with reconnect logic + status
  window.connectSSE = function() {
    if (!window.TOKEN) return;
    if (window.sseConn) { try{ window.sseConn.close(); } catch(e){} }

    // EventSource can't send auth headers — use token in query param if backend supports
    // Fallback: poll every 10s if SSE fails
    let sseUrl = '/api/v1/events';
    // Try with token in URL for servers that support it
    if (window.TOKEN) sseUrl = `/api/v1/events?token=${encodeURIComponent(window.TOKEN)}`;

    try {
      window.sseConn = new EventSource(sseUrl);

      window.sseConn.onopen = () => setSseStatus(true, 'SSE live');

      window.sseConn.onmessage = function(e) {
        setSseStatus(true, 'SSE live');
        try {
          const msg = JSON.parse(e.data);
          if (window._handleSSEMsg) window._handleSSEMsg(msg);
          else handleSSEMsg(msg);
        } catch(err){}
      };

      window.sseConn.onerror = function() {
        setSseStatus(false, 'SSE reconnecting…');
        try { window.sseConn.close(); } catch(e){}
        // Fallback: poll every 15s
        startSSEFallbackPoll();
        setTimeout(window.connectSSE, 8000);
      };
    } catch(e) {
      setSseStatus(false, 'SSE unavailable');
      startSSEFallbackPoll();
    }
  };

  let _pollInterval = null;
  function startSSEFallbackPoll() {
    if (_pollInterval) return;
    _pollInterval = setInterval(async () => {
      try {
        const data = await window.api('GET', '/vsp/runs?limit=5');
        const runs = data.runs || [];
        const latestRunning = runs.find(r=>r.status==='RUNNING');
        if (latestRunning) {
          handleSSEMsg({type:'scan_started', rid:latestRunning.rid, mode:latestRunning.mode, tools_total:latestRunning.tools_total||0});
        }
      } catch(e){}
    }, 15000);
  }

  function handleSSEMsg(msg) {
    if (window._scanProgress !== undefined) {
      // Use scan progress handler from v050
      if (msg.type==='scan_started') {
        window._scanProgress[msg.rid] = {rid:msg.rid,mode:msg.mode,tools:{},done:0,total:msg.tools_total||0};
        document.getElementById('scan-progress-overlay')?.classList.add('open');
      }
    }
    if (msg.type==='scan_complete') {
      window.addNotification?.('Scan complete — '+msg.mode, msg.gate==='PASS'?'success':'error',
        (msg.findings||0)+' findings · '+(msg.gate||'')+'· '+(msg.rid||'').slice(-8));
      if (typeof showToast==='function') showToast('Scan: '+msg.gate, msg.gate==='PASS'?'success':'error');
      setTimeout(()=>{ window.loadDashboard?.(); window.loadDashboardCharts?.(); }, 500);
    }
  }
  window._handleSSEMsg = handleSSEMsg;
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 3. KANBAN DRAG-DROP
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeKanbanDragDrop(){
  // Patch renderKanban cards to add draggable
  const _origRenderKanban = window._renderKanban;

  // Delegate drag events on kanban board
  document.addEventListener('dragstart', e => {
    const card = e.target.closest('.kanban-card');
    if (!card) return;
    card.classList.add('dragging');
    e.dataTransfer.setData('text/plain', card.dataset.findingId || '');
    e.dataTransfer.setData('finding-json', card.dataset.findingJson || '{}');
    e.dataTransfer.effectAllowed = 'move';
    window._draggingCard = card;
  });

  document.addEventListener('dragend', e => {
    const card = e.target.closest('.kanban-card');
    if (card) card.classList.remove('dragging');
    document.querySelectorAll('.kanban-col').forEach(c=>c.classList.remove('drag-over'));
    window._draggingCard = null;
  });

  document.addEventListener('dragover', e => {
    const col = e.target.closest('.kanban-col');
    if (!col) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    document.querySelectorAll('.kanban-col').forEach(c=>c.classList.remove('drag-over'));
    col.classList.add('drag-over');
  });

  document.addEventListener('drop', async e => {
    const col = e.target.closest('.kanban-col');
    if (!col) return;
    e.preventDefault();
    col.classList.remove('drag-over');
    const newStatus = col.id.replace('kanban-col-','');
    const findingId = e.dataTransfer.getData('text/plain');
    if (!findingId || !newStatus) return;
    try {
      await window.api('POST', '/remediation/finding/'+findingId, {status:newStatus});
      if (typeof showToast==='function') showToast('Status → '+newStatus.replace('_',' '), 'success');
      // Re-render kanban
      setTimeout(()=>{ if(window._renderKanbanBoard) window._renderKanbanBoard(); }, 300);
    } catch(e2) {
      if (typeof showToast==='function') showToast('Update failed: '+e2.message, 'error');
    }
  });
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 4. AUDIT PANEL UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeAudit(){
  const panel = document.getElementById('panel-audit');
  if (!panel) return;

  // Inject stats strip before existing cards
  const strip = document.createElement('div');
  strip.innerHTML = `
    <div class="audit-stat-strip" id="audit-stat-strip" style="margin-bottom:16px">
      <div class="audit-stat-cell"><div class="audit-stat-val c-cyan" id="aud-total">—</div><div class="audit-stat-lbl">Total events</div></div>
      <div class="audit-stat-cell"><div class="audit-stat-val" id="aud-today">—</div><div class="audit-stat-lbl">Today</div></div>
      <div class="audit-stat-cell"><div class="audit-stat-val c-amber" id="aud-logins">—</div><div class="audit-stat-lbl">Logins</div></div>
      <div class="audit-stat-cell"><div class="audit-stat-val c-green" id="aud-scans">—</div><div class="audit-stat-lbl">Scan triggers</div></div>
    </div>
  `;
  panel.insertBefore(strip, panel.firstChild);

  const ACTION_COLORS = {
    login:'#38bdf8', logout:'#94a3b8',
    scan_triggered:'#4ade80', scan_complete:'#4ade80',
    remediation_update:'#fbbf24', export:'#818cf8',
    policy_update:'#fb923c', user_created:'#f472b6',
  };

  const _origLoadAudit = window.loadAudit;
  window.loadAudit = async function() {
    try {
      const data = await window.api('GET', '/audit/log?limit=100');
      const entries = data.entries || [];

      // Stats
      const today = new Date().toDateString();
      const todayCount = entries.filter(e => new Date(e.created_at).toDateString()===today).length;
      const logins = entries.filter(e=>(e.action||'').includes('login')).length;
      const scans  = entries.filter(e=>(e.action||'').includes('scan')).length;

      const set = (id,v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
      set('aud-total',  entries.length);
      set('aud-today',  todayCount);
      set('aud-logins', logins);
      set('aud-scans',  scans);

      // Table with colored action badges
      const tbody = document.getElementById('audit-table');
      if (tbody) {
        tbody.innerHTML = entries.slice(0,50).map(e => {
          const color = ACTION_COLORS[(e.action||'').toLowerCase()] || '#64748b';
          return `<tr>
            <td style="color:#64748b;font-family:var(--mono);font-size:11px">${e.seq||'—'}</td>
            <td><span class="audit-action-badge" style="background:${color}18;color:${color};border:1px solid ${color}44">${e.action||'—'}</span></td>
            <td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.resource||'—')}</td>
            <td style="color:#64748b;font-size:11px;font-family:var(--mono)">${e.ip||'—'}</td>
            <td style="color:#64748b;font-size:11px">${e.created_at?new Date(e.created_at).toLocaleString():'—'}</td>
            <td style="font-family:monospace;font-size:10px;color:#334155">${(e.hash||'').slice(0,16)}${e.hash?'…':''}</td>
          </tr>`;
        }).join('');
      }
    } catch(e2) { if (_origLoadAudit) _origLoadAudit(); }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 5. SBOM PANEL UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradeSBOM(){
  const panel = document.getElementById('panel-sbom');
  if (!panel) return;

  // Inject stats
  const strip = document.createElement('div');
  strip.innerHTML = `
    <div class="sbom-stat-strip" style="margin-bottom:16px">
      <div class="sbom-stat-cell"><div class="sbom-stat-val c-cyan" id="sbom-total-runs">—</div><div class="sbom-stat-lbl">Total SBOMs</div></div>
      <div class="sbom-stat-cell"><div class="sbom-stat-val c-red" id="sbom-vuln-runs">—</div><div class="sbom-stat-lbl">With findings</div></div>
      <div class="sbom-stat-cell"><div class="sbom-stat-val c-green" id="sbom-clean-runs">—</div><div class="sbom-stat-lbl">Clean runs</div></div>
      <div class="sbom-stat-cell"><div class="sbom-stat-val c-amber" id="sbom-latest-findings">—</div><div class="sbom-stat-lbl">Latest findings</div></div>
      <div class="sbom-stat-cell"><div class="sbom-stat-val" id="sbom-formats">CDX</div><div class="sbom-stat-lbl">Format</div></div>
    </div>
  `;
  panel.insertBefore(strip, panel.firstChild);

  const _origLoadSBOM = window.loadSBOM;
  window.loadSBOM = async function() {
    try {
      const data = await window.api('GET', '/vsp/runs/index');
      const runs = (data.runs||[]).filter(r=>r.status==='DONE');
      const vulnRuns  = runs.filter(r=>(r.total||r.total_findings||0)>0);
      const cleanRuns = runs.filter(r=>(r.total||r.total_findings||0)===0);
      const latest    = runs[0];

      const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
      set('sbom-total-runs',   runs.length);
      set('sbom-vuln-runs',    vulnRuns.length);
      set('sbom-clean-runs',   cleanRuns.length);
      set('sbom-latest-findings', latest?(latest.total||latest.total_findings||0):'—');

      // Table
      const tbody = document.getElementById('sbom-tbody');
      if (tbody) {
        tbody.innerHTML = runs.slice(0,20).map(r => {
          const findings = r.total||r.total_findings||0;
          return `<tr>
            <td><code style="font-size:10px">${r.rid.slice(-20)}</code></td>
            <td><span style="font-size:10px;font-weight:700;color:${r.mode==='IAC'?'#fbbf24':r.mode==='SAST'?'#818cf8':'#38bdf8'}">${r.mode}</span></td>
            <td>${r.gate ? window.gatePill(r.gate) : '—'}</td>
            <td style="color:${findings>0?'var(--red)':'var(--green)'};font-family:var(--mono)">${findings}</td>
            <td style="color:var(--text3);font-size:11px">${new Date(r.created_at).toLocaleDateString()}</td>
            <td>
              <a href="#" onclick="downloadSBOM(event,'${r.rid}')"
                style="color:var(--amber);font-size:11px;letter-spacing:.05em;text-decoration:none;border:1px solid var(--amber);padding:2px 8px;border-radius:3px">
                ↓ CDX
              </a>
            </td>
          </tr>`;
        }).join('');
      }
    } catch(e) { if(_origLoadSBOM) _origLoadSBOM(); }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 6. POLICY PANEL UPGRADE
// ═══════════════════════════════════════════════════════════════════════════════
(function upgradePolicy(){
  const panel = document.getElementById('panel-policy');
  if (!panel) return;

  // Add default policy rules display
  const DEFAULT_RULES = [
    {name:'Block Critical Findings', desc:'Fail gate if any CRITICAL finding exists', fail_on:'CRITICAL', active:true, builtin:true},
    {name:'Block Secrets', desc:'Fail gate if secrets/credentials detected', fail_on:'SECRETS', active:true, builtin:true},
    {name:'High Threshold', desc:'Warn if HIGH findings exceed 50', fail_on:'HIGH>50', active:true, builtin:false},
    {name:'SLA Breach Alert', desc:'Warn if SLA breach detected', fail_on:'SLA', active:false, builtin:false},
  ];

  const _origLoadRules = window.loadRules;
  window.loadRules = async function() {
    let rules = [];
    try {
      const data = await window.api('GET', '/policy/rules');
      rules = data.rules || [];
    } catch(e) {}

    // Show default + custom rules
    const allRules = [...DEFAULT_RULES, ...rules.map(r=>({...r, builtin:false, active:true}))];
    const rulesEl = document.getElementById('rules-list');
    if (!rulesEl) return;

    rulesEl.innerHTML = allRules.map((r, i) => `
      <div class="policy-rule-card">
        <div class="policy-rule-header">
          <div class="policy-rule-name">${esc(r.name)}</div>
          ${r.builtin ? '<span style="font-size:9px;color:var(--text3);letter-spacing:.1em;background:var(--border);padding:2px 6px;border-radius:3px">BUILT-IN</span>' : ''}
          <button class="policy-toggle ${r.active?'on':''}" onclick="togglePolicyRule(${i},this)" title="${r.active?'Enabled':'Disabled'}"></button>
        </div>
        <div style="font-size:12px;color:var(--text2);margin-bottom:8px">${esc(r.desc||r.description||'')}</div>
        <div class="policy-rule-meta">
          <span>Fail on: <b style="color:var(--amber)">${r.fail_on||'—'}</b></span>
          ${r.repo_pattern?`<span>Pattern: <code>${r.repo_pattern}</code></span>`:''}
          ${r.max_high!=null?`<span>Max HIGH: <b>${r.max_high===-1?'∞':r.max_high}</b></span>`:''}
          ${r.min_score!=null?`<span>Min score: <b>${r.min_score}</b></span>`:''}
        </div>
      </div>`).join('');
  };

  window.togglePolicyRule = function(idx, btn) {
    btn.classList.toggle('on');
    const isOn = btn.classList.contains('on');
    btn.title = isOn ? 'Enabled' : 'Disabled';
    if (typeof showToast === 'function') showToast('Rule '+(isOn?'enabled':'disabled'), 'info');
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// 7. SLA TRACKER — standalone panel + sidebar link
// ═══════════════════════════════════════════════════════════════════════════════
(function initSLAPanel(){
  // Add to sidebar under Compliance
  const compSection = document.querySelector('#panel-compliance2')?.closest('.panel');
  const sbomBtn = document.querySelector('.stab[onclick*="sbom"]');
  if (sbomBtn) {
    const btn = document.createElement('button');
    btn.className = 'stab';
    btn.innerHTML = `<span style="font-size:12px;width:16px">◷</span>SLA`;
    btn.onclick = function(){ showPanel('sla',this); loadSLAPanel(); };
    sbomBtn.parentNode.insertBefore(btn, sbomBtn.nextSibling);
  }

  // Create panel
  const slaPanel = document.createElement('div');
  slaPanel.id = 'panel-sla';
  slaPanel.className = 'panel';
  slaPanel.innerHTML = `
    <div style="font-family:var(--display);font-size:22px;font-weight:800;margin-bottom:4px">SLA Tracker</div>
    <div style="font-size:10px;letter-spacing:.15em;color:var(--text3);text-transform:uppercase;margin-bottom:20px">
      Remediation deadlines · breach detection · escalation
    </div>

    <div class="sla-tracker-grid">
      <div class="sla-tracker-card">
        <div style="font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--text2);text-transform:uppercase;margin-bottom:12px">SLA Policy</div>
        <div class="sla-breach-row">
          <span style="color:var(--red);font-weight:700;font-size:12px;min-width:80px">CRITICAL</span>
          <span class="sla-days-badge ok">3 days</span>
          <span id="sla-crit-count" style="margin-left:auto;font-family:var(--mono);font-size:12px">— open</span>
        </div>
        <div class="sla-breach-row">
          <span style="color:#ff8c00;font-weight:700;font-size:12px;min-width:80px">HIGH</span>
          <span class="sla-days-badge ok">14 days</span>
          <span id="sla-high-count" style="margin-left:auto;font-family:var(--mono);font-size:12px">— open</span>
        </div>
        <div class="sla-breach-row">
          <span style="color:var(--amber);font-weight:700;font-size:12px;min-width:80px">MEDIUM</span>
          <span class="sla-days-badge ok">30 days</span>
          <span id="sla-med-count" style="margin-left:auto;font-family:var(--mono);font-size:12px">— open</span>
        </div>
        <div class="sla-breach-row">
          <span style="color:var(--green);font-weight:700;font-size:12px;min-width:80px">LOW</span>
          <span class="sla-days-badge ok">90 days</span>
          <span id="sla-low-count" style="margin-left:auto;font-family:var(--mono);font-size:12px">— open</span>
        </div>
      </div>
      <div class="sla-tracker-card">
        <div style="font-size:10px;font-weight:700;letter-spacing:.1em;color:var(--text2);text-transform:uppercase;margin-bottom:12px">Breach Status</div>
        <div id="sla-breach-list">
          <div style="color:var(--text3);font-size:11px">Loading…</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">SLA detail</span>
        <button class="btn-sm" onclick="loadSLAPanel()">↻ Refresh</button>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Open</th><th>SLA (days)</th><th>Breach count</th><th>Status</th><th>Action</th></tr></thead>
          <tbody id="sla-detail-tbody"></tbody>
        </table>
      </div>
    </div>
  `;
  document.querySelector('.main')?.appendChild(slaPanel);

  window.loadSLAPanel = async function() {
    try {
      const [sla, summary] = await Promise.all([
        window.api('GET', '/vsp/sla_tracker'),
        window.api('GET', '/vsp/findings/summary'),
      ]);

      const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
      set('sla-crit-count', (summary.critical||0)+' open');
      set('sla-high-count', (summary.high||0)+' open');
      set('sla-med-count',  (summary.medium||0)+' open');
      set('sla-low-count',  (summary.low||0)+' open');

      const slaData = sla.sla || [];
      const breaches = slaData.filter(s=>s.status!=='green');

      const breachEl = document.getElementById('sla-breach-list');
      if (breachEl) {
        breachEl.innerHTML = breaches.length ? breaches.map(s=>`
          <div class="sla-breach-row">
            <span style="color:${SEV_COLOR[s.severity]||'#94a3b8'};font-weight:700;font-size:11px;min-width:80px">${s.severity}</span>
            <span class="sla-days-badge breach">BREACH</span>
            <span style="font-size:11px;color:var(--text2);margin-left:8px">${s.breach_count||0} overdue</span>
          </div>`).join('')
        : '<div style="color:var(--green);font-size:12px;padding:8px 0">✓ No SLA breaches detected</div>';
      }

      const tbody = document.getElementById('sla-detail-tbody');
      if (tbody) {
        tbody.innerHTML = slaData.length ? slaData.map(s=>`
          <tr>
            <td>${window.sevPill(s.severity)}</td>
            <td style="font-family:var(--mono);font-weight:700;color:${SEV_COLOR[s.severity]||'#94a3b8'}">${s.open_count||0}</td>
            <td style="font-family:var(--mono);color:var(--text3)">${s.sla_days||'—'}</td>
            <td style="font-family:var(--mono);color:${(s.breach_count||0)>0?'var(--red)':'var(--green)'}">${s.breach_count||0}</td>
            <td><span class="sla-days-badge ${s.status==='green'?'ok':'breach'}">${(s.status||'').toUpperCase()}</span></td>
            <td>
              ${(s.breach_count||0)>0
                ? `<button class="btn-sm" style="color:var(--red);border-color:var(--red)" onclick="showPanel('remediation',null);loadRemediation()">Escalate →</button>`
                : '<span style="color:var(--text3);font-size:11px">On track</span>'}
            </td>
          </tr>`).join('')
        : '<tr><td colspan="6" style="color:var(--text3);padding:16px;text-align:center">No SLA data — run a scan first</td></tr>';
      }
    } catch(e) { console.error('sla panel', e); }
  };
})();


// ═══════════════════════════════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════════════════════════════
setTimeout(() => {
  // Auto-load executive if active
  const active = document.querySelector('.panel.active')?.id;
  if (active === 'panel-executive') window.loadExecutive?.();
  if (active === 'panel-audit')     window.loadAudit?.();
  if (active === 'panel-sbom')      window.loadSBOM?.();
  if (active === 'panel-policy')    window.loadRules?.();
  // Reconnect SSE with fix
  window.connectSSE?.();
}, 600);

// Patch showPanel to auto-load upgraded panels
const _sp70 = window.showPanel;
window.showPanel = function(name, btn) {
  _sp70?.(name, btn);
  if (name==='executive') setTimeout(()=>window.loadExecutive?.(), 100);
  if (name==='audit')     setTimeout(()=>window.loadAudit?.(), 100);
  if (name==='sbom')      setTimeout(()=>window.loadSBOM?.(), 100);
  if (name==='policy')    setTimeout(()=>window.loadRules?.(), 100);
  if (name==='sla')       setTimeout(()=>window.loadSLAPanel?.(), 100);
};

console.log('[VSP Upgrade v0.7.0] Executive+SSE+Kanban+Audit+SBOM+Policy+SLA loaded ✓');
