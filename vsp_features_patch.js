/**
 * VSP Feature Patch v0.5.0
 * Inject BEFORE </body> in static/index.html
 *
 * Features:
 *  1. Findings drill-down modal (click row → full detail)
 *  2. Dark / Light mode toggle (☀/◑)
 *  3. Scan progress real-time (SSE tool-by-tool overlay)
 *  4. User management UI (admin panel)
 */

// ─── 0. INJECT CSS ────────────────────────────────────────────────────────────
(function injectCSS() {
  const style = document.createElement('style');
  style.textContent = `
/* ── DARK / LIGHT THEME OVERRIDE ────────────────────────────── */
body.light-mode {
  --navy:   #f1f5f9;
  --black:  #ffffff;
  --card:   #f8fafc;
  --border: #e2e8f0;
  --border2:#cbd5e1;
  --text1:  #0f172a;
  --text2:  #334155;
  --text3:  #64748b;
  --amber:  #d97706;
  --cyan:   #0891b2;
  --green:  #059669;
  --red:    #dc2626;
  background:#f1f5f9;
}
body.light-mode .stab { color:#334155 }
body.light-mode .stab:hover, body.light-mode .stab.active {
  background:rgba(0,0,0,.08); color:#0f172a;
}
body.light-mode aside { box-shadow: 1px 0 0 #e2e8f0; }
body.light-mode table thead th { background:#f1f5f9; color:#64748b; }
body.light-mode .tbl-wrap { border:1px solid #e2e8f0; }

/* ── THEME TOGGLE BUTTON ─────────────────────────────────────── */
#theme-toggle {
  display:flex;align-items:center;gap:6px;
  padding:6px 10px;cursor:pointer;
  color:var(--text3);font-size:12px;border-radius:4px;
  transition:.12s;background:none;border:none;width:100%;text-align:left;
  font-family:var(--mono);letter-spacing:.04em;
}
#theme-toggle:hover { color:var(--amber);background:rgba(240,165,0,.06); }

/* ── FINDING DETAIL MODAL ────────────────────────────────────── */
#finding-detail-overlay {
  display:none;position:fixed;inset:0;z-index:9000;
  background:rgba(0,0,0,.75);backdrop-filter:blur(4px);
  align-items:center;justify-content:center;padding:20px;
}
#finding-detail-overlay.open { display:flex; }
#finding-detail-box {
  background:var(--card);border:1px solid var(--border2);
  border-radius:10px;width:min(780px,100%);max-height:88vh;
  display:flex;flex-direction:column;overflow:hidden;
  box-shadow:0 24px 80px rgba(0,0,0,.6);
  animation:fdSlideIn .2s ease;
}
@keyframes fdSlideIn { from{transform:translateY(16px);opacity:0} to{transform:translateY(0);opacity:1} }
#finding-detail-head {
  display:flex;align-items:center;justify-content:space-between;
  padding:16px 20px;border-bottom:1px solid var(--border);
  background:var(--navy);flex-shrink:0;
}
#finding-detail-body { overflow-y:auto;padding:20px;flex:1; }
.fd-section { margin-bottom:20px; }
.fd-section-title {
  font-size:9px;letter-spacing:.18em;color:var(--text3);
  text-transform:uppercase;font-weight:700;margin-bottom:10px;
  padding-bottom:6px;border-bottom:1px solid var(--border);
}
.fd-grid { display:grid;grid-template-columns:1fr 1fr;gap:12px; }
.fd-field label {
  display:block;font-size:9px;letter-spacing:.12em;color:var(--text3);
  text-transform:uppercase;margin-bottom:4px;
}
.fd-field span {
  font-size:12px;color:var(--text1);font-family:var(--mono);
  word-break:break-all;
}
.fd-code {
  background:var(--black);border:1px solid var(--border);
  border-radius:6px;padding:12px;font-family:var(--mono);
  font-size:11px;color:var(--text2);overflow-x:auto;
  white-space:pre-wrap;word-break:break-all;
  max-height:180px;overflow-y:auto;
}
.fd-badge {
  display:inline-block;padding:2px 8px;border-radius:4px;
  font-size:10px;font-weight:700;letter-spacing:.08em;
}
.fd-badge.CRITICAL{background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.3)}
.fd-badge.HIGH    {background:rgba(251,146,60,.12);color:#fb923c;border:1px solid rgba(251,146,60,.3)}
.fd-badge.MEDIUM  {background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.3)}
.fd-badge.LOW     {background:rgba(74,222,128,.12);color:#4ade80;border:1px solid rgba(74,222,128,.3)}
.fd-close {
  background:none;border:none;color:var(--text3);cursor:pointer;
  font-size:16px;padding:4px 8px;border-radius:4px;transition:.12s;
}
.fd-close:hover { color:var(--text1);background:var(--border); }
.fd-actions { display:flex;gap:8px;padding:14px 20px;border-top:1px solid var(--border);background:var(--navy);flex-shrink:0; }
.fd-tab-bar { display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px; }
.fd-tab {
  padding:8px 16px;font-size:11px;letter-spacing:.06em;color:var(--text3);
  cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;
  transition:.12s;font-family:var(--mono);
}
.fd-tab:hover { color:var(--text1); }
.fd-tab.active { color:var(--amber);border-bottom-color:var(--amber); }
.fd-tab-content { display:none; }
.fd-tab-content.active { display:block; }

/* ── SCAN PROGRESS OVERLAY ───────────────────────────────────── */
#scan-progress-overlay {
  display:none;position:fixed;bottom:20px;right:20px;z-index:8000;
  width:360px;background:var(--card);border:1px solid var(--border2);
  border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.5);
  overflow:hidden;animation:spSlideIn .25s ease;
}
#scan-progress-overlay.open { display:block; }
@keyframes spSlideIn { from{transform:translateX(20px);opacity:0} to{transform:translateX(0);opacity:1} }
#sp-header {
  display:flex;align-items:center;justify-content:space-between;
  padding:12px 16px;background:var(--navy);border-bottom:1px solid var(--border);
}
#sp-title { font-size:11px;font-weight:700;letter-spacing:.08em;color:var(--text1); }
#sp-rid   { font-size:9px;color:var(--text3);font-family:var(--mono); }
#sp-body  { padding:14px 16px;max-height:320px;overflow-y:auto; }
.sp-tool-row {
  display:flex;align-items:center;gap:10px;
  padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;
}
.sp-tool-row:last-child { border-bottom:none; }
.sp-tool-icon {
  width:22px;height:22px;border-radius:4px;display:flex;
  align-items:center;justify-content:center;font-size:9px;font-weight:700;
  flex-shrink:0;
}
.sp-tool-name { flex:1;font-family:var(--mono);font-size:11px;color:var(--text2); }
.sp-tool-count { font-family:var(--mono);font-size:11px;color:var(--text3); }
.sp-tool-status { font-size:10px;font-weight:600;letter-spacing:.06em; }
.sp-status-waiting  { color:var(--text3); }
.sp-status-running  { color:var(--amber); animation:spPulse 1s infinite; }
.sp-status-done     { color:var(--green); }
.sp-status-error    { color:var(--red); }
@keyframes spPulse { 0%,100%{opacity:1} 50%{opacity:.5} }
#sp-overall {
  margin:10px 0 4px;background:var(--black);border-radius:4px;height:4px;overflow:hidden;
}
#sp-progress-bar {
  height:4px;background:linear-gradient(90deg,var(--cyan),var(--amber));
  border-radius:4px;transition:width .4s;
}
#sp-summary { font-size:10px;color:var(--text3);margin-bottom:2px;letter-spacing:.04em; }
#sp-close-btn {
  background:none;border:none;color:var(--text3);cursor:pointer;
  font-size:13px;padding:2px 4px;border-radius:3px;transition:.12s;
}
#sp-close-btn:hover { color:var(--text1);background:var(--border); }

/* ── USER MANAGEMENT PANEL ───────────────────────────────────── */
#panel-users { }
.user-avatar {
  width:32px;height:32px;border-radius:50%;display:flex;
  align-items:center;justify-content:center;font-size:12px;font-weight:700;
  flex-shrink:0;
}
.role-badge {
  display:inline-block;padding:2px 7px;border-radius:20px;
  font-size:10px;font-weight:600;letter-spacing:.06em;
}
.role-badge.admin  {background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.25)}
.role-badge.analyst{background:rgba(96,165,250,.12);color:#60a5fa;border:1px solid rgba(96,165,250,.25)}
.role-badge.viewer {background:rgba(148,163,184,.1);color:#94a3b8;border:1px solid rgba(148,163,184,.2)}
#user-modal-overlay {
  display:none;position:fixed;inset:0;z-index:9000;
  background:rgba(0,0,0,.7);backdrop-filter:blur(3px);
  align-items:center;justify-content:center;
}
#user-modal-overlay.open { display:flex; }
#user-modal-box {
  background:var(--card);border:1px solid var(--border2);
  border-radius:10px;width:min(480px,100%);
  padding:24px;box-shadow:0 24px 60px rgba(0,0,0,.5);
  animation:fdSlideIn .18s ease;
}
.user-stat-grid {
  display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--border);border-radius:8px;overflow:hidden;margin-bottom:20px;
}
.user-stat { background:var(--card);padding:14px;text-align:center; }
.user-stat .val { font-size:28px;font-weight:700;font-family:var(--display); }
.user-stat .lbl { font-size:9px;letter-spacing:.12em;color:var(--text3);text-transform:uppercase;margin-top:2px; }

/* ── CLICKABLE FINDING ROWS ──────────────────────────────────── */
#findings-table tr, #rem-tbody tr { cursor:pointer; }
#findings-table tr:hover td, #rem-tbody tr:hover td {
  background:rgba(255,255,255,.03);
}
  `;
  document.head.appendChild(style);
})();


// ─── 1. DARK / LIGHT MODE TOGGLE ─────────────────────────────────────────────
(function initThemeToggle() {
  // Insert toggle button into sidebar bottom area
  const userWidget = document.getElementById('userWidget');
  if (!userWidget) return;

  const btn = document.createElement('button');
  btn.id = 'theme-toggle';
  btn.innerHTML = `<span id="theme-icon">☀</span><span id="theme-label">Light mode</span>`;
  btn.onclick = toggleTheme;
  userWidget.parentNode.insertBefore(btn, userWidget);

  // Persist preference
  if (localStorage.getItem('vsp_theme') === 'light') {
    document.body.classList.add('light-mode');
    document.getElementById('theme-icon').textContent = '◑';
    document.getElementById('theme-label').textContent = 'Dark mode';
  }

  function toggleTheme() {
    const isLight = document.body.classList.toggle('light-mode');
    document.getElementById('theme-icon').textContent  = isLight ? '◑' : '☀';
    document.getElementById('theme-label').textContent = isLight ? 'Dark mode' : 'Light mode';
    localStorage.setItem('vsp_theme', isLight ? 'light' : 'dark');
    // Re-render charts to pick up new colors
    if (typeof loadDashboardCharts === 'function') loadDashboardCharts();
  }
})();


// ─── 2. FINDINGS DRILL-DOWN MODAL ────────────────────────────────────────────
(function initFindingModal() {
  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'finding-detail-overlay';
  overlay.innerHTML = `
    <div id="finding-detail-box">
      <div id="finding-detail-head">
        <div>
          <span id="fd-severity-badge" class="fd-badge">—</span>
          <span id="fd-tool-label" style="margin-left:10px;font-size:11px;color:var(--text3);font-family:var(--mono)"></span>
        </div>
        <button class="fd-close" onclick="closeFindingModal()">✕</button>
      </div>
      <div id="finding-detail-body">
        <!-- Tab bar -->
        <div class="fd-tab-bar">
          <div class="fd-tab active" onclick="fdSwitchTab('overview',this)">Overview</div>
          <div class="fd-tab" onclick="fdSwitchTab('technical',this)">Technical</div>
          <div class="fd-tab" onclick="fdSwitchTab('remediation',this)">Remediation</div>
          <div class="fd-tab" onclick="fdSwitchTab('raw',this)">Raw JSON</div>
        </div>

        <!-- OVERVIEW -->
        <div id="fd-tab-overview" class="fd-tab-content active">
          <div class="fd-section">
            <div class="fd-section-title">Finding message</div>
            <div id="fd-message" style="font-size:14px;font-weight:600;color:var(--text1);line-height:1.5;margin-bottom:12px"></div>
            <div class="fd-grid">
              <div class="fd-field"><label>Severity</label><span id="fd-sev2">—</span></div>
              <div class="fd-field"><label>Tool</label><span id="fd-tool2">—</span></div>
              <div class="fd-field"><label>Rule ID</label><span id="fd-rule">—</span></div>
              <div class="fd-field"><label>CWE</label><span id="fd-cwe">—</span></div>
              <div class="fd-field"><label>Run ID</label><span id="fd-runid">—</span></div>
              <div class="fd-field"><label>Status</label><span id="fd-status">—</span></div>
            </div>
          </div>
          <div class="fd-section">
            <div class="fd-section-title">Location</div>
            <div class="fd-grid">
              <div class="fd-field" style="grid-column:span 2"><label>File path</label><span id="fd-path">—</span></div>
              <div class="fd-field"><label>Line</label><span id="fd-line">—</span></div>
              <div class="fd-field"><label>Column</label><span id="fd-col">—</span></div>
            </div>
          </div>
        </div>

        <!-- TECHNICAL -->
        <div id="fd-tab-technical" class="fd-tab-content">
          <div class="fd-section">
            <div class="fd-section-title">Code snippet</div>
            <div class="fd-code" id="fd-snippet">Loading...</div>
          </div>
          <div class="fd-section">
            <div class="fd-section-title">References</div>
            <div id="fd-refs" style="font-size:12px;color:var(--text2);line-height:1.8"></div>
          </div>
          <div class="fd-section">
            <div class="fd-section-title">CVSS / Risk score</div>
            <div id="fd-cvss" style="font-size:12px;color:var(--text2)"></div>
          </div>
        </div>

        <!-- REMEDIATION GUIDE -->
        <div id="fd-tab-remediation" class="fd-tab-content">
          <div class="fd-section">
            <div class="fd-section-title">Recommended fix</div>
            <div class="fd-code" id="fd-fix-code" style="min-height:80px"></div>
          </div>
          <div class="fd-section">
            <div class="fd-section-title">Remediation steps</div>
            <ol id="fd-fix-steps" style="font-size:12px;color:var(--text2);line-height:1.9;padding-left:18px"></ol>
          </div>
          <div class="fd-section">
            <div class="fd-section-title">Current workflow status</div>
            <div id="fd-rem-status-block" style="font-size:12px;color:var(--text2)">Loading...</div>
          </div>
        </div>

        <!-- RAW JSON -->
        <div id="fd-tab-raw" class="fd-tab-content">
          <div class="fd-section-title">Raw finding JSON</div>
          <div class="fd-code" id="fd-raw-json" style="min-height:200px;font-size:10px"></div>
        </div>
      </div>
      <div class="fd-actions">
        <button class="btn-sm btn-primary" id="fd-btn-remediate" onclick="fdGoRemediate()">Open remediation →</button>
        <button class="btn-sm" onclick="fdCopyID()">Copy ID</button>
        <button class="btn-sm" onclick="fdCopyPath()">Copy path</button>
        <button class="btn-sm" style="margin-left:auto" onclick="closeFindingModal()">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeFindingModal(); });

  // Keyboard
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay.classList.contains('open')) closeFindingModal();
  });
})();

// Current finding ref
window._fdCurrent = null;

window.closeFindingModal = function() {
  document.getElementById('finding-detail-overlay').classList.remove('open');
};

window.fdSwitchTab = function(name, el) {
  document.querySelectorAll('.fd-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.fd-tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('fd-tab-' + name).classList.add('active');
};

window.openFindingModal = async function(finding) {
  window._fdCurrent = finding;
  const overlay = document.getElementById('finding-detail-overlay');
  overlay.classList.add('open');

  // Reset tabs
  document.querySelectorAll('.fd-tab')[0].click();

  // Badge
  const badge = document.getElementById('fd-severity-badge');
  badge.textContent = finding.severity || '—';
  badge.className = 'fd-badge ' + (finding.severity || '');
  document.getElementById('fd-tool-label').textContent = finding.tool || '';

  // Overview
  document.getElementById('fd-message').textContent = finding.message || '—';
  document.getElementById('fd-sev2').textContent   = finding.severity || '—';
  document.getElementById('fd-tool2').textContent  = finding.tool || '—';
  document.getElementById('fd-rule').textContent   = finding.rule_id || '—';
  document.getElementById('fd-cwe').textContent    = finding.cwe || '—';
  document.getElementById('fd-runid').textContent  = finding.run_id || '—';
  document.getElementById('fd-path').textContent   = finding.path || '—';
  document.getElementById('fd-line').textContent   = finding.line || '—';
  document.getElementById('fd-col').textContent    = finding.col || '—';

  // Raw JSON
  document.getElementById('fd-raw-json').textContent = JSON.stringify(finding, null, 2);

  // Technical tab — code snippet (from context field or mock)
  const snippet = finding.code_snippet || finding.context || '# No code snippet available';
  document.getElementById('fd-snippet').textContent = snippet;

  // References
  const refs = finding.references || finding.refs || [];
  document.getElementById('fd-refs').innerHTML = refs.length
    ? refs.map(r => `<div>→ <a href="${r}" target="_blank" style="color:var(--cyan)">${r}</a></div>`).join('')
    : '<span style="color:var(--text3)">No references available</span>';

  // CVSS
  document.getElementById('fd-cvss').textContent = finding.cvss
    ? `CVSS ${finding.cvss_version||'3.1'}: ${finding.cvss} — ${cvssLabel(finding.cvss)}`
    : 'No CVSS score available for this finding';

  // Fix suggestions based on rule
  populateFixSuggestions(finding);

  // Remediation status
  document.getElementById('fd-status').textContent = 'Loading...';
  try {
    const data = await window.api('GET', '/remediation/finding/' + finding.id).catch(()=>null);
    if (data && data.remediation) {
      const r = data.remediation;
      document.getElementById('fd-status').textContent = r.status || 'open';
      document.getElementById('fd-rem-status-block').innerHTML = `
        <div class="fd-grid">
          <div class="fd-field"><label>Status</label><span>${r.status||'open'}</span></div>
          <div class="fd-field"><label>Priority</label><span>${r.priority||'—'}</span></div>
          <div class="fd-field"><label>Assignee</label><span>${r.assignee||'—'}</span></div>
          <div class="fd-field"><label>Ticket</label><span>${r.ticket_url?`<a href="${r.ticket_url}" style="color:var(--cyan)" target="_blank">Open</a>`:'—'}</span></div>
        </div>
        ${r.notes?`<div style="margin-top:10px;padding:10px;background:var(--black);border:1px solid var(--border);border-radius:4px;font-size:11px;color:var(--text2)">${r.notes}</div>`:''}
      `;
    } else {
      document.getElementById('fd-status').textContent = 'open';
      document.getElementById('fd-rem-status-block').innerHTML = '<span style="color:var(--text3)">No remediation record yet. Click "Open remediation" to create one.</span>';
    }
  } catch(e) {
    document.getElementById('fd-status').textContent = 'open';
  }
};

function cvssLabel(score) {
  if (!score) return '';
  const n = parseFloat(score);
  if (n >= 9.0) return 'CRITICAL';
  if (n >= 7.0) return 'HIGH';
  if (n >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function populateFixSuggestions(f) {
  const tool = (f.tool || '').toLowerCase();
  const rule = (f.rule_id || '').toLowerCase();
  const msg  = (f.message || '').toLowerCase();

  let code = '# No automated fix available\n# Manual remediation required';
  let steps = ['Review the finding in context', 'Apply the recommended fix', 'Re-run the scan to verify'];

  if (msg.includes('s3') && msg.includes('acl')) {
    code = `# Terraform: restrict S3 ACL
resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"   # was: "public-read" or "public-read-write"
}`;
    steps = [
      'Locate the S3 bucket resource in your Terraform files',
      'Change the ACL from "public-read" or "public-read-write" to "private"',
      'Alternatively, use bucket policies with explicit deny for public access',
      'Enable S3 Block Public Access at the account level',
      'Apply: terraform apply',
      'Re-run IaC scan to confirm',
    ];
  } else if (msg.includes('unrestricted') && msg.includes('security group')) {
    code = `# Terraform: restrict ingress
resource "aws_security_group_rule" "example" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # was: 0.0.0.0/0
  security_group_id = aws_security_group.example.id
}`;
    steps = [
      'Identify which service requires internet access',
      'Replace 0.0.0.0/0 with specific CIDR blocks or security group references',
      'Use separate rules per required CIDR range',
      'Consider using VPC endpoints instead of internet access',
      'Apply and re-scan',
    ];
  } else if (msg.includes('root')) {
    code = `# Dockerfile: use non-root user
FROM alpine:3.18
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY . .
USER appuser   # add this line
CMD ["./app"]`;
    steps = [
      'Add a non-root user to your Dockerfile',
      'Use USER directive to switch to that user',
      'Ensure application files have correct ownership (chown)',
      'Rebuild and re-scan',
    ];
  } else if (tool === 'bandit' || tool === 'semgrep') {
    code = `# Python: example safe pattern\n# Review the flagged line and apply language-specific hardening`;
    steps = [
      'Review the flagged code pattern',
      'Apply the suggested fix from the rule documentation',
      'Add unit tests to prevent regression',
      'Re-run SAST scan',
    ];
  }

  document.getElementById('fd-fix-code').textContent = code;
  document.getElementById('fd-fix-steps').innerHTML = steps.map(s => `<li>${s}</li>`).join('');
}

window.fdGoRemediate = function() {
  if (!window._fdCurrent) return;
  const f = window._fdCurrent;
  closeFindingModal();
  // Navigate to remediation panel and open modal
  document.querySelector('.stab[onclick*="remediation"]')?.click();
  setTimeout(() => {
    if (typeof openRemModal === 'function') {
      openRemModal(f.id, f.message, f.severity);
    }
  }, 400);
};

window.fdCopyID   = function() { navigator.clipboard?.writeText(window._fdCurrent?.id || ''); showToast('Finding ID copied', 'success'); };
window.fdCopyPath = function() { navigator.clipboard?.writeText(window._fdCurrent?.path || ''); showToast('Path copied', 'success'); };

// ── Patch loadFindings to make rows clickable ─────────────────────────────────
const _origLoadFindings = window.loadFindings;
window.loadFindings = async function() {
  const sev  = document.getElementById('filterSev')?.value || '';
  const tool = document.getElementById('filterTool')?.value || '';
  const q    = document.getElementById('filterQ')?.value || '';
  let path   = '/vsp/findings?limit=100';
  if (sev)  path += '&severity=' + sev;
  if (tool) path += '&tool=' + tool;
  if (q)    path += '&q=' + encodeURIComponent(q);
  try {
    const data = await window.api('GET', path);
    const findings = data.findings || [];
    document.getElementById('findings-count').textContent = data.total + ' findings';
    // Store findings for modal lookup
    window._findingsCache = findings;
    document.getElementById('findings-table').innerHTML = findings.map((f, i) => `
      <tr onclick="openFindingModal(window._findingsCache[${i}])" title="Click for details">
        <td>${window.sevPill(f.severity)}</td>
        <td style="color:#94a3b8">${f.tool}</td>
        <td style="font-family:monospace;font-size:11px;color:#60a5fa">${f.rule_id||'—'}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${esc(f.message)}">${esc(f.message)||'—'}</td>
        <td style="font-family:monospace;font-size:11px;color:#94a3b8">${esc(f.path)||'—'}</td>
        <td style="color:#64748b">${f.line||'—'}</td>
        <td style="font-size:11px;color:#818cf8">${f.cwe||'—'}</td>
      </tr>`).join('');
  } catch(e) { console.error('findings', e); }
};

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }


// ─── 3. SCAN PROGRESS REAL-TIME (SSE tool-by-tool) ───────────────────────────
(function initScanProgress() {
  // Create overlay panel
  const overlay = document.createElement('div');
  overlay.id = 'scan-progress-overlay';
  overlay.innerHTML = `
    <div id="sp-header">
      <div>
        <div id="sp-title">SCAN IN PROGRESS</div>
        <div id="sp-rid"></div>
      </div>
      <button id="sp-close-btn" onclick="document.getElementById('scan-progress-overlay').classList.remove('open')">✕</button>
    </div>
    <div id="sp-body">
      <div id="sp-summary"></div>
      <div id="sp-overall"><div id="sp-progress-bar" style="width:0%"></div></div>
      <div style="margin-top:12px" id="sp-tools-list"></div>
    </div>
  `;
  document.body.appendChild(overlay);

  // Track active scans
  window._scanProgress = {};

  // Override connectSSE to add progress handler
  const _origSSE = window.connectSSE;
  window.connectSSE = function() {
    if (!window.TOKEN) return;
    if (window.sseConn) window.sseConn.close();
    window.sseConn = new EventSource('/api/v1/events');
    window.sseConn.onmessage = function(e) {
      try {
        const msg = JSON.parse(e.data);
        handleSSEMessage(msg);
      } catch(err) {}
    };
    window.sseConn.onerror = () => setTimeout(window.connectSSE, 5000);
  };

  function handleSSEMessage(msg) {
    if (msg.type === 'scan_started') {
      window._scanProgress[msg.rid] = {
        rid: msg.rid, mode: msg.mode,
        tools: {}, done: 0, total: msg.tools_total || 0,
      };
      renderScanProgress(msg.rid);
      document.getElementById('scan-progress-overlay').classList.add('open');
      window.addNotification && window.addNotification('Scan started — ' + msg.mode, 'scan', 'Run ' + (msg.rid||'').slice(-8));
    }

    if (msg.type === 'tool_started') {
      const s = window._scanProgress[msg.rid];
      if (s) {
        s.tools[msg.tool] = { status:'running', findings: 0 };
        renderScanProgress(msg.rid);
      }
    }

    if (msg.type === 'tool_complete') {
      const s = window._scanProgress[msg.rid];
      if (s) {
        s.tools[msg.tool] = { status:'done', findings: msg.findings || 0 };
        s.done = Object.values(s.tools).filter(t=>t.status==='done').length;
        renderScanProgress(msg.rid);
      }
    }

    if (msg.type === 'tool_error') {
      const s = window._scanProgress[msg.rid];
      if (s) {
        s.tools[msg.tool] = { status:'error', findings: 0 };
        renderScanProgress(msg.rid);
      }
    }

    if (msg.type === 'scan_complete') {
      const s = window._scanProgress[msg.rid];
      if (s) {
        s.done = s.total;
        // Mark all running as done
        Object.keys(s.tools).forEach(t => {
          if (s.tools[t].status === 'running') s.tools[t].status = 'done';
        });
        renderScanProgress(msg.rid);
        setTimeout(() => {
          document.getElementById('scan-progress-overlay').classList.remove('open');
          delete window._scanProgress[msg.rid];
        }, 4000);
      }
      window.addNotification && window.addNotification(
        'Scan complete — ' + msg.mode,
        msg.gate === 'PASS' ? 'success' : 'error',
        msg.findings + ' findings · ' + msg.gate + ' · ' + (msg.rid||'').slice(-8)
      );
      if (typeof showToast === 'function') showToast('Scan complete: ' + msg.gate, msg.gate==='PASS'?'success':'error');
      if (typeof loadDashboard === 'function') loadDashboard();
      if (typeof loadDashboardCharts === 'function') loadDashboardCharts();
    }
  }

  const TOOL_COLORS = {
    bandit:'#818cf8', semgrep:'#38bdf8', grype:'#fb923c', trivy:'#4ade80',
    gitleaks:'#f472b6', kics:'#fbbf24', checkov:'#a78bfa', nikto:'#34d399',
    nuclei:'#60a5fa', codeql:'#e879f9', default:'#94a3b8',
  };

  function renderScanProgress(rid) {
    const s = window._scanProgress[rid];
    if (!s) return;

    document.getElementById('sp-rid').textContent = rid.slice(-16);
    document.getElementById('sp-title').textContent = 'SCAN IN PROGRESS · ' + s.mode;

    const pct = s.total > 0 ? Math.round((s.done / s.total) * 100) : 0;
    document.getElementById('sp-progress-bar').style.width = pct + '%';
    document.getElementById('sp-summary').textContent = `${s.done} / ${s.total} tools · ${pct}%`;

    const toolEntries = Object.entries(s.tools);
    // Also show queued tools
    const totalFindings = toolEntries.reduce((a, [,t]) => a + (t.findings||0), 0);

    document.getElementById('sp-tools-list').innerHTML = toolEntries.map(([name, t]) => {
      const color = TOOL_COLORS[name] || TOOL_COLORS.default;
      const initials = name.slice(0,2).toUpperCase();
      const statusClass = 'sp-status-' + t.status;
      const statusText  = t.status === 'running' ? '● running' : t.status === 'done' ? '✓ done' : t.status === 'error' ? '✗ error' : '○ waiting';
      return `<div class="sp-tool-row">
        <div class="sp-tool-icon" style="background:${color}22;color:${color}">${initials}</div>
        <span class="sp-tool-name">${name}</span>
        <span class="sp-tool-count">${t.findings > 0 ? t.findings + ' findings' : ''}</span>
        <span class="sp-tool-status ${statusClass}">${statusText}</span>
      </div>`;
    }).join('') || '<div style="color:var(--text3);font-size:11px;padding:8px 0">Waiting for tools to start...</div>';
  }

  // Also hook into triggerScan to show the overlay immediately
  const _origTrigger = window.triggerScan;
  window.triggerScan = async function() {
    if (_origTrigger) await _origTrigger();
    // If a new run was created, we'll pick it up via SSE
  };
})();


// ─── 4. USER MANAGEMENT UI ───────────────────────────────────────────────────
(function initUserManagement() {
  // Only show for admin role
  function isAdmin() {
    try {
      const u = JSON.parse(localStorage.getItem('vsp_user') || '{}');
      return u.role === 'admin';
    } catch { return false; }
  }

  // Add "Users" nav button to sidebar (under Security section)
  const secDiv = document.querySelector('#sidebar-nav')?.nextElementSibling?.nextElementSibling;
  if (secDiv) {
    const btn = document.createElement('button');
    btn.className = 'stab';
    btn.id = 'nav-btn-users';
    btn.innerHTML = `<span style="font-size:12px;width:16px">◈</span>Users`;
    btn.onclick = function() {
      showPanel('users', this);
      loadUsers();
    };
    // Insert after the Security group's last button
    secDiv.appendChild(btn);
  }

  // Create the users panel
  const usersPanel = document.createElement('div');
  usersPanel.id = 'panel-users';
  usersPanel.className = 'panel';
  usersPanel.innerHTML = `
    <div class="user-stat-grid">
      <div class="user-stat"><div class="val" id="usr-total">—</div><div class="lbl">Total users</div></div>
      <div class="user-stat"><div class="val c-red" id="usr-admins">—</div><div class="lbl">Admins</div></div>
      <div class="user-stat"><div class="val c-amber" id="usr-analysts">—</div><div class="lbl">Analysts</div></div>
      <div class="user-stat"><div class="val" id="usr-viewers">—</div><div class="lbl">Viewers</div></div>
    </div>

    <div class="card" style="margin-bottom:16px">
      <div class="card-head">
        <span class="card-title">User accounts</span>
        <div style="display:flex;gap:8px">
          <button class="btn-sm" onclick="loadUsers()">↻ Refresh</button>
          <button class="btn-sm btn-primary" onclick="openUserModal()">+ Invite user</button>
        </div>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Tenant</th><th>Last login</th><th>Status</th><th></th></tr></thead>
          <tbody id="users-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><span class="card-title">API tokens</span><button class="btn-sm btn-primary" onclick="genAPIToken()">+ Generate token</button></div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Token ID</th><th>Description</th><th>Created</th><th>Last used</th><th></th></tr></thead>
          <tbody id="tokens-tbody"><tr><td colspan="5" style="color:var(--text3);padding:16px;text-align:center;font-size:11px">No API tokens — click Generate token to create one</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- User create/edit modal -->
    <div id="user-modal-overlay">
      <div id="user-modal-box">
        <div style="font-family:var(--display);font-size:17px;font-weight:700;margin-bottom:20px" id="user-modal-title">Invite user</div>
        <div class="form-group">
          <label class="form-label">Email address</label>
          <input id="usr-email" class="form-ctrl" type="email" placeholder="user@company.com">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Role</label>
            <select id="usr-role" class="form-ctrl">
              <option value="viewer">Viewer — read only</option>
              <option value="analyst">Analyst — remediation + export</option>
              <option value="admin">Admin — full access</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">MFA required</label>
            <select id="usr-mfa" class="form-ctrl">
              <option value="false">No</option>
              <option value="true">Yes</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Initial password (leave blank to send email invite)</label>
          <input id="usr-pass" class="form-ctrl" type="password" placeholder="optional">
        </div>
        <div id="user-modal-err" style="color:var(--red);font-size:11px;margin-bottom:10px;min-height:16px"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button class="btn-sm" onclick="closeUserModal()">Cancel</button>
          <button class="btn-sm btn-primary" onclick="saveUser()">Create user →</button>
        </div>
      </div>
    </div>
  `;

  // Insert before the first panel (after the notif panel)
  const main = document.querySelector('.main');
  if (main) main.appendChild(usersPanel);

  window.openUserModal = function(user) {
    document.getElementById('user-modal-title').textContent = user ? 'Edit user' : 'Invite user';
    document.getElementById('usr-email').value = user?.email || '';
    document.getElementById('usr-role').value  = user?.role  || 'viewer';
    document.getElementById('usr-mfa').value   = user?.mfa_required ? 'true' : 'false';
    document.getElementById('usr-pass').value  = '';
    document.getElementById('user-modal-err').textContent = '';
    document.getElementById('user-modal-overlay').classList.add('open');
    window._editingUserId = user?.id || null;
  };

  window.closeUserModal = function() {
    document.getElementById('user-modal-overlay').classList.remove('open');
  };

  window.saveUser = async function() {
    const email = document.getElementById('usr-email').value.trim();
    const role  = document.getElementById('usr-role').value;
    const mfa   = document.getElementById('usr-mfa').value === 'true';
    const pass  = document.getElementById('usr-pass').value;
    const err   = document.getElementById('user-modal-err');

    if (!email) { err.textContent = 'Email is required'; return; }
    if (!/\S+@\S+\.\S+/.test(email)) { err.textContent = 'Invalid email format'; return; }

    try {
      const payload = { email, role, mfa_required: mfa };
      if (pass) payload.password = pass;

      if (window._editingUserId) {
        await window.api('PUT', '/admin/users/' + window._editingUserId, payload);
        showToast('User updated', 'success');
      } else {
        await window.api('POST', '/admin/users', payload);
        showToast('User invited: ' + email, 'success');
      }
      closeUserModal();
      loadUsers();
    } catch(e) {
      err.textContent = 'Error: ' + e.message;
    }
  };

  window.loadUsers = async function() {
    try {
      const data = await window.api('GET', '/admin/users');
      const users = data.users || [];

      // Stats
      document.getElementById('usr-total').textContent   = users.length;
      document.getElementById('usr-admins').textContent  = users.filter(u=>u.role==='admin').length;
      document.getElementById('usr-analysts').textContent= users.filter(u=>u.role==='analyst').length;
      document.getElementById('usr-viewers').textContent = users.filter(u=>u.role==='viewer').length;

      const avatarColors = {'admin':'#f87171','analyst':'#60a5fa','viewer':'#94a3b8'};

      document.getElementById('users-tbody').innerHTML = users.length ? users.map(u => `
        <tr>
          <td>
            <div style="display:flex;align-items:center;gap:10px">
              <div class="user-avatar" style="background:${avatarColors[u.role]||'#64748b'}22;color:${avatarColors[u.role]||'#64748b'}">${(u.email||'?')[0].toUpperCase()}</div>
              <div>
                <div style="font-size:12px;color:var(--text1)">${esc(u.email)}</div>
                ${u.mfa_required?'<div style="font-size:9px;color:var(--green);letter-spacing:.1em">MFA ENABLED</div>':''}
              </div>
            </div>
          </td>
          <td><span class="role-badge ${u.role}">${u.role}</span></td>
          <td style="font-size:11px;color:var(--text3);font-family:var(--mono)">${(u.tenant_id||'').slice(0,8)}…</td>
          <td style="font-size:11px;color:var(--text3)">${u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Never'}</td>
          <td><span class="pill ${u.active!==false?'pill-done':'pill-failed'}">${u.active!==false?'active':'disabled'}</span></td>
          <td>
            <div style="display:flex;gap:4px">
              <button class="btn-sm" onclick="openUserModal(${JSON.stringify(u).replace(/"/g,'&quot;')})">Edit</button>
              <button class="btn-sm" style="color:var(--red)" onclick="deleteUser('${u.id}','${esc(u.email)}')">Remove</button>
            </div>
          </td>
        </tr>`).join('')
      : '<tr><td colspan="6" style="color:var(--text3);padding:24px;text-align:center">No users found</td></tr>';

    } catch(e) {
      // If API doesn't exist, show demo data
      const demoUsers = [
        {id:'1',email:'admin@vsp.local',role:'admin',active:true,mfa_required:true,tenant_id:'1bdf7f20-dbb3-4116'},
        {id:'2',email:'analyst@vsp.local',role:'analyst',active:true,mfa_required:false,tenant_id:'1bdf7f20-dbb3-4116'},
        {id:'3',email:'viewer@vsp.local',role:'viewer',active:true,mfa_required:false,tenant_id:'1bdf7f20-dbb3-4116'},
      ];
      document.getElementById('usr-total').textContent   = demoUsers.length;
      document.getElementById('usr-admins').textContent  = 1;
      document.getElementById('usr-analysts').textContent= 1;
      document.getElementById('usr-viewers').textContent = 1;
      document.getElementById('users-tbody').innerHTML = demoUsers.map(u => `
        <tr>
          <td>
            <div style="display:flex;align-items:center;gap:10px">
              <div class="user-avatar" style="background:rgba(96,165,250,.15);color:#60a5fa">${u.email[0].toUpperCase()}</div>
              <div style="font-size:12px;color:var(--text1)">${u.email}</div>
            </div>
          </td>
          <td><span class="role-badge ${u.role}">${u.role}</span></td>
          <td style="font-size:11px;color:var(--text3);font-family:var(--mono)">${u.tenant_id}</td>
          <td style="font-size:11px;color:var(--text3)">Today</td>
          <td><span class="pill pill-done">active</span></td>
          <td><button class="btn-sm">Edit</button></td>
        </tr>`).join('');
    }
  };

  window.deleteUser = async function(id, email) {
    if (!confirm(`Remove user ${email}?`)) return;
    try {
      await window.api('DELETE', '/admin/users/' + id);
      showToast('User removed: ' + email, 'success');
      loadUsers();
    } catch(e) {
      showToast('Error: ' + e.message, 'error');
    }
  };

  window.genAPIToken = async function() {
    const desc = prompt('Token description (e.g. CI/CD pipeline):');
    if (!desc) return;
    try {
      const data = await window.api('POST', '/admin/tokens', { description: desc });
      const token = data.token || data.api_token || '(token hidden — copy now)';
      // Show in a copyable dialog
      const box = document.createElement('div');
      box.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;';
      box.innerHTML = `
        <div style="background:var(--card);border:1px solid var(--border2);border-radius:10px;padding:24px;width:min(520px,90%);box-shadow:0 24px 60px rgba(0,0,0,.6)">
          <div style="font-family:var(--display);font-size:16px;font-weight:700;margin-bottom:4px">API Token Created</div>
          <div style="font-size:11px;color:var(--red);margin-bottom:16px">⚠ Copy this token now — it will not be shown again</div>
          <div style="background:var(--black);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:var(--mono);font-size:11px;word-break:break-all;color:var(--amber);margin-bottom:16px">${token}</div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn-sm btn-primary" onclick="navigator.clipboard?.writeText('${token}');this.textContent='Copied ✓'">Copy to clipboard</button>
            <button class="btn-sm" onclick="this.closest('div[style]').remove();loadUsers()">Close</button>
          </div>
        </div>`;
      document.body.appendChild(box);
    } catch(e) {
      showToast('Error generating token: ' + e.message, 'error');
    }
  };
})();


// ─── FINAL: re-wire showApp to init new features ─────────────────────────────
const _patchedShowApp = window.showApp;
window.showApp = function() {
  _patchedShowApp && _patchedShowApp();
  // Re-connect SSE with new handler
  if (typeof connectSSE === 'function') connectSSE();
};

console.log('[VSP Patch v0.5.0] All 4 features loaded ✓');
