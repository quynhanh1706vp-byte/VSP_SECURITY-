#!/usr/bin/env python3
"""
VSP Gov Patch v1.5 — Policy Rule Creator + OSCAL Downloads
Fixes:
  1. Policy "+ New rule" button — wires to existing _openNewRuleModal() JS
  2. OSCAL AR / POA&M buttons — fetches latest run_id then triggers real download
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_fix15_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

changes = 0

# ════════════════════════════════════════════════════════════════════════════
# 1. Fix Policy "+ New rule" button
#    The JS function already exists at line ~6222 (_openNewRuleModal or similar)
#    Just replace the toast with the real call
# ════════════════════════════════════════════════════════════════════════════
OLD_RULE_BTN = """onclick="showToast('Rule creator coming soon','info')">+ New rule"""
NEW_RULE_BTN = """onclick="_openNewRuleModal()">+ New rule"""

if OLD_RULE_BTN in html:
    html = html.replace(OLD_RULE_BTN, NEW_RULE_BTN, 1)
    print("[+] Policy '+ New rule' button wired to _openNewRuleModal()")
    changes += 1
else:
    print("[!] Policy button pattern not found — trying fallback")
    OLD2 = "showToast('Rule creator coming soon','info')"
    NEW2 = "_openNewRuleModal()"
    if OLD2 in html:
        html = html.replace(OLD2, NEW2, 1)
        print("[+] Policy button fixed (fallback)")
        changes += 1

# ════════════════════════════════════════════════════════════════════════════
# 2. Fix OSCAL AR button
# ════════════════════════════════════════════════════════════════════════════
OLD_OSCAL_AR = """onclick="showToast('OSCAL AR downloaded','success')">↓ OSCAL AR"""
NEW_OSCAL_AR = """onclick="downloadOSCAL('ar')">↓ OSCAL AR"""

if OLD_OSCAL_AR in html:
    html = html.replace(OLD_OSCAL_AR, NEW_OSCAL_AR, 1)
    print("[+] OSCAL AR button wired to downloadOSCAL('ar')")
    changes += 1
else:
    print("[!] OSCAL AR pattern not found")

# ════════════════════════════════════════════════════════════════════════════
# 3. Fix OSCAL POA&M button
# ════════════════════════════════════════════════════════════════════════════
OLD_OSCAL_POAM = """onclick="showToast('OSCAL POA&M downloaded','success')">↓ OSCAL POA&M"""
NEW_OSCAL_POAM = """onclick="downloadOSCAL('poam')">↓ OSCAL POA&M"""

if OLD_OSCAL_POAM in html:
    html = html.replace(OLD_OSCAL_POAM, NEW_OSCAL_POAM, 1)
    print("[+] OSCAL POA&M button wired to downloadOSCAL('poam')")
    changes += 1
else:
    print("[!] OSCAL POA&M pattern not found")

# ════════════════════════════════════════════════════════════════════════════
# 4. Inject downloadOSCAL() JS
# ════════════════════════════════════════════════════════════════════════════
OSCAL_JS = """
// ── GOV PATCH v1.5: OSCAL Downloads ──────────────────────────────────────
async function downloadOSCAL(type) {
  await ensureToken();
  var h = {'Authorization': 'Bearer ' + window.TOKEN};

  // Get latest run_id
  var runId = null;
  try {
    var r = await fetch('/api/v1/vsp/run/latest', {headers: h});
    if (r.ok) {
      var d = await r.json();
      runId = d.id || d.run_id || (d.run && d.run.id) || null;
    }
  } catch(e) {}

  if (!runId) {
    showToast('No completed run found — run a scan first', 'error');
    return;
  }

  var url = type === 'ar'
    ? '/api/v1/compliance/oscal/ar?run_id='   + runId
    : '/api/v1/compliance/oscal/poam?run_id=' + runId;

  var label = type === 'ar' ? 'OSCAL AR' : 'OSCAL POA&M';

  try {
    showToast('Generating ' + label + '…', 'info');
    var resp = await fetch(url, {headers: h});
    if (!resp.ok) {
      var err = await resp.json().catch(function(){ return {}; });
      showToast((err.error || 'OSCAL generation failed'), 'error');
      return;
    }
    var blob = await resp.blob();
    var ct   = resp.headers.get('Content-Type') || '';
    var ext  = ct.includes('json') ? 'json' : 'xml';
    var fname = 'vsp_' + type + '_' + runId.substring(0, 16) + '.' + ext;
    var a    = document.createElement('a');
    a.href   = URL.createObjectURL(blob);
    a.download = fname;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast(label + ' downloaded → ' + fname, 'success');
  } catch(e) {
    showToast('Download failed: ' + (e.message || 'network error'), 'error');
  }
}
// ── END GOV PATCH v1.5 OSCAL ─────────────────────────────────────────────
"""

html = html.replace("</body>", "<script>" + OSCAL_JS + "</script>\n</body>", 1)
print("[+] downloadOSCAL() JS injected")
changes += 1

# ════════════════════════════════════════════════════════════════════════════
# 5. Check if _openNewRuleModal exists, if not inject a minimal one
# ════════════════════════════════════════════════════════════════════════════
if "_openNewRuleModal" not in html or html.count("function _openNewRuleModal") == 0:
    # The existing code has the modal HTML inline-built in JS at line ~6222
    # We just need to ensure the function name matches what's already there
    # Check for existing function names
    import re
    existing = re.findall(r'function (_open\w+Rule\w*)\s*\(', html)
    if existing:
        # Alias it
        ALIAS_JS = f"""
<script>
// GOV PATCH v1.5: alias rule modal function
if (typeof {existing[0]} === 'function' && typeof _openNewRuleModal === 'undefined') {{
  window._openNewRuleModal = {existing[0]};
}}
</script>"""
        html = html.replace("</body>", ALIAS_JS + "\n</body>", 1)
        print(f"[+] _openNewRuleModal aliased to {existing[0]}")
    else:
        # Inject minimal modal
        RULE_MODAL_JS = """
<script>
// GOV PATCH v1.5: minimal rule creator modal
function _openNewRuleModal() {
  // Build modal dynamically
  var existing = document.getElementById('new-rule-modal-gov');
  if (existing) { existing.classList.add('open'); return; }

  var overlay = document.createElement('div');
  overlay.id = 'new-rule-modal-gov';
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" style="width:min(500px,95vw)">
      <div class="modal-head">
        <div class="modal-title">Create policy rule</div>
        <button class="modal-close" onclick="document.getElementById('new-rule-modal-gov').classList.remove('open')">✕</button>
      </div>
      <div class="modal-body">
        <div class="form-group mb8">
          <label class="form-label">Rule name <span style="color:var(--red)">*</span></label>
          <input id="nr-name-gov" class="form-ctrl" placeholder="e.g. Block Critical Findings">
        </div>
        <div class="form-group mb8">
          <label class="form-label">Description</label>
          <input id="nr-desc-gov" class="form-ctrl" placeholder="What does this rule do?">
        </div>
        <div class="g2 mb8">
          <div class="form-group">
            <label class="form-label">Severity threshold</label>
            <select id="nr-sev-gov" class="form-ctrl">
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH" selected>HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Max findings</label>
            <input id="nr-max-gov" class="form-ctrl" type="number" value="0" min="0">
          </div>
        </div>
        <div class="form-group mb8">
          <label class="form-label">Action</label>
          <select id="nr-action-gov" class="form-ctrl">
            <option value="block">Block (FAIL gate)</option>
            <option value="warn">Warn only</option>
            <option value="notify">Notify only</option>
          </select>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-ghost" onclick="document.getElementById('new-rule-modal-gov').classList.remove('open')">Cancel</button>
        <button class="btn btn-primary" onclick="_submitNewRule()">Create rule →</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  setTimeout(function(){ overlay.classList.add('open'); }, 10);
}

async function _submitNewRule() {
  var name   = (document.getElementById('nr-name-gov')||{}).value||'';
  var desc   = (document.getElementById('nr-desc-gov')||{}).value||'';
  var sev    = (document.getElementById('nr-sev-gov')||{}).value||'HIGH';
  var maxF   = parseInt((document.getElementById('nr-max-gov')||{}).value||'0');
  var action = (document.getElementById('nr-action-gov')||{}).value||'block';

  if (!name) { showToast('Rule name is required', 'error'); return; }

  await ensureToken();
  try {
    var r = await fetch('/api/v1/policy/rules', {
      method: 'POST',
      headers: {'Authorization':'Bearer '+window.TOKEN, 'Content-Type':'application/json'},
      body: JSON.stringify({
        name: name,
        description: desc,
        conditions: { min_severity: sev, max_findings: maxF },
        action: action,
        enabled: true
      })
    });
    if (!r.ok) {
      var e = await r.json().catch(function(){return{};});
      showToast('Failed: '+(e.error||r.status), 'error');
      return;
    }
    document.getElementById('new-rule-modal-gov').classList.remove('open');
    showToast('Rule "'+name+'" created', 'success');
    if (typeof loadPolicy === 'function') setTimeout(loadPolicy, 300);
  } catch(err) {
    showToast('Error: '+(err.message||'request failed'), 'error');
  }
}
</script>"""
        html = html.replace("</body>", RULE_MODAL_JS + "\n</body>", 1)
        print("[+] Full rule creator modal injected")
        changes += 1

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Patch v1.5 complete — {changes} fixes applied → {TARGET}")
print(f"   Backup → {bak}")
print("""
What was fixed:
  [1] Policy '+ New rule' → opens real rule creator modal
  [2] Rule modal: name, description, severity threshold, max findings, action
  [3] Rule creator → POST /api/v1/policy/rules (real API)
  [4] OSCAL AR button → GET /api/v1/compliance/oscal/ar?run_id=<latest>
  [5] OSCAL POA&M button → GET /api/v1/compliance/oscal/poam?run_id=<latest>
  [6] Both OSCAL downloads: auto-detect filename + extension from Content-Type
  [7] Error handling for all 3 features
""")
