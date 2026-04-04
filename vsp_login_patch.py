#!/usr/bin/env python3
"""
VSP Gov Patch v1.1 — Login Page with DoD Warning Notice
Replaces auto-login with proper login screen featuring:
  - DoD/USG Warning & Consent Banner (STIG/DoD 8500.01 compliant wording)
  - CAC/PIV notice
  - Credential form with proper UX
  - UNCLASSIFIED banner on login screen
Usage:
  python3 vsp_login_patch.py /home/test/Data/GOLANG_VSP/static/index.html
"""

import sys, shutil, datetime, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_loginpatch_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# ════════════════════════════════════════════════════════════════════════════
# 1. CSS for login overlay
# ════════════════════════════════════════════════════════════════════════════
LOGIN_CSS = """
/* ═══════════════════════════════════════════════════
   GOV PATCH v1.1 — Login Page / DoD Warning Notice
═══════════════════════════════════════════════════ */
#gov-login-overlay {
  position: fixed;
  inset: 0;
  z-index: 99998;
  background: #080c14;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
}
#gov-login-overlay.hidden { display: none; }

.login-classif-bar {
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 22px;
  background: #00a651;
  color: #fff;
  display: flex; align-items: center; justify-content: center;
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em;
  font-family: var(--font-mono);
  z-index: 2;
}
.login-classif-bar-bot {
  position: absolute;
  bottom: 0; left: 0; right: 0;
  height: 18px;
  background: #00a651;
  color: #fff;
  display: flex; align-items: center; justify-content: center;
  font-size: 9px; font-weight: 600; letter-spacing: 0.1em;
  font-family: var(--font-mono);
}

.login-wrap {
  width: 100%;
  max-width: 520px;
  padding: 0 16px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* Warning banner */
.login-warning-box {
  border: 1px solid rgba(251,191,36,0.5);
  background: rgba(251,191,36,0.06);
  border-radius: 4px;
  padding: 14px 16px;
}
.login-warning-title {
  color: var(--amber);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  margin-bottom: 8px;
  display: flex; align-items: center; gap: 8px;
}
.login-warning-title::before {
  content: '⚠';
  font-size: 12px;
}
.login-warning-text {
  color: #94a3b8;
  font-size: 9px;
  line-height: 1.6;
  font-family: var(--font-mono);
}
.login-warning-text strong { color: #cbd5e1; }

/* Login card */
.login-card {
  background: #0f1a2e;
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 6px;
  padding: 24px;
}
.login-logo-row {
  display: flex; align-items: center; gap: 10px;
  margin-bottom: 20px;
}
.login-logo-icon {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, #0ea5e9, #6366f1);
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  font-size: 13px; font-weight: 800; color: #fff;
  font-family: var(--font-display);
  flex-shrink: 0;
}
.login-logo-text { line-height: 1.2; }
.login-logo-title {
  font-family: var(--font-display);
  font-size: 15px; font-weight: 800;
  color: #f1f5f9;
}
.login-logo-sub {
  font-size: 9px; color: #64748b;
  letter-spacing: 0.08em;
}

.login-field { margin-bottom: 12px; }
.login-label {
  display: block;
  font-size: 9px; font-weight: 600;
  color: #64748b; letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-bottom: 5px;
}
.login-input {
  width: 100%; box-sizing: border-box;
  background: #080c14;
  border: 1px solid rgba(255,255,255,0.10);
  border-radius: 4px;
  color: #f1f5f9;
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 8px 10px;
  outline: none;
  transition: border-color 0.15s;
}
.login-input:focus { border-color: rgba(14,165,233,0.6); }
.login-input::placeholder { color: #334155; }

.login-btn-row {
  display: flex; gap: 8px; margin-top: 16px;
}
.login-btn-primary {
  flex: 1;
  background: #0ea5e9;
  color: #fff;
  border: none;
  border-radius: 4px;
  padding: 9px 16px;
  font-family: var(--font-mono);
  font-size: 11px; font-weight: 700;
  letter-spacing: 0.06em;
  cursor: pointer;
  transition: background 0.15s, opacity 0.15s;
}
.login-btn-primary:hover { background: #0284c7; }
.login-btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

.login-btn-cac {
  background: transparent;
  color: #64748b;
  border: 1px solid rgba(255,255,255,0.10);
  border-radius: 4px;
  padding: 9px 12px;
  font-family: var(--font-mono);
  font-size: 10px;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.login-btn-cac:hover {
  border-color: rgba(99,102,241,0.5);
  color: #a5b4fc;
  background: rgba(99,102,241,0.06);
}

.login-error {
  color: #ef4444;
  font-size: 10px;
  margin-top: 8px;
  min-height: 14px;
}
.login-spinner {
  display: none;
  width: 12px; height: 12px;
  border: 2px solid rgba(255,255,255,0.2);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  margin: 0 auto;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Footer row */
.login-footer-row {
  display: flex; align-items: center; justify-content: space-between;
  padding-top: 8px;
  border-top: 1px solid rgba(255,255,255,0.05);
  margin-top: 4px;
}
.login-footer-badges { display: flex; gap: 6px; }
.login-footer-badge {
  font-size: 8px; font-weight: 700;
  padding: 1px 5px;
  border-radius: 2px;
  border: 1px solid;
  font-family: var(--font-mono);
  letter-spacing: 0.06em;
}
.login-footer-badge.fr { color:#2563eb; border-color:rgba(37,99,235,.4); background:rgba(37,99,235,.08); }
.login-footer-badge.cm { color:#7c3aed; border-color:rgba(124,58,237,.4); background:rgba(124,58,237,.08); }
.login-ver { font-size: 8px; color: #334155; }

/* Consent checkbox */
.login-consent {
  display: flex; align-items: flex-start; gap: 8px;
  margin-top: 12px;
}
.login-consent input[type=checkbox] {
  margin-top: 1px; flex-shrink: 0;
  accent-color: var(--cyan);
}
.login-consent label {
  font-size: 9px; color: #64748b; line-height: 1.5;
  cursor: pointer;
}
.login-consent label strong { color: #94a3b8; }
"""

html = html.replace("</style>", LOGIN_CSS + "\n</style>", 1)
print("[+] Login CSS injected")

# ════════════════════════════════════════════════════════════════════════════
# 2. Login overlay HTML — inject right after <div class="app">
# ════════════════════════════════════════════════════════════════════════════
LOGIN_HTML = """
<!-- GOV PATCH v1.1: Login Overlay with DoD Warning Notice -->
<div id="gov-login-overlay">
  <!-- Classification bars -->
  <div class="login-classif-bar">UNCLASSIFIED // FOR OFFICIAL USE ONLY</div>
  <div class="login-classif-bar-bot">UNCLASSIFIED // FOUO — Authorized Users Only</div>

  <div class="login-wrap">

    <!-- DoD Warning & Consent Banner -->
    <div class="login-warning-box">
      <div class="login-warning-title">U.S. Government Warning &amp; Consent Notice</div>
      <div class="login-warning-text">
        You are accessing a <strong>U.S. Government information system</strong>, which includes (1) this computer, (2) this computer network, (3) all computers connected to this network, and (4) all devices and storage media attached to this network or to a computer on this network. This information system is provided for <strong>U.S. Government-authorized use only</strong>.<br><br>
        Unauthorized or improper use of this system may result in <strong>disciplinary action</strong>, as well as civil and criminal penalties. By using this system, you consent to monitoring, interception, recording, reading, copying, or capturing by authorized personnel. <strong>There is no right of privacy in this system.</strong><br><br>
        Evidence of unauthorized use collected during monitoring may be used for administrative, criminal, or other adverse action.
      </div>
    </div>

    <!-- Login Card -->
    <div class="login-card">
      <div class="login-logo-row">
        <div class="login-logo-icon">VSP</div>
        <div class="login-logo-text">
          <div class="login-logo-title">VSP Security Platform</div>
          <div class="login-logo-sub">VULNERABILITY SCANNING PLATFORM · v0.10.0</div>
        </div>
      </div>

      <div class="login-field">
        <label class="login-label" for="login-email">Email / User ID</label>
        <input class="login-input" id="login-email" type="email"
               placeholder="user@agency.gov" autocomplete="username">
      </div>
      <div class="login-field">
        <label class="login-label" for="login-pass">Password</label>
        <input class="login-input" id="login-pass" type="password"
               placeholder="••••••••" autocomplete="current-password">
      </div>

      <!-- Consent -->
      <div class="login-consent">
        <input type="checkbox" id="login-consent-cb">
        <label for="login-consent-cb">
          I have read, understand, and consent to the <strong>U.S. Government Warning &amp; Consent Notice</strong> above. I am an authorized user of this system.
        </label>
      </div>

      <div class="login-error" id="login-error"></div>

      <div class="login-btn-row">
        <button class="login-btn-primary" id="login-submit-btn" onclick="govLoginSubmit()">
          <span id="login-btn-text">AUTHENTICATE →</span>
          <div class="login-spinner" id="login-spinner"></div>
        </button>
        <button class="login-btn-cac" onclick="showToast('CAC/PIV — configure OIDC/SSO in Settings','info')" title="CAC/PIV Smart Card (requires OIDC/SSO)">
          🪪 CAC/PIV
        </button>
      </div>

      <div class="login-footer-row" style="margin-top:16px">
        <div class="login-footer-badges">
          <span class="login-footer-badge fr">FedRAMP</span>
          <span class="login-footer-badge cm">CMMC L2</span>
        </div>
        <span class="login-ver">CONTROLLED UNCLASSIFIED INFORMATION</span>
      </div>
    </div>

  </div>
</div>
<!-- END GOV PATCH v1.1 Login Overlay -->
"""

# inject right after <div class="app">
html = html.replace('<div class="app">', '<div class="app">\n' + LOGIN_HTML, 1)
print("[+] Login HTML overlay injected")

# ════════════════════════════════════════════════════════════════════════════
# 3. Replace auto-login JS with proper login form handler
# ════════════════════════════════════════════════════════════════════════════
OLD_AUTOLOGIN = """// Auto-login nếu chưa có token"""

# Find the full auto-login block and replace it
# Pattern: from "// Auto-login" to the closing of that async IIFE
AUTOLOGIN_PATTERN = re.compile(
    r'// Auto-login[^\n]*\n.*?(?=\n\s*//|\nfunction|\nasync function|\nwindow\.|\n<)',
    re.DOTALL
)

LOGIN_JS = """
// ── GOV PATCH v1.1: Login Gate ───────────────────────────────────────────
// Replaces auto-login with proper consent + credential form

async function govLoginSubmit() {
  var emailEl  = document.getElementById('login-email');
  var passEl   = document.getElementById('login-pass');
  var consentEl= document.getElementById('login-consent-cb');
  var errEl    = document.getElementById('login-error');
  var btnText  = document.getElementById('login-btn-text');
  var spinner  = document.getElementById('login-spinner');
  var submitBtn= document.getElementById('login-submit-btn');

  errEl.textContent = '';

  var email    = (emailEl||{}).value||'';
  var password = (passEl||{}).value||'';
  var consent  = consentEl && consentEl.checked;

  if (!consent) {
    errEl.textContent = 'You must consent to the Warning Notice before proceeding.';
    return;
  }
  if (!email || !password) {
    errEl.textContent = 'Email and password are required.';
    return;
  }

  // Show spinner
  if (btnText)  btnText.style.display  = 'none';
  if (spinner)  spinner.style.display  = 'block';
  if (submitBtn) submitBtn.disabled = true;

  try {
    var r = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email, password})
    });

    if (!r.ok) {
      var data = await r.json().catch(()=>({}));
      throw new Error(data.error || 'Authentication failed — check credentials');
    }

    var data = await r.json();
    window.TOKEN = data.token;
    localStorage.setItem('vsp_token', data.token);

    // Sync user info to topbar
    if (data.email) {
      var name = data.email.split('@')[0];
      var avatarEl = document.getElementById('topbar-avatar');
      var nameEl   = document.getElementById('topbar-username');
      var orgEl    = document.getElementById('gov-org-label');
      if (avatarEl) avatarEl.textContent = name.charAt(0).toUpperCase();
      if (nameEl)   nameEl.textContent   = name;
      if (orgEl && data.tenant_id) orgEl.textContent = data.tenant_id.substring(0,12).toUpperCase();
      // Update sidebar user row
      var emailRowEl = document.querySelector('.user-email');
      var roleRowEl  = document.querySelector('.user-role');
      if (emailRowEl) emailRowEl.textContent = data.email;
      if (roleRowEl)  roleRowEl.textContent  = (data.role||'user') + ' · ' + (data.tenant_id||'default');
    }

    // Dismiss overlay with fade
    var overlay = document.getElementById('gov-login-overlay');
    if (overlay) {
      overlay.style.transition = 'opacity 0.4s';
      overlay.style.opacity = '0';
      setTimeout(function(){ overlay.classList.add('hidden'); }, 420);
    }

    // Boot the app
    if (typeof loadDashboard === 'function') loadDashboard();
    else if (typeof loadCurrentPanel === 'function') loadCurrentPanel();
    else if (typeof initApp === 'function') initApp();

    showToast('Authenticated — welcome, ' + (data.email||'user'), 'success');

  } catch(err) {
    errEl.textContent = err.message || 'Authentication failed.';
    if (btnText)  btnText.style.display  = 'inline';
    if (spinner)  spinner.style.display  = 'none';
    if (submitBtn) submitBtn.disabled    = false;
  }
}

// Allow Enter key on login form
document.addEventListener('DOMContentLoaded', function() {
  ['login-email','login-pass'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('keydown', function(e){
      if (e.key === 'Enter') govLoginSubmit();
    });
  });

  // Check for stored token — skip login if still valid
  var stored = localStorage.getItem('vsp_token');
  if (stored) {
    // Quick validate: decode JWT expiry
    try {
      var parts = stored.split('.');
      if (parts.length === 3) {
        var payload = JSON.parse(atob(parts[1]));
        if (payload.exp && payload.exp * 1000 > Date.now()) {
          window.TOKEN = stored;
          var overlay = document.getElementById('gov-login-overlay');
          if (overlay) overlay.classList.add('hidden');
          if (typeof loadCurrentPanel === 'function') setTimeout(loadCurrentPanel, 100);
        } else {
          localStorage.removeItem('vsp_token');
        }
      }
    } catch(e) { localStorage.removeItem('vsp_token'); }
  }
});
// ── END GOV PATCH v1.1 Login Gate ────────────────────────────────────────
"""

# Try to find and neutralize the old auto-login block
old_autologin_start = "// Auto-login nếu chưa có token"
idx = html.find(old_autologin_start)
if idx != -1:
    # Find the end of the autologin block (next top-level function/comment or closing script)
    # Look for the pattern: fetch to auth/login + closing bracket
    end_marker = "// ──"
    end_idx = html.find(end_marker, idx + 100)
    if end_idx == -1:
        # fallback: find next major JS function
        end_idx = html.find("\nfunction ", idx + 100)
    if end_idx != -1:
        old_block = html[idx:end_idx]
        html = html[:idx] + LOGIN_JS + "\n" + html[end_idx:]
        print("[+] Auto-login replaced with govLoginSubmit()")
    else:
        # Just comment it out and append
        html = html.replace(old_autologin_start,
            "// [GOV PATCH] Auto-login disabled — see govLoginSubmit() below\n// " + old_autologin_start, 1)
        html = html.replace("</body>", "<script>" + LOGIN_JS + "</script>\n</body>", 1)
        print("[+] Auto-login commented out + govLoginSubmit() appended")
else:
    # Append login JS anyway
    html = html.replace("</body>", "<script>" + LOGIN_JS + "</script>\n</body>", 1)
    print("[!] Auto-login pattern not found — govLoginSubmit() appended to end")

# ════════════════════════════════════════════════════════════════════════════
# WRITE
# ════════════════════════════════════════════════════════════════════════════
with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Login patch complete → {TARGET}")
print(f"   Backup at          → {bak}")
print("""
What was added:
  [1] Login overlay — full screen, blocks app until authenticated
  [2] DoD/USG Warning & Consent Notice — STIG-compliant wording
  [3] Consent checkbox — user must acknowledge before login
  [4] CAC/PIV button — placeholder, routes to OIDC/SSO
  [5] Credential form — email + password → POST /api/v1/auth/login
  [6] Token persistence — checks localStorage for valid JWT on reload
  [7] User sync — populates topbar avatar/name/org after login
  [8] UNCLASSIFIED banner on login screen
  [9] FedRAMP / CMMC badges on login card

To roll back:
  cp {bak} {target}
""".format(bak=bak, target=TARGET))
