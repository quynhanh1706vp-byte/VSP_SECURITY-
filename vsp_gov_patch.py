#!/usr/bin/env python3
"""
VSP Government UI Patch v1.0
Adds:
  1. Classification Banner (UNCLASSIFIED//FOUO) — top + bottom
  2. Topbar upgrade: user identity, clearance, session countdown, org selector
  3. Footer: build hash, CUI notice, ITAR/FedRAMP badges
Usage:
  python3 vsp_gov_patch.py /home/test/Data/GOLANG_VSP/static/index.html
"""

import sys, re, shutil, datetime, os

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

# ── backup ──────────────────────────────────────────────────────────────────
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_govpatch_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# ════════════════════════════════════════════════════════════════════════════
# 1. CSS INJECTION — insert before </style> (first occurrence)
# ════════════════════════════════════════════════════════════════════════════
CSS = """
/* ═══════════════════════════════════════════════════
   GOV PATCH v1.0 — Classification Banner + Topbar++
═══════════════════════════════════════════════════ */

/* ── Classification Banner ── */
.classif-banner {
  position: fixed;
  top: 0; left: 0; right: 0;
  z-index: 9999;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  user-select: none;
}
.classif-banner.unclass {
  background: #00a651;
  color: #fff;
}
.classif-banner.cui {
  background: #5a2d82;
  color: #fff;
}
.classif-banner.secret {
  background: #c8102e;
  color: #fff;
}
.classif-banner-label {
  display: flex; align-items: center; gap: 6px;
}
.classif-banner-label::before {
  content: '';
  display: inline-block;
  width: 6px; height: 6px;
  border-radius: 50%;
  background: rgba(255,255,255,0.7);
}
.classif-banner-ts {
  opacity: 0.65;
  font-size: 9px;
}
.classif-banner-bottom {
  position: fixed;
  bottom: 0; left: 0; right: 0;
  z-index: 9999;
  height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 24px;
  font-family: var(--font-mono);
  font-size: 9px;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  background: #00a651;
  color: #fff;
  user-select: none;
}

/* ── Offset layout for banners ── */
.app {
  padding-top: 22px !important;
  padding-bottom: 18px !important;
}

/* ── Topbar gov additions ── */
.topbar-gov-bar {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--t3);
  border-left: 1px solid var(--b2);
  padding-left: 10px;
  margin-left: 4px;
}
.topbar-gov-bar .gov-org {
  color: var(--cyan);
  font-weight: 600;
  font-size: 9px;
  cursor: pointer;
  border: 1px solid rgba(0,200,255,0.25);
  padding: 1px 6px;
  border-radius: 3px;
  transition: background 0.15s;
}
.topbar-gov-bar .gov-org:hover { background: rgba(0,200,255,0.08); }
.session-timer {
  display: flex; align-items: center; gap: 4px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--t3);
  border: 1px solid var(--b2);
  padding: 2px 7px;
  border-radius: 3px;
}
.session-timer.warn { color: var(--amber); border-color: rgba(251,191,36,0.4); }
.session-timer.crit { color: var(--red); border-color: rgba(239,68,68,0.4); animation: livePulse 1s infinite; }
.session-timer-icon { font-size: 8px; }

.user-clearance {
  font-family: var(--font-mono);
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.08em;
  background: rgba(0,166,81,0.15);
  color: #00a651;
  border: 1px solid rgba(0,166,81,0.35);
  padding: 1px 5px;
  border-radius: 2px;
}

.topbar-user-pill {
  display: flex; align-items: center; gap: 6px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--t2);
  border: 1px solid var(--b2);
  padding: 3px 8px 3px 4px;
  border-radius: 4px;
  cursor: pointer;
  transition: background 0.15s;
}
.topbar-user-pill:hover { background: rgba(255,255,255,0.04); }
.topbar-user-avatar {
  width: 18px; height: 18px;
  border-radius: 50%;
  background: var(--cyan);
  color: #000;
  font-size: 8px;
  font-weight: 800;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}

/* ── Footer ── */
.gov-footer {
  position: fixed;
  bottom: 18px; left: var(--sidebar-w); right: 0;
  height: 24px;
  background: rgba(8,12,20,0.95);
  border-top: 1px solid var(--b1);
  display: flex; align-items: center;
  padding: 0 16px;
  gap: 16px;
  font-family: var(--font-mono);
  font-size: 9px;
  color: var(--t4);
  z-index: 100;
}
[data-theme="light"] .gov-footer {
  background: rgba(240,244,248,0.97);
  border-top: 1px solid rgba(0,0,0,0.08);
}
.gov-footer-badge {
  padding: 1px 5px;
  border-radius: 2px;
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.06em;
  border: 1px solid;
}
.gov-footer-badge.fedramp { color: #2563eb; border-color: rgba(37,99,235,0.4); background: rgba(37,99,235,0.08); }
.gov-footer-badge.cmmc    { color: #7c3aed; border-color: rgba(124,58,237,0.4); background: rgba(124,58,237,0.08); }
.gov-footer-badge.nist    { color: #059669; border-color: rgba(5,150,105,0.4); background: rgba(5,150,105,0.08); }
.gov-footer-sep { color: var(--b2); }
.gov-footer-build { color: var(--t4); }
.gov-footer-cui {
  margin-left: auto;
  color: #5a2d82;
  font-weight: 700;
  font-size: 8px;
  letter-spacing: 0.1em;
  border: 1px solid rgba(90,45,130,0.4);
  background: rgba(90,45,130,0.08);
  padding: 1px 5px;
  border-radius: 2px;
}
.gov-footer-itar {
  color: var(--amber);
  font-weight: 600;
  font-size: 8px;
  letter-spacing: 0.08em;
}

/* ── Content offset for footer ── */
.content {
  padding-bottom: 44px !important;
}
"""

# inject CSS before first </style>
html = html.replace("</style>", CSS + "\n</style>", 1)
print("[+] CSS injected")

# ════════════════════════════════════════════════════════════════════════════
# 2. CLASSIFICATION BANNER — inject at top of <body> (after <body> or <div class="app">)
# ════════════════════════════════════════════════════════════════════════════
BANNER_TOP = """<!-- GOV PATCH: Classification Banner -->
<div class="classif-banner unclass" id="classif-banner-top">
  <span class="classif-banner-label">UNCLASSIFIED // FOR OFFICIAL USE ONLY</span>
  <span class="classif-banner-ts" id="banner-ts"></span>
</div>"""

BANNER_BOTTOM = """<!-- GOV PATCH: Classification Banner Bottom -->
<div class="classif-banner-bottom" id="classif-banner-bot">
  UNCLASSIFIED // FOUO &nbsp;|&nbsp; Handle via CUI procedures &nbsp;|&nbsp; VSP Security Platform
</div>"""

# inject banner after <div class="app">
html = html.replace('<div class="app">', BANNER_TOP + '\n<div class="app">', 1)
print("[+] Classification banner (top) injected")

# ════════════════════════════════════════════════════════════════════════════
# 3. TOPBAR RIGHT — replace existing topbar-right with upgraded version
# ════════════════════════════════════════════════════════════════════════════
OLD_TOPBAR_RIGHT = """    <div class="topbar-right">
      <div class="sse-status">
        <div class="sse-dot sse-live" id="sse-dot"></div>
        <span id="sse-label">SSE live</span>
      </div>
      <button class="notif-btn" onclick="showToast('Notifications — 1 unread','info')">
        🔔
        <span class="notif-count">1</span>
      </button>
      <button class="btn btn-ghost" onclick="loadCurrentPanel()">↻ Refresh</button>
      <button class="btn btn-primary" onclick="document.getElementById('scan-modal').classList.add('open')">+ New Scan</button>
    </div>"""

NEW_TOPBAR_RIGHT = """    <div class="topbar-right">
      <!-- SSE status -->
      <div class="sse-status">
        <div class="sse-dot sse-live" id="sse-dot"></div>
        <span id="sse-label">SSE live</span>
      </div>
      <!-- Session timer -->
      <div class="session-timer" id="session-timer" title="Session expires">
        <span class="session-timer-icon">⏱</span>
        <span id="session-countdown">28:47</span>
      </div>
      <!-- Org selector -->
      <div class="topbar-gov-bar">
        <span style="color:var(--t4)">ORG</span>
        <span class="gov-org" onclick="showToast('Tenant switcher — use sidebar','info')" id="gov-org-label">DEFAULT</span>
      </div>
      <!-- Notification -->
      <button class="notif-btn" onclick="showToast('Notifications — 1 unread','info')">
        🔔
        <span class="notif-count">1</span>
      </button>
      <!-- User pill -->
      <div class="topbar-user-pill" onclick="showToast('Profile settings coming soon','info')">
        <div class="topbar-user-avatar" id="topbar-avatar">A</div>
        <span id="topbar-username">admin</span>
        <span class="user-clearance" id="topbar-clearance">UNCLASS</span>
      </div>
      <!-- Actions -->
      <button class="btn btn-ghost" onclick="loadCurrentPanel()">↻</button>
      <button class="btn btn-primary" onclick="document.getElementById('scan-modal').classList.add('open')">+ Scan</button>
    </div>"""

if OLD_TOPBAR_RIGHT in html:
    html = html.replace(OLD_TOPBAR_RIGHT, NEW_TOPBAR_RIGHT, 1)
    print("[+] Topbar-right upgraded")
else:
    print("[!] WARNING: topbar-right pattern not matched exactly — check manually")

# ════════════════════════════════════════════════════════════════════════════
# 4. FOOTER — inject before </body>
# ════════════════════════════════════════════════════════════════════════════
FOOTER_HTML = """
<!-- GOV PATCH: Footer -->
<footer class="gov-footer" id="gov-footer">
  <span class="gov-footer-badge fedramp">FedRAMP</span>
  <span class="gov-footer-badge cmmc">CMMC L2</span>
  <span class="gov-footer-badge nist">NIST 800-53</span>
  <span class="gov-footer-sep">|</span>
  <span class="gov-footer-build" id="footer-build">VSP v0.10.0 · build <span id="footer-hash">a1b2c3d</span> · <span id="footer-date">2026-03-28</span></span>
  <span class="gov-footer-sep">|</span>
  <span class="gov-footer-itar">ITAR/EAR controlled</span>
  <span class="gov-footer-cui">CUI // FOUO</span>
</footer>
"""

BANNER_BOTTOM_FULL = BANNER_BOTTOM + "\n"

# inject footer + bottom banner before </body>
html = html.replace("</body>", FOOTER_HTML + BANNER_BOTTOM_FULL + "</body>", 1)
print("[+] Footer + bottom banner injected")

# ════════════════════════════════════════════════════════════════════════════
# 5. JS INJECTION — session timer + banner timestamp + user sync
# ════════════════════════════════════════════════════════════════════════════
JS_PATCH = """
// ── GOV PATCH JS ─────────────────────────────────────────────────────────

// Banner timestamp
(function() {
  var el = document.getElementById('banner-ts');
  if (el) {
    function pad(n){ return n<10?'0'+n:n; }
    function tick() {
      var d = new Date();
      el.textContent = pad(d.getUTCFullYear())+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())
        +' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())+' UTC';
    }
    tick(); setInterval(tick, 1000);
  }
})();

// Session countdown timer (30 min session, resets on activity)
(function() {
  var SESSION_MINUTES = 30;
  var expiry = Date.now() + SESSION_MINUTES * 60 * 1000;
  var timerEl = document.getElementById('session-countdown');
  var timerWrap = document.getElementById('session-timer');
  function resetTimer() { expiry = Date.now() + SESSION_MINUTES * 60 * 1000; }
  ['click','keydown','mousemove'].forEach(function(e){
    document.addEventListener(e, resetTimer, {passive:true});
  });
  function tickTimer() {
    var left = Math.max(0, Math.floor((expiry - Date.now()) / 1000));
    var m = Math.floor(left/60), s = left%60;
    if (timerEl) timerEl.textContent = m+':'+(s<10?'0':'')+s;
    if (timerWrap) {
      timerWrap.className = 'session-timer';
      if (left < 300) timerWrap.className += ' warn';
      if (left < 60)  timerWrap.className += ' crit';
      if (left === 0) showToast('Session expired — please re-authenticate','error');
    }
  }
  tickTimer(); setInterval(tickTimer, 1000);
})();

// Sync topbar user from JWT / existing user-row
(function() {
  setTimeout(function() {
    var emailEl = document.querySelector('.user-email');
    var roleEl  = document.querySelector('.user-role');
    if (emailEl) {
      var email = emailEl.textContent.trim();
      var name  = email.split('@')[0];
      var avatarEl = document.getElementById('topbar-avatar');
      var nameEl   = document.getElementById('topbar-username');
      if (avatarEl) avatarEl.textContent = name.charAt(0).toUpperCase();
      if (nameEl)   nameEl.textContent   = name;
    }
    if (roleEl) {
      var role = roleEl.textContent;
      var orgMatch = role.match(/([^·]+)$/);
      var orgEl = document.getElementById('gov-org-label');
      if (orgEl && orgMatch) orgEl.textContent = orgMatch[1].trim().toUpperCase().substring(0,12);
    }
  }, 800);
})();

// Footer build hash from version string if available
(function() {
  var hashEl = document.getElementById('footer-hash');
  if (hashEl && window.VSP_BUILD_HASH) hashEl.textContent = window.VSP_BUILD_HASH;
})();
// ── END GOV PATCH JS ─────────────────────────────────────────────────────
"""

html = html.replace("</body>", "<script>" + JS_PATCH + "</script>\n</body>", 1)
print("[+] JS patch injected")

# ════════════════════════════════════════════════════════════════════════════
# WRITE
# ════════════════════════════════════════════════════════════════════════════
with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Patch complete → {TARGET}")
print(f"   Backup at      → {bak}")
print("""
What was added:
  [1] Classification Banner TOP  — UNCLASSIFIED//FOUO (green), live UTC clock
  [2] Classification Banner BOT  — fixed bottom, mirrors top
  [3] Topbar: session countdown timer (30min, resets on activity)
  [4] Topbar: ORG label (synced from tenant)
  [5] Topbar: User pill with avatar + clearance badge
  [6] Footer: FedRAMP / CMMC L2 / NIST 800-53 badges
  [7] Footer: Build hash + date + ITAR/EAR notice + CUI//FOUO

To roll back:
  cp {bak} {target}
""".format(bak=bak, target=TARGET))
