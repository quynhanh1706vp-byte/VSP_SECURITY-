#!/usr/bin/env python3
"""
VSP Gov Patch v1.3 — Notification Center Dropdown
Replaces showToast() bell button with a real dropdown panel.
Mock data: scan completions, gate failures, SLA alerts, audit events.
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_notifpatch_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# ════════════════════════════════════════════════════════════════════════════
# 1. CSS
# ════════════════════════════════════════════════════════════════════════════
NOTIF_CSS = """
/* ═══════════════════════════════════════════════
   GOV PATCH v1.3 — Notification Center
═══════════════════════════════════════════════ */
.notif-wrapper {
  position: relative;
}
.notif-dropdown {
  display: none;
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  width: 340px;
  background: var(--card, #0f1a2e);
  border: 1px solid var(--b2, rgba(255,255,255,0.1));
  border-radius: 6px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.5);
  z-index: 9000;
  overflow: hidden;
  font-family: var(--font-mono);
}
.notif-dropdown.open { display: block; }

.notif-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid var(--b1, rgba(255,255,255,0.06));
}
.notif-header-title {
  font-size: 10px; font-weight: 700;
  color: var(--t2, #e2e8f0);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.notif-mark-all {
  font-size: 9px; color: var(--cyan, #0ea5e9);
  cursor: pointer; background: none; border: none;
  font-family: var(--font-mono);
  padding: 0;
}
.notif-mark-all:hover { text-decoration: underline; }

.notif-list {
  max-height: 320px;
  overflow-y: auto;
}
.notif-list::-webkit-scrollbar { width: 4px; }
.notif-list::-webkit-scrollbar-track { background: transparent; }
.notif-list::-webkit-scrollbar-thumb { background: var(--b2); border-radius: 2px; }

.notif-item {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--b1, rgba(255,255,255,0.04));
  cursor: pointer;
  transition: background 0.12s;
  position: relative;
}
.notif-item:hover { background: rgba(255,255,255,0.03); }
.notif-item.unread { background: rgba(14,165,233,0.04); }
.notif-item.unread::before {
  content: '';
  position: absolute;
  left: 4px; top: 50%; transform: translateY(-50%);
  width: 4px; height: 4px;
  border-radius: 50%;
  background: var(--cyan, #0ea5e9);
}

.notif-icon {
  width: 28px; height: 28px;
  border-radius: 4px;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
  font-size: 12px;
}
.notif-icon.scan    { background: rgba(14,165,233,0.12); color: #0ea5e9; }
.notif-icon.fail    { background: rgba(239,68,68,0.12);  color: #ef4444; }
.notif-icon.warn    { background: rgba(251,191,36,0.12); color: #fbbf24; }
.notif-icon.pass    { background: rgba(34,197,94,0.12);  color: #22c55e; }
.notif-icon.audit   { background: rgba(139,92,246,0.12); color: #8b5cf6; }
.notif-icon.sla     { background: rgba(251,191,36,0.12); color: #fbbf24; }

.notif-body { flex: 1; min-width: 0; }
.notif-title {
  font-size: 10px; font-weight: 600;
  color: var(--t1, #f1f5f9);
  margin-bottom: 2px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.notif-desc {
  font-size: 9px; color: var(--t3, #64748b);
  line-height: 1.4;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.notif-time {
  font-size: 8px; color: var(--t4, #475569);
  flex-shrink: 0; padding-top: 2px;
}

.notif-empty {
  padding: 24px;
  text-align: center;
  font-size: 10px; color: var(--t4, #475569);
}

.notif-footer {
  padding: 8px 14px;
  border-top: 1px solid var(--b1, rgba(255,255,255,0.06));
  text-align: center;
}
.notif-footer-btn {
  font-size: 9px; color: var(--t3, #64748b);
  background: none; border: none;
  font-family: var(--font-mono);
  cursor: pointer; padding: 0;
}
.notif-footer-btn:hover { color: var(--t1); }

/* Light theme */
[data-theme="light"] .notif-dropdown {
  background: #ffffff;
  border-color: rgba(0,0,0,0.1);
  box-shadow: 0 8px 32px rgba(0,0,0,0.15);
}
[data-theme="light"] .notif-item.unread { background: rgba(14,165,233,0.06); }
"""

html = html.replace("</style>", NOTIF_CSS + "\n</style>", 1)
print("[+] Notification CSS injected")

# ════════════════════════════════════════════════════════════════════════════
# 2. Replace notif button with wrapper + dropdown
# ════════════════════════════════════════════════════════════════════════════
OLD_NOTIF_BTN = """      <button class="notif-btn" onclick="showToast('Notifications — 1 unread','info')">
        🔔
        <span class="notif-count">1</span>
      </button>"""

NEW_NOTIF_HTML = """      <!-- GOV PATCH v1.3: Notification Center -->
      <div class="notif-wrapper" id="notif-wrapper">
        <button class="notif-btn" onclick="toggleNotifPanel(event)" id="notif-bell-btn">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1a5 5 0 015 5v3l1.5 2H1.5L3 9V6a5 5 0 015-5z"/><path d="M6.5 13.5a1.5 1.5 0 003 0"/></svg>
          <span class="notif-count" id="notif-count-badge">1</span>
        </button>
        <div class="notif-dropdown" id="notif-dropdown">
          <div class="notif-header">
            <span class="notif-header-title">Notifications</span>
            <button class="notif-mark-all" onclick="notifMarkAll()">Mark all read</button>
          </div>
          <div class="notif-list" id="notif-list">
            <!-- populated by JS -->
          </div>
          <div class="notif-footer">
            <button class="notif-footer-btn" onclick="showPanel('audit',null);toggleNotifPanel()">
              View full audit log →
            </button>
          </div>
        </div>
      </div>"""

if OLD_NOTIF_BTN in html:
    html = html.replace(OLD_NOTIF_BTN, NEW_NOTIF_HTML, 1)
    print("[+] Notification button replaced with dropdown wrapper")
else:
    print("[!] notif-btn pattern not matched exactly")

# ════════════════════════════════════════════════════════════════════════════
# 3. JS
# ════════════════════════════════════════════════════════════════════════════
NOTIF_JS = """
// ── GOV PATCH v1.3: Notification Center ─────────────────────────────────

var _notifData = [
  {
    id: 1, unread: true, type: 'fail',
    title: 'Gate FAIL — RID_SCHED_20260329',
    desc: 'IAC scan · 104 findings · score 22/100',
    time: '2m ago',
    action: function(){ showPanel('findings', null); }
  },
  {
    id: 2, unread: false, type: 'scan',
    title: 'Scan completed — RID_VSP_20260329',
    desc: 'FULL scan · 49 findings · DONE',
    time: '47m ago',
    action: function(){ showPanel('scanlog', null); }
  },
  {
    id: 3, unread: false, type: 'warn',
    title: 'SLA breach risk — 3 findings',
    desc: 'HIGH severity · due in 2 days',
    time: '1h ago',
    action: function(){ showPanel('sla', null); }
  },
  {
    id: 4, unread: false, type: 'audit',
    title: 'User login — admin@vsp.local',
    desc: 'Authentication · default tenant',
    time: '1h ago',
    action: function(){ showPanel('audit', null); }
  },
  {
    id: 5, unread: false, type: 'pass',
    title: 'Gate PASS — RID_VSP_20260329_164947',
    desc: 'IAC scan · 8 findings · score 81/100',
    time: '3h ago',
    action: function(){ showPanel('runs', null); }
  },
];

var _notifOpen = false;

function _renderNotifList() {
  var list = document.getElementById('notif-list');
  if (!list) return;
  var unread = _notifData.filter(function(n){ return n.unread; });
  var badge = document.getElementById('notif-count-badge');
  if (badge) {
    badge.textContent = unread.length;
    badge.style.display = unread.length > 0 ? '' : 'none';
  }
  if (_notifData.length === 0) {
    list.innerHTML = '<div class="notif-empty">No notifications</div>';
    return;
  }
  var iconMap = { scan:'📡', fail:'✕', warn:'⚠', pass:'✓', audit:'◷', sla:'⏱' };
  list.innerHTML = _notifData.map(function(n) {
    return '<div class="notif-item'+(n.unread?' unread':'')+'" onclick="_notifClick('+n.id+')">'
      + '<div class="notif-icon '+n.type+'">'+(iconMap[n.type]||'●')+'</div>'
      + '<div class="notif-body">'
      +   '<div class="notif-title">'+n.title+'</div>'
      +   '<div class="notif-desc">'+n.desc+'</div>'
      + '</div>'
      + '<div class="notif-time">'+n.time+'</div>'
      + '</div>';
  }).join('');
}

function _notifClick(id) {
  var n = _notifData.find(function(x){ return x.id===id; });
  if (!n) return;
  n.unread = false;
  _renderNotifList();
  toggleNotifPanel();
  if (n.action) n.action();
}

function notifMarkAll() {
  _notifData.forEach(function(n){ n.unread = false; });
  _renderNotifList();
}

function toggleNotifPanel(e) {
  if (e) e.stopPropagation();
  var panel = document.getElementById('notif-dropdown');
  if (!panel) return;
  _notifOpen = !_notifOpen;
  if (_notifOpen) {
    panel.classList.add('open');
    _renderNotifList();
  } else {
    panel.classList.remove('open');
  }
}

// Close on outside click
document.addEventListener('click', function(e) {
  if (!_notifOpen) return;
  var wrapper = document.getElementById('notif-wrapper');
  if (wrapper && !wrapper.contains(e.target)) {
    _notifOpen = false;
    var panel = document.getElementById('notif-dropdown');
    if (panel) panel.classList.remove('open');
  }
});

// Initial render
document.addEventListener('DOMContentLoaded', function() {
  _renderNotifList();
});
// ── END GOV PATCH v1.3 ───────────────────────────────────────────────────
"""

html = html.replace("</body>", "<script>" + NOTIF_JS + "</script>\n</body>", 1)
print("[+] Notification JS injected")

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Notification patch complete → {TARGET}")
print(f"   Backup → {bak}")
print("""
What was added:
  [1] Bell icon (SVG) with unread badge counter
  [2] Dropdown panel — click to open/close
  [3] 5 mock notifications: Gate FAIL, Scan complete, SLA warn, Audit, Gate PASS
  [4] Unread indicator (cyan dot + blue tint)
  [5] Click notification → navigates to relevant panel + marks read
  [6] "Mark all read" button
  [7] "View full audit log →" footer link
  [8] Click outside → closes panel
""")
