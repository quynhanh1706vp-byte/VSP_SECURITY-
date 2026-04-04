#!/usr/bin/env python3
"""
VSP Gov Patch v1.8:
  1. Audit panel — wire KPI + timeline + table to real API
  2. Notification dropdown — fetch from /api/v1/notifications (real data)
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_v18_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# ════════════════════════════════════════════════════════════════════════════
# JS patch
# ════════════════════════════════════════════════════════════════════════════
PATCH_JS = """
// ── GOV PATCH v1.8: Audit real data + Notifications real API ─────────────

// ── Audit Panel ───────────────────────────────────────────────────────────
async function loadAuditReal() {
  await ensureToken();
  var h = {'Authorization': 'Bearer ' + window.TOKEN};

  try {
    // Fetch audit log
    var d = await fetch('/api/v1/audit/log?limit=50', {headers: h}).then(function(r){ return r.json(); });
    var entries = d.entries || [];
    var total   = d.total || entries.length;

    // KPI counts
    var today = new Date().toDateString();
    var todayCount  = entries.filter(function(e){ return new Date(e.created_at).toDateString() === today; }).length;
    var loginCount  = entries.filter(function(e){ return e.action && e.action.indexOf('LOGIN') >= 0; }).length;
    var scanCount   = entries.filter(function(e){ return e.action && e.action.indexOf('SCAN') >= 0; }).length;

    // Update KPI elements
    var kpis = document.querySelectorAll('#panel-audit .kpi-value');
    if (kpis[0]) kpis[0].textContent = total;
    if (kpis[1]) kpis[1].textContent = todayCount;
    if (kpis[2]) kpis[2].textContent = loginCount;
    if (kpis[3]) kpis[3].textContent = scanCount;

    // Timeline (recent 10)
    var tl = document.querySelector('#panel-audit .timeline');
    if (tl && entries.length > 0) {
      var recent = entries.slice(0, 10);
      tl.innerHTML = recent.map(function(e) {
        var isOk   = e.action && (e.action.indexOf('PASS') >= 0 || e.action.indexOf('OK') >= 0);
        var isFail = e.action && (e.action.indexOf('FAIL') >= 0 || e.action.indexOf('ERR') >= 0);
        var isWarn = e.action && e.action.indexOf('WARN') >= 0;
        var isLogin= e.action && e.action.indexOf('LOGIN') >= 0;
        var dotStyle, dotIcon;
        if (isOk)    { dotStyle='background:var(--green2);border:1px solid rgba(34,197,94,.25);color:var(--green)';   dotIcon='✓'; }
        else if (isFail) { dotStyle='background:var(--red2);border:1px solid rgba(239,68,68,.25);color:var(--red)';   dotIcon='✗'; }
        else if (isWarn) { dotStyle='background:var(--amber3);border:1px solid rgba(245,158,11,.25);color:var(--amber)'; dotIcon='⚠'; }
        else if (isLogin){ dotStyle='background:var(--cyan2);border:1px solid rgba(6,182,212,.25);color:var(--cyan)'; dotIcon='→'; }
        else             { dotStyle='background:var(--b2);color:var(--t3)';                                           dotIcon='·'; }

        var dt = new Date(e.created_at);
        var dtStr = (dt.getDate()<10?'0':'')+dt.getDate()+'/'+(dt.getMonth()+1)
          +' '+dt.getHours()+':'+(dt.getMinutes()<10?'0':'')+dt.getMinutes();

        return '<div class="tl-item">'
          + '<div class="tl-dot" style="'+dotStyle+'">'+dotIcon+'</div>'
          + '<div class="tl-content">'
          + '<div class="tl-title">'+e.action+(e.resource?' · '+e.resource:'')+'</div>'
          + '<div class="tl-meta">'+e.ip+' · seq:'+e.seq+' · '+dtStr+'</div>'
          + '</div></div>';
      }).join('');
    } else if (tl) {
      tl.innerHTML = '<div style="padding:16px;color:var(--t3);font-size:10px;font-family:var(--font-mono)">No audit entries yet — actions will appear here</div>';
    }

    // Audit table
    var tbody = document.getElementById('audit-table');
    if (tbody && entries.length > 0) {
      tbody.innerHTML = entries.map(function(e) {
        var actionClass = e.action && e.action.indexOf('LOGIN') >= 0 ? 'pill-run'
          : e.action && e.action.indexOf('FAIL') >= 0 ? 'pill-fail'
          : e.action && e.action.indexOf('PASS') >= 0 ? 'pill-pass' : 'pill-done';
        var dt = new Date(e.created_at);
        var dtStr = (dt.getDate()<10?'0':'')+dt.getDate()+'/'+(dt.getMonth()+1)
          +' '+(dt.getHours()<10?'0':'')+dt.getHours()+':'+(dt.getMinutes()<10?'0':'')+dt.getMinutes();
        return '<tr>'
          + '<td class="mono-sm">'+e.seq+'</td>'
          + '<td><span class="pill '+actionClass+'" style="font-size:8px">'+e.action+'</span></td>'
          + '<td class="mono-sm" style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e.resource+'</td>'
          + '<td class="mono-sm">'+e.ip+'</td>'
          + '<td class="mono-sm">'+dtStr+'</td>'
          + '<td class="mono-sm" style="color:var(--t4)">'+e.hash.slice(0,8)+'…</td>'
          + '</tr>';
      }).join('');
    }

  } catch(err) {
    console.error('loadAuditReal:', err);
  }
}

// Hook into showPanel to load audit data
var _origShowPanelAudit = window.showPanel;
window.showPanel = function(name, btn) {
  if (_origShowPanelAudit) _origShowPanelAudit(name, btn);
  if (name === 'audit') setTimeout(loadAuditReal, 100);
};

// Also run on page load if audit is active
if (document.getElementById('panel-audit') && 
    document.getElementById('panel-audit').classList.contains('active')) {
  setTimeout(loadAuditReal, 500);
}

// ── Notifications real API ────────────────────────────────────────────────
async function _fetchRealNotifications() {
  await ensureToken();
  try {
    var d = await fetch('/api/v1/notifications', {
      headers: {'Authorization': 'Bearer ' + window.TOKEN}
    }).then(function(r){ return r.json(); });

    var notifs = d.notifications || [];
    if (!notifs.length) return; // keep mock data if no real notifs

    // Convert to internal format
    _notifData = notifs.map(function(n) {
      var isLogin = n.title && n.title.indexOf('LOGIN') >= 0;
      var isFail  = n.title && n.title.indexOf('FAIL') >= 0;
      var isPass  = n.title && n.title.indexOf('PASS') >= 0;
      var isScan  = n.title && n.title.indexOf('SCAN') >= 0;
      var type = isFail ? 'fail' : isPass ? 'pass' : isScan ? 'scan' : isLogin ? 'audit' : 'audit';

      var dt = new Date(n.created_at);
      var now = Date.now();
      var diff = Math.floor((now - dt.getTime()) / 60000);
      var timeStr = diff < 1 ? 'just now' : diff < 60 ? diff+'m ago' : Math.floor(diff/60)+'h ago';

      return {
        id: n.id,
        unread: !n.read,
        type: type,
        title: n.title,
        desc: n.body || '',
        time: timeStr,
        action: function() { showPanel('audit', null); }
      };
    });

    _renderNotifList();
  } catch(e) {
    console.error('fetchRealNotifications:', e);
  }
}

// Fetch real notifications on load and every 30s
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(_fetchRealNotifications, 1500);
  setInterval(_fetchRealNotifications, 30000);
});

// ── END GOV PATCH v1.8 ───────────────────────────────────────────────────
"""

html = html.replace("</body>", "<script>" + PATCH_JS + "</script>\n</body>", 1)
print("[+] Audit real data + Notifications real API JS injected")

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Patch v1.8 → {TARGET}")
print(f"   Backup → {bak}")
print("""
What changed:
  [1] Audit KPI: total events, today, logins, scans — from real API
  [2] Audit timeline: real entries with correct icons (✓/✗/⚠/→)
  [3] Audit table: real data with seq, action, resource, ip, time, hash
  [4] Notification dropdown: fetches /api/v1/notifications every 30s
  [5] Notification unread badge: reflects real unread count
""")
