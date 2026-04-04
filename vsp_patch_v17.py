#!/usr/bin/env python3
"""
VSP Fix v1.7 — Runs pagination + chart label fix
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_v17_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# ── 1. Add pagination HTML to Runs panel ─────────────────────────────────
OLD_RUNS_TABLE_END = """        </div>
      </div>
    </div>

    <!-- ════════════════════════════════════
         FINDINGS PANEL"""

NEW_RUNS_TABLE_END = """        </div>
        <div class="pagination" id="runs-pagination-wrap">
          <span class="pagination-info" id="runs-page-info">— runs</span>
          <div class="page-btns" id="runs-page-btns"></div>
        </div>
      </div>
    </div>

    <!-- ════════════════════════════════════
         FINDINGS PANEL"""

if OLD_RUNS_TABLE_END in html:
    html = html.replace(OLD_RUNS_TABLE_END, NEW_RUNS_TABLE_END, 1)
    print("[+] Runs pagination HTML injected")
else:
    print("[!] Runs table end pattern not matched")

# ── 2. JS: add pagination logic to loadRuns ──────────────────────────────
PAGINATION_JS = """
// ── GOV PATCH v1.7: Runs Pagination ─────────────────────────────────────
window._runsState = { page: 0, pageSize: 15, allRuns: [] };

function _renderRunsPage() {
  var state  = window._runsState;
  var runs   = state.allRuns;
  var start  = state.page * state.pageSize;
  var end    = Math.min(start + state.pageSize, runs.length);
  var page   = runs.slice(start, end);

  var modeStyle = {
    IAC:    'background:var(--cyan2);color:var(--cyan);border:1px solid rgba(6,182,212,.25)',
    FULL:   'background:var(--purple2);color:var(--purple);border:1px solid rgba(139,92,246,.25)',
    SAST:   'background:var(--blue2);color:var(--blue);border:1px solid rgba(59,130,246,.25)',
    SCA:    'background:var(--orange2);color:var(--orange);border:1px solid rgba(249,115,22,.25)',
    SECRETS:'background:var(--red2);color:var(--red);border:1px solid rgba(239,68,68,.25)',
    DAST:   'background:var(--green2);color:var(--green);border:1px solid rgba(34,197,94,.25)',
  };
  var gateClass  = {PASS:'pill-pass', FAIL:'pill-fail', WARN:'pill-warn'};
  var statusClass= {DONE:'pill-done', RUNNING:'pill-run', FAILED:'pill-fail', QUEUED:'pill-queue'};

  var tbody = document.getElementById('runs-table');
  if (!tbody) return;

  tbody.innerHTML = page.map(function(r) {
    var sm      = window._normSummary ? window._normSummary(r.summary) : (r.summary||{});
    var score   = sm.SCORE || sm.score || 0;
    var total   = r.total || r.total_findings || 0;
    var scoreColor = score > 70 ? 'var(--green)' : score > 40 ? 'var(--amber)' : score > 0 ? 'var(--red)' : 'var(--t3)';
    var findColor  = total > 0 ? ((sm.CRITICAL||0) > 0 ? 'c-red' : (sm.HIGH||0) > 0 ? 'c-orange' : 'c-amber') : 'c-green';
    var mStyle  = modeStyle[r.mode] || modeStyle.IAC;
    var gClass  = r.gate ? (gateClass[r.gate] || 'pill-done') : '';
    var sClass  = statusClass[r.status] || 'pill-done';
    var dt      = new Date(r.created_at);
    var dateStr = (dt.getDate()<10?'0':'')+dt.getDate()+'/'+(dt.getMonth()<9?'0':'')+(dt.getMonth()+1)
                + ' ' + (dt.getHours()<10?'0':'')+dt.getHours()+':'+(dt.getMinutes()<10?'0':'')+dt.getMinutes();
    return '<tr style="cursor:pointer" onclick="viewRunLog(\\'' + r.rid + '\\')">'
      + '<td class="mono" style="font-size:10px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+r.rid+'">'+r.rid+'</td>'
      + '<td><span class="pill" style="'+mStyle+'">'+r.mode+'</span></td>'
      + '<td class="mono-sm">'+(r.profile||'FAST')+'</td>'
      + '<td><span class="pill '+sClass+'">'+r.status+'</span></td>'
      + '<td>'+(r.gate?'<span class="pill '+gClass+'">'+r.gate+'</span>':'<span class="c-t3">—</span>')+'</td>'
      + '<td class="fw7 '+findColor+'">'+total+'</td>'
      + '<td class="mono-sm">'+(r.tools_done||0)+'/'+(r.tools_total||0)+'</td>'
      + '<td class="mono" style="font-size:11px;color:'+scoreColor+'">'+(score===0?'0':score||'—')+'</td>'
      + '<td class="mono-sm">'+dateStr+'</td>'
      + '</tr>';
  }).join('');

  // Pagination info
  var infoEl = document.getElementById('runs-page-info');
  if (infoEl) infoEl.textContent = 'Showing ' + (start+1) + '–' + end + ' of ' + runs.length + ' runs';

  // Page buttons
  var btnsEl = document.getElementById('runs-page-btns');
  if (btnsEl) {
    var totalPages = Math.ceil(runs.length / state.pageSize);
    var btns = '';
    // Prev
    btns += '<button class="page-btn" '+(state.page===0?'disabled':'')+' onclick="_runsGoPage('+(state.page-1)+')">‹</button>';
    // Page numbers
    for (var i = 0; i < totalPages; i++) {
      if (i === 0 || i === totalPages-1 || Math.abs(i - state.page) <= 1) {
        btns += '<button class="page-btn'+(i===state.page?' active':'')+'" onclick="_runsGoPage('+i+')">'+(i+1)+'</button>';
      } else if (Math.abs(i - state.page) === 2) {
        btns += '<span class="page-btn" style="opacity:.4">…</span>';
      }
    }
    // Next
    btns += '<button class="page-btn" '+(state.page>=totalPages-1?'disabled':'')+' onclick="_runsGoPage('+(state.page+1)+')">›</button>';
    btnsEl.innerHTML = btns;
  }
}

function _runsGoPage(p) {
  var state = window._runsState;
  var totalPages = Math.ceil(state.allRuns.length / state.pageSize);
  state.page = Math.max(0, Math.min(p, totalPages - 1));
  _renderRunsPage();
  // Scroll to top of runs table
  var el = document.getElementById('runs-table');
  if (el) el.closest('.card') && el.closest('.card').scrollIntoView({behavior:'smooth', block:'nearest'});
}

// Override loadRuns to store all runs and use pagination
var _prevLoadRuns = window.loadRuns;
window.loadRuns = async function() {
  await ensureToken();
  try {
    var d = await fetch('/api/v1/vsp/runs/index?limit=200', {
      headers: {'Authorization': 'Bearer ' + window.TOKEN}
    }).then(function(r){ return r.json(); });
    var runs = d.runs || [];
    window._runsState.allRuns = runs;
    window._runsState.page = 0;

    // KPI calculations
    var done = runs.filter(function(r){ return r.status === 'DONE'; });
    var pass = done.filter(function(r){ return r.gate === 'PASS'; });
    var fail = done.filter(function(r){ return r.gate === 'FAIL'; });
    var passRate = done.length > 0 ? Math.round(pass.length / done.length * 100) : 0;
    var totalF   = done.reduce(function(s,r){ return s+(r.total||r.total_findings||0); }, 0);
    var avgF     = done.length > 0 ? Math.round(totalF / done.length) : 0;
    var latest   = runs[0];
    var latestSm = latest ? (window._normSummary ? window._normSummary(latest.summary) : (latest.summary||{})) : {};
    var latestScore = latestSm.SCORE || latestSm.score || 0;
    var lastGate = latest ? (latest.gate || '—') : '—';
    var lastGateColor = lastGate==='PASS'?'var(--green)':lastGate==='FAIL'?'var(--red)':lastGate==='WARN'?'var(--amber)':'var(--t3)';

    function setEl(id, val) { var e=document.getElementById(id); if(e) e.textContent=val; }
    setEl('rk-total', runs.length);
    setEl('rk-passrate', passRate + '%');
    setEl('rk-pass-sub', pass.length + ' pass / ' + fail.length + ' fail');
    setEl('rk-avgfindings', avgF);
    var lgEl = document.getElementById('rk-lastgate');
    if (lgEl) { lgEl.textContent=lastGate; lgEl.style.color=lastGateColor; }
    setEl('rk-lastgate-sub', latest ? latest.rid.slice(-12) : '—');
    var scoreEl = document.getElementById('rk-score');
    if (scoreEl) {
      scoreEl.textContent = latestScore > 0 ? latestScore : 'N/A';
      scoreEl.style.color = latestScore>=70?'var(--green)':latestScore>=40?'var(--amber)':'var(--red)';
    }

    // Gate trend chart
    var last20  = runs.slice(0,20).reverse();
    var gateCtx = document.getElementById('runs-gate-chart');
    if (gateCtx && window.Chart) {
      if (window._runsGateChart) window._runsGateChart.destroy();
      window._runsGateChart = new Chart(gateCtx, {
        type: 'bar',
        data: {
          labels: last20.map(function(r){ return r.rid.slice(-6); }),
          datasets: [{
            data: last20.map(function(r){ return r.gate==='PASS'?1:r.gate==='WARN'?0.5:r.gate==='FAIL'?-1:0; }),
            backgroundColor: last20.map(function(r){
              return r.gate==='PASS'?'rgba(34,197,94,0.7)':r.gate==='WARN'?'rgba(251,191,36,0.7)':r.gate==='FAIL'?'rgba(239,68,68,0.7)':'rgba(100,116,139,0.4)';
            }),
            borderRadius: 3,
          }]
        },
        options: {
          responsive:true, maintainAspectRatio:false,
          plugins:{legend:{display:false}},
          scales:{
            x:{ticks:{display:false},grid:{display:false}},
            y:{display:false,min:-1.2,max:1.2}
          }
        }
      });
    }

    // Findings by mode bar
    var modeCtx = document.getElementById('runs-mode-chart');
    if (modeCtx && window.Chart) {
      var modeTotals={};
      done.forEach(function(r){
        var t=r.total||r.total_findings||0;
        modeTotals[r.mode]=(modeTotals[r.mode]||0)+t;
      });
      var modeColors={IAC:'rgba(6,182,212,0.8)',FULL:'rgba(139,92,246,0.8)',SAST:'rgba(59,130,246,0.8)',SCA:'rgba(249,115,22,0.8)',SECRETS:'rgba(239,68,68,0.8)',DAST:'rgba(34,197,94,0.8)'};
      var modeKeys=Object.keys(modeTotals).filter(function(k){return modeTotals[k]>0;});
      if (window._runsModeChart) window._runsModeChart.destroy();
      window._runsModeChart = new Chart(modeCtx, {
        type:'bar',
        data:{
          labels:modeKeys,
          datasets:[{
            data:modeKeys.map(function(k){return modeTotals[k];}),
            backgroundColor:modeKeys.map(function(k){return modeColors[k]||'rgba(100,116,139,0.6)';}),
            borderRadius:4, borderWidth:0
          }]
        },
        options:{
          indexAxis:'y', responsive:true, maintainAspectRatio:false,
          plugins:{legend:{display:false},tooltip:{callbacks:{label:function(c){return ' '+c.raw+' findings';}}}},
          scales:{
            x:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'var(--t3)',font:{size:9}},beginAtZero:true},
            y:{grid:{display:false},ticks:{color:'var(--t2)',font:{size:10}}}
          }
        }
      });
    }

    // Render paginated table
    _renderRunsPage();

  } catch(e) { console.error('loadRuns v1.7:', e); }
};
// ── END GOV PATCH v1.7 ───────────────────────────────────────────────────
"""

html = html.replace("</body>", "<script>" + PAGINATION_JS + "</script>\n</body>", 1)
print("[+] Runs pagination + loadRuns v1.7 JS injected")

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Patch v1.7 → {TARGET}")
print(f"   Backup → {bak}")
print("""
What changed:
  [1] Runs pagination: 15 runs/page, prev/next/page buttons
  [2] loadRuns fully rewritten — clean, no duplicate code
  [3] Chart mode bar: correct data, tooltip shows findings count
  [4] Gate chart: clean minimal bars
""")
