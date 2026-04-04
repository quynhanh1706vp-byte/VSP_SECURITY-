#!/usr/bin/env python3
"""
VSP Fix v1.6b:
  1. Inject KPI + charts into Runs panel (correct pattern)
  2. Fix SyntaxError: viewRunLog(''r.rid'') → viewRunLog('+JSON.stringify(r.rid)+')"
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_v16b_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

changes = 0

# ════════════════════════════════════════════════════════════════════════════
# 1. Fix SyntaxError: bad onclick in loadRuns patch JS
#    Python escaped \' as '' — fix to use JSON.stringify
# ════════════════════════════════════════════════════════════════════════════
BAD_ONCLICK = """        return '<tr style="cursor:pointer" onclick="viewRunLog(''+r.rid+'')">'"""
GOOD_ONCLICK = """        return '<tr style="cursor:pointer" onclick="viewRunLog(\\'' + r.rid + '\\')">'"""

if BAD_ONCLICK in html:
    html = html.replace(BAD_ONCLICK, GOOD_ONCLICK, 1)
    print("[+] SyntaxError in viewRunLog onclick fixed")
    changes += 1
else:
    # Try alternate — already has correct escaping, check what's there
    import re
    m = re.search(r"viewRunLog\([^)]{0,30}\)", html[html.find("GOV PATCH v1.6"):html.find("GOV PATCH v1.6")+3000] if "GOV PATCH v1.6" in html else html[-4000:])
    if m:
        print(f"[=] viewRunLog pattern found as: {m.group()} — may already be fixed")
    else:
        print("[!] viewRunLog pattern not found for fix")

# ════════════════════════════════════════════════════════════════════════════
# 2. Inject KPI row + charts before panel-runs card
#    Correct anchor: <div id="panel-runs" class="panel">
# ════════════════════════════════════════════════════════════════════════════
OLD_RUNS_ANCHOR = '    <div id="panel-runs" class="panel">\n      <div class="card mb14">'

NEW_RUNS_ANCHOR = '''    <div id="panel-runs" class="panel">
      <!-- GOV PATCH v1.6b: Runs KPI Row -->
      <div class="runs-kpi-row" id="runs-kpi-row">
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Total Runs</div>
          <div class="runs-kpi-value c-cyan" id="rk-total">—</div>
          <div class="runs-kpi-sub">all time</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Pass Rate</div>
          <div class="runs-kpi-value c-green" id="rk-passrate">—</div>
          <div class="runs-kpi-sub" id="rk-pass-sub">gates</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Avg Findings</div>
          <div class="runs-kpi-value c-amber" id="rk-avgfindings">—</div>
          <div class="runs-kpi-sub">per run</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Last Gate</div>
          <div class="runs-kpi-value" id="rk-lastgate" style="font-size:18px">—</div>
          <div class="runs-kpi-sub" id="rk-lastgate-sub">—</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Latest Score</div>
          <div class="runs-kpi-value" id="rk-score">—</div>
          <div class="runs-kpi-sub">/100</div>
        </div>
      </div>

      <!-- GOV PATCH v1.6b: Runs Charts -->
      <div class="runs-chart-row">
        <div class="runs-chart-card">
          <div class="runs-chart-title">Gate decisions — last 20 runs</div>
          <canvas id="runs-gate-chart" height="90"></canvas>
        </div>
        <div class="runs-chart-card">
          <div class="runs-chart-title">Findings by mode</div>
          <canvas id="runs-mode-chart" height="90"></canvas>
        </div>
      </div>

      <div class="card mb14">'''

if OLD_RUNS_ANCHOR in html:
    html = html.replace(OLD_RUNS_ANCHOR, NEW_RUNS_ANCHOR, 1)
    print("[+] Runs KPI row + charts injected")
    changes += 1
else:
    # Try more flexible match
    import re
    pat = re.compile(r'(<div id="panel-runs" class="panel">\s*\n\s*)<div class="card mb14">')
    m = pat.search(html)
    if m:
        html = pat.sub(
            NEW_RUNS_ANCHOR.replace('    <div id="panel-runs" class="panel">\n      <div class="card mb14">', m.group(0)),
            html, count=1
        )
        # simpler: just insert before <div class="card mb14"> inside panel-runs
        idx = html.find('<div id="panel-runs" class="panel">')
        if idx != -1:
            card_idx = html.find('<div class="card mb14">', idx)
            if card_idx != -1:
                KPI_BLOCK = '''      <!-- GOV PATCH v1.6b: Runs KPI Row -->
      <div class="runs-kpi-row" id="runs-kpi-row">
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Total Runs</div>
          <div class="runs-kpi-value c-cyan" id="rk-total">—</div>
          <div class="runs-kpi-sub">all time</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Pass Rate</div>
          <div class="runs-kpi-value c-green" id="rk-passrate">—</div>
          <div class="runs-kpi-sub" id="rk-pass-sub">gates</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Avg Findings</div>
          <div class="runs-kpi-value c-amber" id="rk-avgfindings">—</div>
          <div class="runs-kpi-sub">per run</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Last Gate</div>
          <div class="runs-kpi-value" id="rk-lastgate" style="font-size:18px">—</div>
          <div class="runs-kpi-sub" id="rk-lastgate-sub">—</div>
        </div>
        <div class="runs-kpi-card">
          <div class="runs-kpi-label">Latest Score</div>
          <div class="runs-kpi-value" id="rk-score">—</div>
          <div class="runs-kpi-sub">/100</div>
        </div>
      </div>
      <div class="runs-chart-row">
        <div class="runs-chart-card">
          <div class="runs-chart-title">Gate decisions — last 20 runs</div>
          <canvas id="runs-gate-chart" height="90"></canvas>
        </div>
        <div class="runs-chart-card">
          <div class="runs-chart-title">Findings by mode</div>
          <canvas id="runs-mode-chart" height="90"></canvas>
        </div>
      </div>\n      '''
                html = html[:card_idx] + KPI_BLOCK + html[card_idx:]
                print("[+] Runs KPI row + charts injected (flexible match)")
                changes += 1
    else:
        print("[!] Could not inject Runs KPI — pattern not found")

# ════════════════════════════════════════════════════════════════════════════
# 3. Fix runs table header — add Score column if missing
# ════════════════════════════════════════════════════════════════════════════
OLD_RUNS_THEAD = '<thead><tr><th>Run ID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th><th>Findings</th><th>Tools</th><th>Created</th></tr></thead>'
NEW_RUNS_THEAD = '<thead><tr><th>Run ID</th><th>Mode</th><th>Profile</th><th>Status</th><th>Gate</th><th>Findings</th><th>Tools</th><th>Score</th><th>Created</th></tr></thead>'

if OLD_RUNS_THEAD in html:
    html = html.replace(OLD_RUNS_THEAD, NEW_RUNS_THEAD, 1)
    print("[+] Runs table: Score column added to header")
    changes += 1
else:
    print("[=] Runs thead already updated or pattern changed")

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Fix v1.6b — {changes} changes → {TARGET}")
print(f"   Backup → {bak}")
print("""
Fixed:
  [1] SyntaxError: viewRunLog onclick quote escaping
  [2] Runs KPI row (5 cards) injected above table
  [3] Runs chart row (gate trend + mode doughnut) injected
  [4] Score column added to runs table header
""")
