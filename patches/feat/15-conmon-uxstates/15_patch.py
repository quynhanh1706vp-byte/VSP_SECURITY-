#!/usr/bin/env python3
"""
FEAT-16 (Sprint 12): Apply VSPUXState to ConMon panel.

No mock data. UX upgrade — panel had complete inline UX states (loading/empty/
error) but used plain HTML strings. This patch upgrades to VSPUXState for
consistency with FEAT-05/06/07/08/10/11/12/13/14/15.

Targets: #schedules-body, #deviations-body
Loaders: loadSchedules(), loadDeviations()
loadCadence() left unchanged (no table target).
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/conmon.html")
BACKUP = pathlib.Path("static/panels/conmon.html.bak.feat15")
MARKER = "/* FEAT-16 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-16 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Inject skeleton at loadSchedules entry ───────────────────
old_sched_entry = "async function loadSchedules() {"
new_sched_entry = '''async function loadSchedules() {
  if(typeof VSPUXState !== 'undefined') VSPUXState.skeleton('#schedules-body', {rows: 4});'''
if old_sched_entry not in src:
    print("FAIL: loadSchedules entry not found"); sys.exit(1)
# Use count=1 to only replace the first occurrence
idx = src.find(old_sched_entry)
src = src[:idx] + new_sched_entry + src[idx + len(old_sched_entry):]
print("Injected skeleton at loadSchedules entry")

# ─── 2. Upgrade loadSchedules empty inline ───────────────────────
old_sched_empty = "tbody.innerHTML = '<tr><td colspan=\"7\" class=\"empty\">No schedules. Click \"+ New Schedule\" to create one.</td></tr>';"
new_sched_empty = '''if(typeof VSPUXState !== 'undefined'){VSPUXState.empty('#schedules-body','No schedules — click + New Schedule to create one',loadSchedules);}else{tbody.innerHTML = '<tr><td colspan="7" class="empty">No schedules.</td></tr>';}'''
if old_sched_empty not in src:
    print("FAIL: loadSchedules empty not found"); sys.exit(1)
src = src.replace(old_sched_empty, new_sched_empty, 1)
print("Upgraded loadSchedules empty state")

# ─── 3. Inject skeleton at loadDeviations entry ──────────────────
old_dev_entry = "async function loadDeviations() {"
new_dev_entry = '''async function loadDeviations() {
  if(typeof VSPUXState !== 'undefined') VSPUXState.skeleton('#deviations-body', {rows: 4});'''
if old_dev_entry not in src:
    print("FAIL: loadDeviations entry not found"); sys.exit(1)
idx = src.find(old_dev_entry)
src = src[:idx] + new_dev_entry + src[idx + len(old_dev_entry):]
print("Injected skeleton at loadDeviations entry")

# ─── 4. Upgrade loadDeviations empty inline ──────────────────────
# Use regex because line has template literal ${openOnly ? 'open ' : ''}
old_dev_empty_re = re.compile(
    r"tbody\.innerHTML = `<tr><td colspan=\"7\" class=\"empty\">No \$\{openOnly \? 'open ' : ''\}deviations</td></tr>`;"
)
m = old_dev_empty_re.search(src)
if not m:
    print("FAIL: loadDeviations empty not found"); sys.exit(1)
new_dev_empty = '''if(typeof VSPUXState !== 'undefined'){VSPUXState.empty('#deviations-body', 'No '+(openOnly?'open ':'')+'deviations', loadDeviations);}else{tbody.innerHTML = `<tr><td colspan="7" class="empty">No ${openOnly ? 'open ' : ''}deviations</td></tr>`;}'''
src = src[:m.start()] + new_dev_empty + src[m.end():]
print("Upgraded loadDeviations empty state")

# ─── 5. Upgrade error catches to VSPUXState (2 instances) ────────
# Pattern: tbody.innerHTML = `<tr><td colspan="7" class="empty">Error: ${e.message}</td></tr>`;
# Replace both occurrences
old_err_re = re.compile(
    r"tbody\.innerHTML = `<tr><td colspan=\"7\" class=\"empty\">Error: \$\{e\.message\}</td></tr>`;"
)
matches = list(old_err_re.finditer(src))
if len(matches) < 2:
    print(f"FAIL: expected 2 error patterns, found {len(matches)}"); sys.exit(1)

# Replace 2nd occurrence first (deviations) to keep indices valid
m2 = matches[1]
new_dev_err = '''if(typeof VSPUXState !== 'undefined'){VSPUXState.error('#deviations-body', 'Error: '+e.message, loadDeviations);}else{tbody.innerHTML = `<tr><td colspan="7" class="empty">Error: ${e.message}</td></tr>`;}'''
src = src[:m2.start()] + new_dev_err + src[m2.end():]

# Re-find first occurrence (now the only remaining)
m1 = old_err_re.search(src)
if not m1:
    print("FAIL: schedules error pattern not found after deviation replace"); sys.exit(1)
new_sched_err = '''if(typeof VSPUXState !== 'undefined'){VSPUXState.error('#schedules-body', 'Error: '+e.message, loadSchedules);}else{tbody.innerHTML = `<tr><td colspan="7" class="empty">Error: ${e.message}</td></tr>`;}'''
src = src[:m1.start()] + new_sched_err + src[m1.end():]
print("Upgraded both error catches")

# ─── 6. Marker ───────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
