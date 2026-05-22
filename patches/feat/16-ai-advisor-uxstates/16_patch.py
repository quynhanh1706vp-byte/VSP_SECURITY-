#!/usr/bin/env python3
"""
FEAT-17 (Sprint 13): Apply VSPUXState to AI Advisor panel.

No mock data. Panel had inline loading/error states with custom CSS classes.
This patch upgrades getAdvice() (user-triggered AI advice request) to
VSPUXState for consistency.

Skipped: loadMode() and loadStats() — KPI/badge text updates, skeleton not
applicable (single text values, not tables/lists).

Target: #result (card-style content area for AI response).
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/ai_advisor.html")
BACKUP = pathlib.Path("static/panels/ai_advisor.html.bak.feat16")
MARKER = "/* FEAT-17 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-17 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. Upgrade loading state in getAdvice ───────────────────────
old_loading = """ result.classList.remove('empty');
 result.innerHTML = '<div style="padding:48px;text-align:center;color:var(--t3)"><span class="spin"></span> Generating remediation...</div>';"""
new_loading = """ result.classList.remove('empty');
 if(typeof VSPUXState !== 'undefined'){
   VSPUXState.skeleton('#result', {rows: 4, kind: 'card'});
 } else {
   result.innerHTML = '<div style="padding:48px;text-align:center;color:var(--t3)"><span class="spin"></span> Generating remediation...</div>';
 }"""
if old_loading not in src:
    print("FAIL: getAdvice loading state not found"); sys.exit(1)
src = src.replace(old_loading, new_loading, 1)
print("Upgraded getAdvice loading state")

# ─── 2. Upgrade error state in getAdvice catch ────────────────────
old_error = """ } catch (e) {
 result.innerHTML = `<div style="padding:24px;color:var(--red)">Error: ${escapeHtml(e.message)}</div>`;
 }"""
new_error = """ } catch (e) {
   if(typeof VSPUXState !== 'undefined'){
     VSPUXState.error('#result', 'Error: '+e.message, getAdvice);
   } else {
     result.innerHTML = `<div style="padding:24px;color:var(--red)">Error: ${escapeHtml(e.message)}</div>`;
   }
 }"""
if old_error not in src:
    print("FAIL: getAdvice error catch not found"); sys.exit(1)
src = src.replace(old_error, new_error, 1)
print("Upgraded getAdvice error state")

# ─── 3. Marker top ────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
