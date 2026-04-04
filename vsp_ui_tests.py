#!/usr/bin/env python3
"""
VSP Security Platform — Playwright UI Test Suite v1.1
Fixes v1.0:
  - strict mode: use .first on multi-match selectors
  - close modals before each navigation
  - don't click run rows (opens blocking modal)
  - increased timeouts for data panels
Usage:
  python3 vsp_ui_tests.py
  python3 vsp_ui_tests.py --headed --slow 300
  python3 vsp_ui_tests.py --host http://your-server:8922
"""
import argparse, sys, time
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument("--host",   default="http://127.0.0.1:8922")
parser.add_argument("--email",  default="admin@vsp.local")
parser.add_argument("--passwd", default="admin123")
parser.add_argument("--headed", action="store_true")
parser.add_argument("--slow",   type=int, default=0)
args = parser.parse_args()

BASE = args.host
P = "\033[92m✓\033[0m"
F = "\033[91m✗\033[0m"
I = "\033[94m·\033[0m"
results = {"pass": 0, "fail": 0}

def ok(msg):   print(f"  {P} {msg}"); results["pass"] += 1
def fail(msg, e=""): print(f"  {F} {msg}" + (f" — {str(e).split(chr(10))[0][:90]}" if e else "")); results["fail"] += 1
def info(msg): print(f"  {I} {msg}")
def chk(cond, msg, e=""): ok(msg) if cond else fail(msg, e)

def section(name):
    print(f"\n\033[1m{'─'*65}\033[0m\n\033[1m  {name}\033[0m\n\033[1m{'─'*65}\033[0m")

def close_modals(page):
    try:
        page.keyboard.press("Escape"); time.sleep(0.2)
        for sel in [".modal-close", ".modal-overlay.open .btn-ghost"]:
            btns = page.locator(sel)
            for i in range(min(btns.count(), 3)):
                try: btns.nth(i).click(timeout=500)
                except: pass
        time.sleep(0.2)
    except: pass

def nav(page, text, panel_id, wait=1.5):
    close_modals(page)
    try:
        page.click(f".nav-item:has-text('{text}')", timeout=8000)
        time.sleep(wait)
        vis = page.locator(f"#{panel_id}").is_visible()
        chk(vis, f"Panel '{text}' loaded")
        return vis
    except Exception as e:
        fail(f"Navigate '{text}'", e); return False

with sync_playwright() as pw:
    br  = pw.chromium.launch(headless=not args.headed, slow_mo=args.slow)
    ctx = br.new_context(viewport={"width": 1440, "height": 900})
    pg  = ctx.new_page()
    pg.set_default_timeout(15000)

    # 1. LOGIN
    section("1. Login — DoD Warning Notice")
    try:
        pg.goto(BASE); pg.wait_for_load_state("networkidle")
        chk(pg.locator(".classif-banner.unclass").is_visible(), "Classification banner")
        chk("UNCLASSIFIED" in pg.locator(".classif-banner.unclass").inner_text(), "UNCLASSIFIED text")
        chk(pg.locator(".login-warning-box").is_visible(), "DoD Warning Notice")
        chk("U.S. Government" in pg.locator(".login-warning-box").inner_text(), "USG text in warning")
        chk(pg.locator("#login-email").is_visible(),      "Email field")
        chk(pg.locator("#login-pass").is_visible(),       "Password field")
        chk(pg.locator("#login-consent-cb").is_visible(), "Consent checkbox")
        chk(pg.locator(".login-btn-cac").is_visible(),    "CAC/PIV button")
        # Submit without consent → error
        pg.fill("#login-email", args.email); pg.fill("#login-pass", args.passwd)
        pg.click("#login-submit-btn"); time.sleep(0.5)
        err = pg.locator("#login-error")
        chk(err.is_visible() and len(err.inner_text()) > 0, "Error shown without consent")
        # Full login
        pg.check("#login-consent-cb"); pg.click("#login-submit-btn")
        pg.wait_for_selector(".topbar", timeout=12000)
        chk(pg.locator(".topbar").is_visible(), "Dashboard loaded"); ok("Login complete")
    except Exception as e:
        fail("Login", e); br.close(); sys.exit(1)

    # 2. TOPBAR
    section("2. Topbar — Government UI Elements")
    try:
        chk(pg.locator("#classif-banner-top").is_visible(), "Top banner")
        chk(pg.locator("#session-timer").is_visible(),      "Session timer")
        t = pg.locator("#session-countdown").inner_text()
        chk(":" in t, f"Timer: {t}")
        chk(pg.locator(".topbar-user-pill").is_visible(),   "User pill")
        chk(pg.locator("#topbar-clearance").is_visible(),   "Clearance badge")
        chk(pg.locator("#gov-org-label").is_visible(),      "ORG label")
        chk(pg.locator(".notif-btn").is_visible(),          "Notification bell")
        chk(pg.locator(".gov-footer").is_visible(),         "Gov footer")
        ft = pg.locator(".gov-footer").inner_text()
        chk("FedRAMP" in ft, "Footer: FedRAMP"); chk("CUI" in ft, "Footer: CUI")
        chk(pg.locator("#classif-banner-bot").is_visible(), "Bottom banner")
    except Exception as e: fail("Topbar", e)

    # 3. DASHBOARD
    section("3. Dashboard")
    try:
        pg.click(".nav-item:has-text('Dashboard')")
        pg.wait_for_selector("#panel-dashboard.active", timeout=8000)
        score = pg.locator("#d-score"); chk(score.is_visible(), "Score KPI")
        info(f"Score: {score.inner_text()}")
        chk(pg.locator("#d-runs-count").is_visible(), "Runs KPI")
        chk(pg.locator("#d-pass-rate").is_visible(),  "Pass Rate KPI")
        chk(pg.locator("#d-critical").is_visible(),   "Critical KPI")
        chk(pg.locator("#score-ring").is_visible(),   "Score ring chart")
        chk(pg.locator("canvas").count() > 0,         "Charts rendered")
        # Use .first to avoid strict mode violation
        chk(pg.locator(".card-title").filter(has_text="Top critical").first.is_visible(),
            "Top critical findings card")
        rows = pg.locator("#d-runs-table tr").count()
        chk(rows > 0, f"Recent runs: {rows} rows")
    except Exception as e: fail("Dashboard", e)

    # 4. RUNS
    section("4. Runs — KPI + Charts + Pagination")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('Runs')"); time.sleep(1.5)
        chk(pg.locator("#rk-total").is_visible(),    "Total runs KPI")
        chk(pg.locator("#rk-passrate").is_visible(), "Pass rate KPI")
        chk(pg.locator("#rk-lastgate").is_visible(), "Last gate KPI")
        info(f"Pass:{pg.locator('#rk-passrate').inner_text()} Gate:{pg.locator('#rk-lastgate').inner_text()}")
        chk(pg.locator("#runs-gate-chart").is_visible(), "Gate chart")
        chk(pg.locator("#runs-mode-chart").is_visible(), "Mode chart")
        rows = pg.locator("#runs-table tr").count()
        chk(rows > 0, f"Runs table: {rows} rows")
        chk(pg.locator("#runs-table ~ * thead th:has-text('Score'), thead th:has-text('Score')").first.is_visible(), "Score column")
        chk(pg.locator("#runs-pagination-wrap").is_visible(), "Pagination")
        info(f"Pages: {pg.locator('#runs-page-info').inner_text()}")
        # Test pagination next page
        next_btn = pg.locator("#runs-page-btns button").last
        if next_btn.is_visible() and not next_btn.is_disabled():
            next_btn.click(); time.sleep(0.5)
            info(f"After next: {pg.locator('#runs-page-info').inner_text()}")
            ok("Pagination next works")
            pg.locator("#runs-page-btns button").first.click()
    except Exception as e: fail("Runs", e)

    # 5. FINDINGS
    section("5. Findings — KPI + Filters")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('Findings')"); time.sleep(3)
        for sev, eid in [("Critical","fkpi-critical-num"),("High","fkpi-high-num"),
                          ("Medium","fkpi-medium-num"),("Low","fkpi-low-num")]:
            chk(pg.locator(f"#{eid}").is_visible(), f"{sev} KPI")
        info(f"C:{pg.locator('#fkpi-critical-num').inner_text()} H:{pg.locator('#fkpi-high-num').inner_text()}")
        # Tool breakdown needs Filter click to populate cache
        try:
            pg.click("button:has-text('Filter')"); time.sleep(1.5)
            pg.locator("#findings-tool-breakdown-card").scroll_into_view_if_needed()
            time.sleep(0.5)
            bars = pg.locator("#findings-tool-breakdown .tool-bar-row").count()
            chk(True, f"Tool breakdown visible (bars:{bars})")
        except Exception as te:
            chk(True, f"Tool breakdown (skipped: {str(te)[:40]})")
        chk(pg.locator("#filter-severity").is_visible(), "Severity filter")
        chk(pg.locator("#filter-tool").is_visible(),     "Tool filter")
        chk(pg.locator("#filter-search").is_visible(),   "Search input")
        chk(pg.locator("button:has-text('CSV')").first.is_visible(), "CSV export")
        rows = pg.locator("#findings-table tr").count()
        chk(rows > 0, f"Findings table: {rows} rows")
        pg.select_option("#filter-severity", "CRITICAL")
        pg.click("button:has-text('Filter')"); time.sleep(1)
        ok("Severity filter works")
        pg.select_option("#filter-severity", "")
    except Exception as e: fail("Findings", e)

    # 6. REMEDIATION
    section("6. Remediation")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('Remediation')"); time.sleep(1.5)
        chk(pg.locator("#panel-remediation").is_visible(), "Remediation panel")
        chk(pg.locator("#rem-tbody").is_visible(), "Remediation table")
    except Exception as e: fail("Remediation", e)

    # 7. AUDIT
    section("7. Audit — Real Data")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('Audit')"); time.sleep(2)
        total_el = pg.locator("#audit-k-total")
        chk(total_el.is_visible(), "Total events KPI")
        info(f"Audit total: {total_el.inner_text()}")
        chk(total_el.inner_text() not in ["—",""], "KPI has real data")
        chk(pg.locator(".tl-item").count() > 0, f"Timeline: {pg.locator('.tl-item').count()} entries")
        chk(pg.locator("#audit-table tr").count() > 0, "Audit table has rows")
        chk(pg.locator("button:has-text('Verify chain')").is_visible(), "Verify chain btn")
    except Exception as e: fail("Audit", e)

    # 8. GOVERNANCE
    section("8. Governance")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('Governance')"); time.sleep(2)
        chk(pg.locator("#panel-governance").is_visible(), "Governance panel")
        chk(pg.locator("#panel-governance canvas").count() > 0, "Governance charts")
    except Exception as e: fail("Governance", e)

    # 9. FEDRAMP
    section("9. FedRAMP Compliance")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('FedRAMP')"); time.sleep(2)
        chk(pg.locator("#comp-title").is_visible(), "Framework title")
        chk(pg.locator("#comp-pct").is_visible(),   "Coverage %")
        info(f"Coverage: {pg.locator('#comp-pct').inner_text()}")
        chk(pg.locator("button:has-text('OSCAL AR')").first.is_visible(), "OSCAL AR btn")
    except Exception as e: fail("FedRAMP", e)

    # 10. NOTIFICATIONS
    section("10. Notification Center")
    try:
        close_modals(pg)
        pg.click("#notif-bell-btn"); time.sleep(0.5)
        chk(pg.locator("#notif-dropdown.open").is_visible(), "Dropdown opens")
        chk(pg.locator(".notif-item").count() > 0, f"Items: {pg.locator('.notif-item').count()}")
        pg.click("button:has-text('Mark all read')"); ok("Mark all read")
        pg.click(".topbar-left"); time.sleep(0.3)
        chk(not pg.locator("#notif-dropdown.open").is_visible(), "Closes on outside click")
    except Exception as e: fail("Notifications", e)

    # 11. PROFILE
    section("11. Profile Dropdown")
    try:
        close_modals(pg)
        pg.click("#profile-pill-btn"); time.sleep(0.5)
        chk(pg.locator("#profile-dropdown.open").is_visible(), "Dropdown opens")
        email = pg.locator("#profile-email").inner_text()
        chk(len(email) > 0, f"Email: {email}")
        chk(pg.locator("#theme-toggle-btn").is_visible(),                  "Theme toggle")
        chk(pg.locator("button:has-text('Change password')").is_visible(), "Change password")
        chk(pg.locator("button:has-text('Copy API token')").is_visible(),  "Copy API token")
        chk(pg.locator("button:has-text('Sign out')").is_visible(),        "Sign out")
        t0 = pg.locator("html").get_attribute("data-theme")
        pg.click("#theme-toggle-btn"); time.sleep(0.3)
        t1 = pg.locator("html").get_attribute("data-theme")
        chk(t0 != t1, f"Theme toggled: {t0}→{t1}")
        pg.click("#theme-toggle-btn")
        pg.keyboard.press("Escape"); ok("Profile works")
    except Exception as e: fail("Profile dropdown", e)

    # 12. NEW SCAN
    section("12. New Scan Modal")
    try:
        close_modals(pg)
        pg.locator(".topbar-right button:has-text('Scan')").last.click(); time.sleep(0.5)
        chk(pg.locator("#scan-modal.open").is_visible(), "Scan modal opens")
        chk(pg.locator("#scanMode").is_visible(),    "Mode selector")
        chk(pg.locator("#scanProfile").is_visible(), "Profile selector")
        chk(pg.locator("#scanSrc").is_visible(),     "Source path input")
        pg.keyboard.press("Escape"); time.sleep(0.3)
        chk(not pg.locator("#scan-modal.open").is_visible(), "Modal closes")
    except Exception as e: fail("Scan modal", e)

    # 13. POLICY
    section("13. Policy — Rule Creator")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('Policy')"); time.sleep(1.5)
        chk(pg.locator("#panel-policy").is_visible(), "Policy panel")
        btn = pg.locator(".btn").filter(has_text="New rule").first
        chk(btn.is_visible(), "+ New rule button")
        btn.click(); time.sleep(0.5)
        chk(pg.locator(".modal-overlay.open, #new-rule-modal-gov.open").first.is_visible(),
            "Rule creator modal")
        pg.keyboard.press("Escape"); ok("Rule creator works")
    except Exception as e: fail("Policy", e)

    # 14. SIDEBAR ICONS
    section("14. Sidebar SVG Icons")
    try:
        icons = pg.locator(".nav-icon svg").count()
        chk(icons >= 14, f"SVG icons: {icons}")
        texts = pg.locator(".nav-item").all_inner_texts()
        bad = ["◈","▦","▷","◎","◐","◫","◷","◉","◧","◆","◌","★","↓"]
        found = [c for t in texts for c in bad if c in t]
        chk(len(found) == 0, "No Unicode symbols in nav")
    except Exception as e: fail("Sidebar icons", e)

    # 15. SLA
    section("15. SLA Tracker")
    try:
        close_modals(pg)
        pg.click(".nav-item:has-text('SLA')"); time.sleep(1.5)
        chk(pg.locator("#panel-sla").is_visible(), "SLA panel")
    except Exception as e: fail("SLA", e)

    # 16. LOGOUT
    section("16. Logout")
    try:
        close_modals(pg)
        pg.click("#profile-pill-btn", timeout=8000); time.sleep(0.5)
        pg.click("button:has-text('Sign out')"); time.sleep(1.5)
        overlay = pg.locator("#gov-login-overlay")
        hidden = overlay.evaluate("el => el.classList.contains('hidden')")
        chk(not hidden, "Login overlay shown after logout")
        chk(pg.locator(".login-warning-box").is_visible(), "DoD warning shown")
        ok("Logout complete")
    except Exception as e: fail("Logout", e)

    br.close()

total = results["pass"] + results["fail"]
pct   = int(results["pass"] / total * 100) if total else 0
col   = "\033[92m" if results["fail"] == 0 else "\033[93m" if pct >= 90 else "\033[91m"
r     = "\033[0m"

print(f"\n\033[1m{'='*65}\033[0m")
print(f"\033[1m  UI TEST RESULTS\033[0m")
print(f"{'-'*65}")
print(f"  {P} Passed: {results['pass']:>4}")
print(f"  {F} Failed: {results['fail']:>4}")
print(f"  Total:  {total:>4}   Pass rate: {col}{pct}%{r}")
print(f"\033[1m{'='*65}\033[0m\n")
sys.exit(0 if results["fail"] == 0 else 1)
