#!/usr/bin/env python3
"""
vsp_siem_routes.py
Tự động thêm SIEM routes vào gateway/main.go và copy handler file.
Usage: python3 vsp_siem_routes.py
"""
import re, shutil, os, sys
from datetime import datetime

BASE = os.path.expanduser("~/Data/GOLANG_VSP")
MAIN = BASE + "/cmd/gateway/main.go"
HANDLER_DST = BASE + "/internal/api/handler/siem_extended.go"
HANDLER_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem_handlers.go")
MIGRATION_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem_migration.sql")
MIGRATION_DST = BASE + "/migrations/siem_tables.sql"

# ── 1. Copy handler file ───────────────────────────────────────
if os.path.exists(HANDLER_SRC):
    shutil.copy2(HANDLER_SRC, HANDLER_DST)
    print(f"✓  Handler: {HANDLER_DST}")
else:
    print(f"❌  siem_handlers.go not found at {HANDLER_SRC}")
    sys.exit(1)

# ── 2. Copy migration ──────────────────────────────────────────
if os.path.exists(MIGRATION_SRC):
    shutil.copy2(MIGRATION_SRC, MIGRATION_DST)
    print(f"✓  Migration: {MIGRATION_DST}")

# ── 3. Patch main.go — add handler inits + routes ─────────────
bak = MAIN + f".bak_siem_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
shutil.copy2(MAIN, bak)
print(f"✓  Backup: {bak}")

go = open(MAIN).read()

# ── 3a. Handler struct inits (after existing handler inits) ───
HANDLER_INITS = """
\t// ── SIEM handlers ────────────────────────────────────────
\tcorrH      := &handler.Correlation{DB: db}
\tsoarH      := &handler.SOAR{DB: db}
\tlogSrcH    := &handler.LogSources{DB: db}
\ttiH        := &handler.ThreatIntel{DB: db}"""

# Find a good insertion point — after siemH or after existing handler inits
patterns_init = [
    r'(siemH\s*:=\s*&handler\.SIEM\{[^}]+\})',
    r'(auditH\s*:=\s*&handler\.Audit\{[^}]+\})',
    r'(governanceH\s*:=\s*&handler\.Governance\{[^}]+\})',
]
inserted_init = False
for pat in patterns_init:
    m = re.search(pat, go)
    if m:
        go = go[:m.end()] + HANDLER_INITS + go[m.end():]
        inserted_init = True
        print("✓  Handler inits injected after:", m.group(0)[:40])
        break

if not inserted_init:
    print("⚠️   Could not auto-inject handler inits — add manually:")
    print(HANDLER_INITS)

# ── 3b. Route registrations ────────────────────────────────────
ROUTES = """
\t\t// ── Correlation engine ─────────────────────────────────
\t\tr.Get(\"/api/v1/correlation/rules\",           corrH.ListRules)
\t\tr.Post(\"/api/v1/correlation/rules\",          corrH.CreateRule)
\t\tr.Post(\"/api/v1/correlation/rules/{id}/toggle\", corrH.ToggleRule)
\t\tr.Delete(\"/api/v1/correlation/rules/{id}\",   corrH.DeleteRule)
\t\tr.Get(\"/api/v1/correlation/incidents\",       corrH.ListIncidents)
\t\tr.Post(\"/api/v1/correlation/incidents\",      corrH.CreateIncident)

\t\t// ── SOAR playbooks ──────────────────────────────────────
\t\tr.Get(\"/api/v1/soar/playbooks\",              soarH.ListPlaybooks)
\t\tr.Post(\"/api/v1/soar/playbooks\",             soarH.CreatePlaybook)
\t\tr.Post(\"/api/v1/soar/playbooks/{id}/toggle\", soarH.TogglePlaybook)
\t\tr.Post(\"/api/v1/soar/playbooks/{id}/run\",    soarH.RunPlaybook)
\t\tr.Post(\"/api/v1/soar/trigger\",               soarH.Trigger)
\t\tr.Get(\"/api/v1/soar/runs\",                   soarH.ListRuns)

\t\t// ── Log sources ─────────────────────────────────────────
\t\tr.Get(\"/api/v1/logs/sources\",                logSrcH.List)
\t\tr.Post(\"/api/v1/logs/sources\",               logSrcH.Create)
\t\tr.Delete(\"/api/v1/logs/sources/{id}\",        logSrcH.Delete)
\t\tr.Post(\"/api/v1/logs/sources/{id}/test\",     logSrcH.Test)
\t\tr.Get(\"/api/v1/logs/stats\",                  logSrcH.Stats)

\t\t// ── Threat intelligence ─────────────────────────────────
\t\tr.Get(\"/api/v1/ti/iocs\",                     tiH.ListIOCs)
\t\tr.Get(\"/api/v1/ti/feeds\",                    tiH.ListFeeds)
\t\tr.Get(\"/api/v1/ti/matches\",                  tiH.Matches)
\t\tr.Get(\"/api/v1/ti/mitre\",                    tiH.MITRE)
\t\tr.Post(\"/api/v1/ti/feeds/sync\",              tiH.SyncFeeds)"""

# Check already patched
if "corrH.ListRules" in go:
    print("⚠️   Routes already patched — skipping")
else:
    # Find insertion point — after existing siem routes or before closing of auth block
    patterns_route = [
        r'(r\.Get\("/api/v1/siem/webhooks"[^\n]+\n)',
        r'(r\.Delete\("/api/v1/siem/webhooks/\{id\}"[^\n]+\n)',
        r'(r\.Post\("/api/v1/siem/webhooks/\{id\}/test"[^\n]+\n)',
        r'(r\.Get\("/api/v1/audit/log"[^\n]+\n)',
        r'(r\.Get\("/api/v1/governance[^\n]+\n)',
    ]
    inserted_route = False
    for pat in patterns_route:
        m = re.search(pat, go)
        if m:
            go = go[:m.end()] + ROUTES + "\n" + go[m.end():]
            inserted_route = True
            print("✓  Routes injected after:", m.group(0).strip()[:60])
            break

    if not inserted_route:
        print("⚠️   Could not auto-inject routes — add manually to main.go:")
        print(ROUTES)

# ── 4. Write patched main.go ───────────────────────────────────
open(MAIN, "w").write(go)
print(f"✓  main.go updated ({len(go):,} bytes)")

# ── 5. Run migration ───────────────────────────────────────────
print("""
════════════════════════════════════════════════════
  Next steps:
  
  1. Run migration:
     psql $DATABASE_URL -f migrations/siem_tables.sql
  
  2. Build & restart:
     go build ./cmd/gateway/... && bash start.sh
  
  3. Verify routes:
     curl -s -H "Authorization: Bearer $TOKEN" \\
       http://127.0.0.1:8921/api/v1/correlation/rules
════════════════════════════════════════════════════""")
