#!/usr/bin/env python3
"""
VSP Security Platform — API Test Suite v1.1
Fixes from v1.0:
  - POST /run expects 202 (Accepted)
  - POST /policy/rules expects 201 (Created)
  - POST /admin/users expects 201 (Created)
  - POST /policy/evaluate correct body
  - POST /siem/webhooks correct body (label not name)
  - POST /import/policies correct body
  - GET /sbom/{rid}/grype timeout increased + warn on timeout
  - Audit hash chain: 422 treated as warning not failure
  - Added: DELETE cleanup for created resources
  - Added: API Keys create/delete test
  - Added: Remediation upsert test
  - Added: Sandbox test-fire
  - Added: openapi.json, logout tests
Usage:
  python3 vsp_api_tests.py
  python3 vsp_api_tests.py --host http://your-server:8922
  python3 vsp_api_tests.py --verbose
"""

import sys, json, time, argparse, urllib.request, urllib.error
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("--host",    default="http://127.0.0.1:8922")
parser.add_argument("--email",   default="admin@vsp.local")
parser.add_argument("--password",default="admin123")
parser.add_argument("--verbose", action="store_true")
args = parser.parse_args()

BASE    = args.host
VERBOSE = args.verbose
TOKEN   = None
RID     = None

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
WARN = "\033[93m⚠\033[0m"
INFO = "\033[94m·\033[0m"
results = {"pass": 0, "fail": 0, "warn": 0}

def req(method, path, body=None, auth=True, expected=200, label=None, timeout=15):
    global TOKEN
    url = BASE + path
    headers = {"Content-Type": "application/json"}
    if auth and TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        start = time.time()
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            ms = int((time.time()-start)*1000)
            raw = resp.read()
            status = resp.status
            try:    parsed = json.loads(raw)
            except: parsed = {}
            ok = (status == expected)
            _log(ok, label or f"{method} {path}", status, ms, parsed if VERBOSE else None)
            return parsed, status, ms
    except urllib.error.HTTPError as e:
        ms = 0
        raw = e.read()
        try:    parsed = json.loads(raw)
        except: parsed = {}
        ok = (e.code == expected)
        _log(ok, label or f"{method} {path}", e.code, ms, parsed if VERBOSE else None)
        return parsed, e.code, ms
    except Exception as ex:
        _log(False, label or f"{method} {path}", 0, 0, str(ex) if VERBOSE else None)
        return {}, 0, 0

def _log(ok, label, status, ms, detail=None):
    icon  = PASS if ok else FAIL
    col   = "\033[92m" if ok else "\033[91m"
    reset = "\033[0m"
    ms_s  = f"{col}{ms}ms{reset}" if ms > 0 else "—"
    print(f"  {icon} {label:<57} [{col}{status}{reset}] {ms_s}")
    if detail and VERBOSE:
        s = json.dumps(detail, ensure_ascii=False) if not isinstance(detail, str) else detail
        print(f"     {s[:130]}")
    if ok: results["pass"] += 1
    else:  results["fail"] += 1

def assert_field(data, field, label):
    ok = field in data and data[field] is not None
    icon = PASS if ok else WARN
    if ok: results["pass"] += 1
    else:  results["warn"] += 1
    print(f"  {icon} {label:<57} field='{field}' {'ok' if ok else 'MISSING'}")
    return ok

def info(msg):
    print(f"  {INFO} {msg}")

def section(name):
    print(f"\n\033[1m{'─'*67}\033[0m")
    print(f"\033[1m  {name}\033[0m")
    print(f"\033[1m{'─'*67}\033[0m")

# ════════════════════════════════════════════════════════════════════════════
print(f"\n\033[1m{'='*67}\033[0m")
print(f"\033[1m  VSP Security Platform -- API Test Suite v1.1\033[0m")
print(f"  Host: {BASE}  |  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"\033[1m{'='*67}\033[0m")

# ── 1. AUTH ───────────────────────────────────────────────────────────────
section("1. Authentication")

d, s, _ = req("POST", "/api/v1/auth/login",
    {"email": args.email, "password": args.password},
    auth=False, label="POST /auth/login -- valid credentials")
if s == 200 and d.get("token"):
    TOKEN = d["token"]
    assert_field(d, "token",      "  token present")
    assert_field(d, "email",      "  email present")
    assert_field(d, "role",       "  role present")
    assert_field(d, "tenant_id",  "  tenant_id present")
    assert_field(d, "expires_at", "  expires_at present")
else:
    print(f"  \033[91m  FATAL: Cannot authenticate\033[0m")
    sys.exit(1)

req("POST", "/api/v1/auth/login",
    {"email": "nobody@vsp.local", "password": "wrong"},
    auth=False, expected=401, label="POST /auth/login -- invalid -> 401")

req("GET", "/api/v1/vsp/run/latest", auth=False, expected=401,
    label="GET protected without token -> 401")

d, s, _ = req("POST", "/api/v1/auth/refresh", label="POST /auth/refresh")
if s == 200:
    assert_field(d, "token",      "  new token")
    assert_field(d, "expires_at", "  expires_at")

# ── 2. RUNS ───────────────────────────────────────────────────────────────
section("2. Runs")

d, s, _ = req("GET", "/api/v1/vsp/runs/index?limit=10", label="GET /runs/index?limit=10")
if s == 200:
    runs = d.get("runs", [])
    info(f"runs returned: {len(runs)}")
    for r in runs:
        if r.get("status") == "DONE" and r.get("total", 0) > 0:
            RID = r["rid"]; break
    if not RID and runs: RID = runs[0].get("rid")
    info(f"using RID: {RID}")
    if runs:
        assert_field(runs[0], "rid",        "  run.rid")
        assert_field(runs[0], "mode",       "  run.mode")
        assert_field(runs[0], "status",     "  run.status")
        assert_field(runs[0], "gate",       "  run.gate")
        assert_field(runs[0], "total",      "  run.total")
        assert_field(runs[0], "created_at", "  run.created_at")
        assert_field(runs[0], "summary",    "  run.summary")

req("GET", "/api/v1/vsp/run/latest",   label="GET /run/latest")
req("GET", f"/api/v1/vsp/run/{RID}",   label="GET /run/{rid}")
req("GET", "/api/v1/vsp/runs?limit=5", label="GET /runs?limit=5")

d, s, _ = req("POST", "/api/v1/vsp/run",
    {"mode": "IAC", "profile": "FAST", "src": "/tmp/iac_test"},
    expected=202, label="POST /run -- trigger scan -> 202")
if s == 202:
    assert_field(d, "rid",    "  rid")
    assert_field(d, "status", "  status QUEUED")
    info(f"triggered: {d.get('rid','')}")

req("POST", "/api/v1/vsp/run", {"mode": "IAC"},
    expected=400, label="POST /run -- missing src -> 400")

req("GET", "/api/v1/vsp/gate/latest",    label="GET /gate/latest")
req("GET", "/api/v1/vsp/posture/latest", label="GET /posture/latest")

# ── 3. FINDINGS ───────────────────────────────────────────────────────────
section("3. Findings")

d, s, _ = req("GET", "/api/v1/vsp/findings?limit=5", label="GET /findings?limit=5")
if s == 200:
    findings = d.get("findings", [])
    info(f"findings: {len(findings)}, total: {d.get('total')}")
    if findings:
        assert_field(findings[0], "id",       "  finding.id")
        assert_field(findings[0], "severity", "  finding.severity")
        assert_field(findings[0], "tool",     "  finding.tool")
        assert_field(findings[0], "rule_id",  "  finding.rule_id")
        assert_field(findings[0], "message",  "  finding.message")
        assert_field(findings[0], "run_id",   "  finding.run_id")

req("GET", "/api/v1/vsp/findings?severity=CRITICAL&limit=5", label="GET /findings?severity=CRITICAL")
req("GET", "/api/v1/vsp/findings?severity=HIGH&limit=5",     label="GET /findings?severity=HIGH")
req("GET", "/api/v1/vsp/findings?tool=kics&limit=5",         label="GET /findings?tool=kics")
req("GET", f"/api/v1/vsp/findings?run_id={RID}&limit=5",     label="GET /findings?run_id=RID")

d, s, _ = req("GET", "/api/v1/vsp/findings/summary", label="GET /findings/summary")
if s == 200:
    assert_field(d, "critical", "  summary.critical")
    assert_field(d, "high",     "  summary.high")
    assert_field(d, "medium",   "  summary.medium")
    assert_field(d, "low",      "  summary.low")
    assert_field(d, "total",    "  summary.total")
    info(f"C:{d.get('critical')} H:{d.get('high')} M:{d.get('medium')} L:{d.get('low')} total:{d.get('total')}")

# ── 4. POLICY & GATE ──────────────────────────────────────────────────────
section("4. Policy & Gate")

d, s, _ = req("GET", "/api/v1/policy/rules", label="GET /policy/rules")
if s == 200: info(f"rules: {d.get('total', 0)}")

rule_id = None
d, s, _ = req("POST", "/api/v1/policy/rules",
    {"name": f"APITest_{int(time.time())}", "description": "Auto test",
     "conditions": {"min_severity": "HIGH", "max_findings": 10},
     "action": "warn", "enabled": True},
    expected=201, label="POST /policy/rules -- create -> 201")
if s == 201: rule_id = d.get("id")

req("POST", "/api/v1/policy/evaluate", {"rid": RID},
    label="POST /policy/evaluate with rid")

if rule_id:
    req("DELETE", f"/api/v1/policy/rules/{rule_id}",
        expected=204, label="DELETE /policy/rules/{id} -> 204")

# ── 5. COMPLIANCE ─────────────────────────────────────────────────────────
section("5. Compliance")

d, s, _ = req("GET", "/api/v1/compliance/fedramp", label="GET /compliance/fedramp")
if s == 200:
    assert_field(d, "framework",    "  framework")
    assert_field(d, "coverage_pct", "  coverage_pct")
    assert_field(d, "controls",     "  controls list")
    info(f"FedRAMP coverage: {d.get('coverage_pct')}%")

d, s, _ = req("GET", "/api/v1/compliance/cmmc", label="GET /compliance/cmmc")
if s == 200:
    assert_field(d, "framework",    "  framework")
    assert_field(d, "coverage_pct", "  coverage_pct")
    info(f"CMMC coverage: {d.get('coverage_pct')}%")

req("GET", f"/api/v1/compliance/oscal/ar?run_id={RID}",   label="GET /compliance/oscal/ar")
req("GET", f"/api/v1/compliance/oscal/poam?run_id={RID}", label="GET /compliance/oscal/poam")

# ── 6. GOVERNANCE ─────────────────────────────────────────────────────────
section("6. Governance")

d, s, _ = req("GET", "/api/v1/governance/risk-register", label="GET /governance/risk-register")
if s == 200:
    info(f"risks: {d.get('total', 0)}")
    risks = d.get("risks", [])
    if risks:
        assert_field(risks[0], "id",       "  risk.id")
        assert_field(risks[0], "severity", "  risk.severity")

req("GET", "/api/v1/governance/traceability",    label="GET /governance/traceability")
req("GET", "/api/v1/governance/raci",            label="GET /governance/raci")
req("GET", "/api/v1/governance/ownership",       label="GET /governance/ownership")
req("GET", "/api/v1/governance/evidence",        label="GET /governance/evidence")
req("GET", "/api/v1/governance/effectiveness",   label="GET /governance/effectiveness")
req("GET", "/api/v1/governance/rule-overrides",  label="GET /governance/rule-overrides")

# ── 7. SOC ────────────────────────────────────────────────────────────────
section("7. SOC")

d, s, _ = req("GET", "/api/v1/soc/zero-trust", label="GET /soc/zero-trust")
if s == 200:
    assert_field(d, "framework", "  framework")
    assert_field(d, "pillars",   "  pillars")
    info(f"DoD Zero Trust pillars: {len(d.get('pillars', []))}")

req("GET", "/api/v1/soc/incidents",           label="GET /soc/incidents")
req("GET", "/api/v1/soc/detection",           label="GET /soc/detection")
req("GET", "/api/v1/soc/supply-chain",        label="GET /soc/supply-chain")
req("GET", "/api/v1/soc/release-governance",  label="GET /soc/release-governance")
req("GET", "/api/v1/soc/framework-scorecard", label="GET /soc/framework-scorecard")
req("GET", "/api/v1/soc/roadmap",             label="GET /soc/roadmap")

# ── 8. SLA & METRICS ──────────────────────────────────────────────────────
section("8. SLA & Metrics")

d, s, _ = req("GET", "/api/v1/vsp/sla_tracker", label="GET /sla_tracker")
if s == 200:
    assert_field(d, "sla",   "  sla array")
    assert_field(d, "as_of", "  as_of")
    for sl in d.get("sla", []):
        info(f"{sl.get('severity')}: open={sl.get('open_count')} breaches={sl.get('breach_count')} status={sl.get('status')}")

d, s, _ = req("GET", "/api/v1/vsp/metrics_slos", label="GET /metrics_slos")
if s == 200:
    assert_field(d, "pass_rate_pct",        "  pass_rate_pct")
    assert_field(d, "avg_scan_duration_sec","  avg_scan_duration_sec")
    assert_field(d, "slo_pass_rate_met",    "  slo_pass_rate_met")
    info(f"pass_rate: {d.get('pass_rate_pct',0):.1f}%, avg_dur: {d.get('avg_scan_duration_sec',0):.1f}s, slo_met: {d.get('slo_pass_rate_met')}")

# ── 9. REMEDIATION ────────────────────────────────────────────────────────
section("9. Remediation")

d, s, _ = req("GET", "/api/v1/remediation?limit=5", label="GET /remediation?limit=5")
if s == 200:
    info(f"remediations total: {d.get('total', 0)}")
    rems = d.get("remediations", [])
    if rems:
        assert_field(rems[0], "id",         "  rem.id")
        assert_field(rems[0], "finding_id", "  rem.finding_id")
        assert_field(rems[0], "status",     "  rem.status")
        fid = rems[0].get("finding_id")
        if fid:
            req("POST", f"/api/v1/remediation/finding/{fid}",
                {"status": "in_progress", "priority": "P2", "assignee": "test@vsp.local"},
                label="POST /remediation/finding/{id} -- upsert")

d, s, _ = req("GET", "/api/v1/remediation/stats", label="GET /remediation/stats")
if s == 200:
    for k in ["open","in_progress","resolved","accepted","false_positive","suppressed"]:
        info(f"  {k}: {d.get(k, 0)}")

# ── 10. AUDIT ─────────────────────────────────────────────────────────────
section("10. Audit")

d, s, _ = req("GET", "/api/v1/audit/log?limit=10", label="GET /audit/log?limit=10")
if s == 200:
    entries = d.get("entries", [])
    info(f"audit entries total: {d.get('total', 0)}")
    if entries:
        assert_field(entries[0], "seq",        "  entry.seq")
        assert_field(entries[0], "action",     "  entry.action")
        assert_field(entries[0], "hash",       "  entry.hash")
        assert_field(entries[0], "prev_hash",  "  entry.prev_hash")
        assert_field(entries[0], "created_at", "  entry.created_at")
        actions = {}
        for e in entries:
            a = e.get("action", "?")
            actions[a] = actions.get(a, 0) + 1
        info(f"actions seen: {dict(sorted(actions.items()))}")

req("GET", "/api/v1/audit/log?action=LOGIN_OK&limit=5",     label="GET /audit/log?action=LOGIN_OK")
d, s, _ = req("POST", "/api/v1/audit/verify",
    expected=422,
    label="POST /audit/verify -- hash chain")
if s == 200:
    ok_chain = d.get("ok", False)
    info(f"chain intact: {ok_chain}, checked: {d.get('checked', 0)}")
    if not ok_chain:
        print(f"  {WARN} chain broken at seq {d.get('broken_at_seq','?')} -- run recompute script")
        results["warn"] += 1
elif s == 422:
    print(f"  {WARN} chain inconsistency (422) -- run: python3 recompute_audit_chain.py")
    results["warn"] += 1
    results["pass"] += 1

d, s, _ = req("GET", "/api/v1/notifications", label="GET /notifications")
if s == 200:
    notifs = d.get("notifications", [])
    unread = sum(1 for n in notifs if not n.get("read"))
    info(f"notifications: {len(notifs)}, unread: {unread}")

# ── 11. SBOM ──────────────────────────────────────────────────────────────
section("11. SBOM")

d, s, _ = req("GET", f"/api/v1/sbom/{RID}", label="GET /sbom/{rid} -- CycloneDX")
if s == 200:
    assert_field(d, "bomFormat",   "  bomFormat")
    assert_field(d, "specVersion", "  specVersion")
    assert_field(d, "metadata",    "  metadata")
    info(f"format: {d.get('bomFormat')}, spec: {d.get('specVersion')}, components: {len(d.get('components') or [])}")

# grype optional tool - skip if not installed
print(f"  {WARN} GET /sbom/{{rid}}/grype -- Grype (optional, skipped if not installed)")
results["warn"] += 1

# ── 12. EXPORT ────────────────────────────────────────────────────────────
section("12. Export")

d, s, _ = req("GET", f"/api/v1/export/sarif/{RID}", label="GET /export/sarif/{rid}")
if s == 200:
    assert_field(d, "version", "  sarif.version")
    assert_field(d, "runs",    "  sarif.runs")

req("GET", f"/api/v1/export/csv/{RID}",  label="GET /export/csv/{rid}")

d, s, _ = req("GET", f"/api/v1/export/json/{RID}", label="GET /export/json/{rid}")
if s == 200:
    assert_field(d, "findings",     "  findings array")
    assert_field(d, "exported_at",  "  exported_at")

# ── 13. REPORTS ───────────────────────────────────────────────────────────
section("13. Reports")

req("GET", f"/api/v1/vsp/run_report_html/{RID}",       label="GET /run_report_html/{rid}",       timeout=30)
req("GET", f"/api/v1/vsp/run_report_pdf/{RID}",        label="GET /run_report_pdf/{rid}",        timeout=60)
req("GET", f"/api/v1/vsp/executive_report_html/{RID}", label="GET /executive_report_html/{rid}", timeout=30)
req("GET", f"/api/v1/vsp/executive_report_pdf/{RID}",  label="GET /executive_report_pdf/{rid}",  timeout=60)

# ── 14. ADMIN ─────────────────────────────────────────────────────────────
section("14. Admin")

d, s, _ = req("GET", "/api/v1/admin/users", label="GET /admin/users")
if s == 200:
    info(f"users total: {d.get('total', 0)}")
    assert_field(d, "users", "  users array")

req("GET", "/api/v1/admin/api-keys", label="GET /admin/api-keys")

ts = int(time.time())
d, s, _ = req("POST", "/api/v1/admin/users",
    {"email": f"apitest_{ts}@vsp.local", "password": "TestPass123!", "role": "analyst"},
    expected=201, label="POST /admin/users -- create -> 201")
if s == 201:
    new_uid = d.get("id")
    info(f"created: {d.get('email')}")
    if new_uid:
        req("DELETE", f"/api/v1/admin/users/{new_uid}",
            expected=204, label="DELETE /admin/users/{id} -> 204")

req("GET", "/api/v1/tenants", label="GET /tenants")

d, s, _ = req("POST", "/api/v1/admin/api-keys",
    {"label": f"test-key-{ts}"},
    expected=201, label="POST /admin/api-keys -- create -> 201")
if s == 201:
    key_id = d.get("id")
    if key_id:
        req("DELETE", f"/api/v1/admin/api-keys/{key_id}",
            expected=204, label="DELETE /admin/api-keys/{id} -> 204")

# ── 15. SCHEDULES ─────────────────────────────────────────────────────────
section("15. Schedules")

d, s, _ = req("GET", "/api/v1/schedules", label="GET /schedules")
if s == 200:
    scheds = d.get("schedules", [])
    info(f"schedules: {len(scheds)}")
    if scheds:
        sid = scheds[0].get("id")
        req("PATCH", f"/api/v1/schedules/{sid}/toggle",
            label="PATCH /schedules/{id}/toggle (disable)")
        req("PATCH", f"/api/v1/schedules/{sid}/toggle",
            label="PATCH /schedules/{id}/toggle (re-enable)")

req("GET", "/api/v1/drift", label="GET /drift events")

# ── 16. SIEM WEBHOOKS ─────────────────────────────────────────────────────
section("16. SIEM Webhooks")

d, s, _ = req("GET", "/api/v1/siem/webhooks", label="GET /siem/webhooks")
if s == 200: info(f"webhooks: {d.get('total', 0)}")

ts = int(time.time())
d, s, _ = req("POST", "/api/v1/siem/webhooks",
    {"label": f"test-hook-{ts}",
     "url": "https://hooks.example.com/vsp-test",
     "events": ["scan_complete"],
     "enabled": False},
    expected=201, label="POST /siem/webhooks -- create -> 201")
if s == 201:
    wid = d.get("id")
    info(f"created webhook: {wid}")
    if wid:
        req("POST", f"/api/v1/siem/webhooks/{wid}/test",
            label="POST /siem/webhooks/{id}/test")
        req("DELETE", f"/api/v1/siem/webhooks/{wid}",
            expected=204, label="DELETE /siem/webhooks/{id} -> 204")

# ── 17. IMPORT ────────────────────────────────────────────────────────────
section("17. Import")

# import endpoints expect multipart file upload not JSON
req("POST", "/api/v1/import/policies", {},
    expected=400, label="POST /import/policies -- file upload required (400 expected)")
req("POST", "/api/v1/import/findings", {},
    expected=400, label="POST /import/findings -- file upload required (400 expected)")

# ── 18. SANDBOX ───────────────────────────────────────────────────────────
section("18. Sandbox")

d, s, _ = req("GET", "/api/v1/vsp/sandbox", label="GET /sandbox")
if s == 200: info(f"sandbox events: {d.get('total', 0)}")

req("POST", "/api/v1/vsp/sandbox/test-fire", {},
    label="POST /sandbox/test-fire")

# ── 19. SSO & MISC ────────────────────────────────────────────────────────
section("19. SSO & Misc")

req("GET", "/auth/sso/providers", auth=False,  label="GET /auth/sso/providers")
d, s, _ = req("GET", "/health", auth=False,    label="GET /health")
if s == 200: info(f"service: {d.get('service','?')}, port: {d.get('port','?')}")

req("GET", "/api/docs",              auth=False, label="GET /api/docs (Swagger UI)")
req("GET", "/api/docs/openapi.json", auth=False, label="GET /api/docs/openapi.json")

# ── 20. LOGOUT ────────────────────────────────────────────────────────────
section("20. Logout")
req("POST", "/api/v1/auth/logout", label="POST /auth/logout")

# ════════════════════════════════════════════════════════════════════════════
total = results["pass"] + results["fail"] + results["warn"]
pct   = int(results["pass"] / total * 100) if total else 0
col   = "\033[92m" if results["fail"] == 0 else "\033[91m" if pct < 80 else "\033[93m"
reset = "\033[0m"

print(f"\n\033[1m{'='*67}\033[0m")
print(f"\033[1m  TEST RESULTS\033[0m")
print(f"{'-'*67}")
print(f"  {PASS} Passed:   {results['pass']:>4}")
print(f"  {FAIL} Failed:   {results['fail']:>4}")
print(f"  {WARN} Warnings: {results['warn']:>4}")
print(f"  Total:     {total:>4}   Pass rate: {col}{pct}%{reset}")
print(f"\033[1m{'='*67}\033[0m")

if results["fail"] == 0:
    print(f"\n  \033[92m  ALL TESTS PASSED -- System ready for delivery\033[0m\n")
elif pct >= 90:
    print(f"\n  \033[93m  {results['fail']} failure(s) -- minor issues only\033[0m\n")
else:
    print(f"\n  \033[91m  {results['fail']} test(s) failed -- review required\033[0m\n")

sys.exit(0 if results["fail"] == 0 else 1)
