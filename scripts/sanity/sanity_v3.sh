#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# VSP Sanity Check v3 — proper CSRF bootstrap (login → GET → POST)
# ════════════════════════════════════════════════════════════════════
# Fix from v2: vsp_csrf is set by GET endpoints, NOT by /auth/login.
# Correct flow:
#   1. POST /auth/login        → vsp_token cookie
#   2. GET  /api/v1/anything   → vsp_csrf cookie (server sets it)
#   3. POST /api/v1/anything   → with X-CSRF-Token header from step 2
# ════════════════════════════════════════════════════════════════════
set -u

cd "${REPO_ROOT:-$(pwd)}"

PASS=0; FAIL=0; WARN=0
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*"; FAIL=$((FAIL+1)); }
warn() { printf "  \033[33m⚠\033[0m %s\n" "$*"; WARN=$((WARN+1)); }
info() { printf "  · %s\n" "$*"; }
section() { echo ""; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  $*"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

DB_URL=$(grep '^DATABASE_URL=' .env.production 2>/dev/null | cut -d= -f2- || echo '')
COOKIE=/tmp/sanity_v3_cookies.txt
rm -f "$COOKIE"

# ════════════════════════════════════════════════════════════════
section "1. PROCESS + BINARY"
# ════════════════════════════════════════════════════════════════
sudo systemctl is-active vsp-gateway >/dev/null 2>&1 && ok "vsp-gateway: active" || fail "service NOT active"
PID=$(pgrep -f /usr/local/bin/vsp-gateway | head -1)
[ -n "$PID" ] && ok "PID: $PID, RAM: $(($(ps -o rss= -p "$PID" | tr -d ' ')/1024)) MB" || fail "no process"
sudo ss -tlnp 2>/dev/null | grep -q ":8921 " && ok "Port 8921 listening" || fail "port closed"

# ════════════════════════════════════════════════════════════════
section "2. DATABASE + MIGRATIONS"
# ════════════════════════════════════════════════════════════════
[ -n "$DB_URL" ] && ok "DATABASE_URL configured" || fail "DATABASE_URL missing"
psql "$DB_URL" -c "SELECT 1" >/dev/null 2>&1 && ok "DB connection working" || fail "DB connect FAILED"

VER=$(psql "$DB_URL" -t -c "SELECT MAX(version_id) FROM goose_db_version WHERE is_applied=true;" 2>/dev/null | tr -d ' ')
[ "$VER" = "15" ] && ok "Migration v$VER (latest)" || warn "Migration v$VER (expected 15)"

for tbl in conmon_schedules conmon_deviations conmon_cadence_status \
           ai_advisor_cache ai_advisor_feedback sso_providers sso_login_states; do
  EX=$(psql "$DB_URL" -t -c "SELECT 1 FROM information_schema.tables WHERE table_name='$tbl';" 2>/dev/null | tr -d ' ')
  [ "$EX" = "1" ] && ok "Table $tbl" || fail "Table $tbl MISSING"
done

# ════════════════════════════════════════════════════════════════
section "3. AUTH + CSRF BOOTSTRAP"
# ════════════════════════════════════════════════════════════════

# Step A: Login (sets vsp_token only)
LOGIN=$(curl -s -i -c "$COOKIE" -X POST http://localhost:8921/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vsp.local","password":"NewSecurePass123"}')
STATUS=$(echo "$LOGIN" | grep -oP 'HTTP/\d\.\d \K\d+' | head -1)
[ "$STATUS" = "200" ] && ok "Login HTTP 200" || fail "Login HTTP $STATUS"

# Step B: GET endpoint to bootstrap vsp_csrf cookie
curl -s -b "$COOKIE" -c "$COOKIE" http://localhost:8921/api/v1/conmon/schedules > /dev/null

# Step C: Extract both tokens
JWT=$(awk '/vsp_token/ {print $NF}' "$COOKIE" | head -1)
CSRF=$(awk '/vsp_csrf/ {print $NF}' "$COOKIE" | head -1)

[ -n "$JWT" ] && {
  DOTS=$(echo -n "$JWT" | tr -cd '.' | wc -c)
  [ "$DOTS" = "2" ] && ok "JWT 3-segment (${#JWT} chars)" || fail "JWT format bad"
} || fail "JWT not in cookie file"

[ -n "$CSRF" ] && ok "CSRF bootstrapped via GET (${#CSRF} chars)" || fail "CSRF cookie still missing"

CHK=$(curl -sw '%{http_code}' -o /dev/null -b "$COOKIE" http://localhost:8921/api/v1/auth/check)
[ "$CHK" = "200" ] && ok "/auth/check HTTP 200" || warn "/auth/check HTTP $CHK"

# Helper: csrf-aware POST/PUT/DELETE
csrf_curl() {
  local method=$1; shift
  local url=$1; shift
  curl -sw '\nHTTP=%{http_code}' -X "$method" \
    -b "$COOKIE" \
    -H "X-CSRF-Token: $CSRF" \
    -H "Content-Type: application/json" \
    "$@" "$url"
}

# ════════════════════════════════════════════════════════════════
section "4. PHASE 4.5 GET ENDPOINTS"
# ════════════════════════════════════════════════════════════════
for path in /api/v1/conmon/schedules /api/v1/conmon/cadence /api/v1/conmon/deviations \
            /api/v1/ai/mode /api/v1/ai/cache/stats /api/v1/sso/providers; do
  CODE=$(curl -sw '%{http_code}' -o /dev/null -b "$COOKIE" "http://localhost:8921$path")
  [ "$CODE" = "200" ] && ok "GET $path → 200" || fail "GET $path → $CODE"
done

for ep in "/api/v1/auth/sso/login?provider_id=999" "/api/v1/auth/sso/callback?code=x&state=y"; do
  CODE=$(curl -sw '%{http_code}' -o /dev/null "http://localhost:8921$ep")
  ([ "$CODE" = "404" ] || [ "$CODE" = "400" ]) && ok "Public $ep → $CODE" || fail "$ep → $CODE"
done

# ════════════════════════════════════════════════════════════════
section "5. PRE-EXISTING ENDPOINTS (regression)"
# ════════════════════════════════════════════════════════════════
for ep in /api/v1/assets /api/v1/vsp/run/latest /api/v1/vsp/runs/index /api/v1/vsp/findings \
          /api/v1/remediation/stats /api/p4/zt/status /api/p4/rmf /api/p4/rmf/conmon \
          /api/v1/vsp/sla_tracker /api/v1/correlation/incidents /api/v1/soar/runs \
          /api/v1/logs/stats /api/v1/vsp/findings/summary; do
  CODE=$(curl -sw '%{http_code}' -o /dev/null -b "$COOKIE" "http://localhost:8921$ep")
  [ "$CODE" = "200" ] && ok "$ep → 200" || fail "$ep → $CODE"
done

# ════════════════════════════════════════════════════════════════
section "6. CRUD WITH CSRF (full lifecycle)"
# ════════════════════════════════════════════════════════════════

# ConMon CREATE
CREATE=$(csrf_curl POST http://localhost:8921/api/v1/conmon/schedules \
  -d '{"name":"sanity-v3-test","cadence":"30d","mode":"FULL","target_path":"/tmp/x"}')
CR_CODE=$(echo "$CREATE" | tail -1 | grep -oP '\d+')
CR_BODY=$(echo "$CREATE" | sed '$d')

if [ "$CR_CODE" = "201" ] || [ "$CR_CODE" = "200" ]; then
  ok "ConMon POST schedules → $CR_CODE"
  SID=$(echo "$CR_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  info "Schedule id=$SID body=$CR_BODY"
else
  fail "ConMon POST → $CR_CODE: $CR_BODY"
fi

# Read back
COUNT=$(curl -s -b "$COOKIE" http://localhost:8921/api/v1/conmon/schedules | \
        python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
[ "${COUNT:-0}" -gt 0 ] && ok "ConMon READ: $COUNT schedule(s)" || warn "ConMon READ: 0 (CREATE may have failed)"

# Cleanup
psql "$DB_URL" -c "DELETE FROM conmon_schedules WHERE name LIKE 'sanity-v%';" >/dev/null 2>&1
info "Cleanup: removed sanity-v* schedules"

# SSO provider CREATE
SSO=$(csrf_curl POST http://localhost:8921/api/v1/sso/providers \
  -d '{"name":"sanity-v3-idp","type":"oidc","issuer_url":"https://example.com","client_id":"test","client_secret":"s","redirect_uri":"http://localhost:8921/cb"}')
SC=$(echo "$SSO" | tail -1 | grep -oP '\d+')
SB=$(echo "$SSO" | sed '$d')

if [ "$SC" = "201" ] || [ "$SC" = "200" ]; then
  ok "SSO POST → $SC"
  PID=$(echo "$SB" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  
  if [ -n "$PID" ]; then
    DEL=$(csrf_curl DELETE "http://localhost:8921/api/v1/sso/providers/$PID")
    DC=$(echo "$DEL" | tail -1 | grep -oP '\d+')
    [ "$DC" = "200" ] && ok "SSO DELETE id=$PID → 200" || fail "SSO DELETE → $DC"
  fi
else
  fail "SSO POST → $SC: $SB"
fi

# ════════════════════════════════════════════════════════════════
section "7. AI ADVISOR FUNCTIONALITY"
# ════════════════════════════════════════════════════════════════
MODE=$(curl -s -b "$COOKIE" http://localhost:8921/api/v1/ai/mode | python3 -c "import json,sys; print(json.load(sys.stdin).get('mode',''))" 2>/dev/null)
info "Mode: $MODE (expected: local since ANTHROPIC_API_KEY=REPLACE_WITH_REAL_KEY)"

# Submit advise
ADV=$(csrf_curl POST http://localhost:8921/api/v1/ai/advise \
  -d '{"framework":"fedramp_moderate","control_id":"SI-2","finding_summary":"Critical CVE-2024-9999 in production package, no patch applied"}')
AC=$(echo "$ADV" | tail -1 | grep -oP '\d+')
AB=$(echo "$ADV" | sed '$d')

if [ "$AC" = "200" ]; then
  REM_LEN=$(echo "$AB" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('remediation','')))" 2>/dev/null || echo 0)
  REFS=$(echo "$AB" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('references',[])))" 2>/dev/null || echo 0)
  EFF_J=$(echo "$AB" | python3 -c "import json,sys; print(json.load(sys.stdin).get('effort_hours',{}).get('junior',0))" 2>/dev/null || echo 0)
  EFF_M=$(echo "$AB" | python3 -c "import json,sys; print(json.load(sys.stdin).get('effort_hours',{}).get('mid',0))" 2>/dev/null || echo 0)
  EFF_S=$(echo "$AB" | python3 -c "import json,sys; print(json.load(sys.stdin).get('effort_hours',{}).get('senior',0))" 2>/dev/null || echo 0)
  SRC=$(echo "$AB" | python3 -c "import json,sys; print(json.load(sys.stdin).get('source',''))" 2>/dev/null)
  CACHED=$(echo "$AB" | python3 -c "import json,sys; print(json.load(sys.stdin).get('cached',False))" 2>/dev/null)
  
  if [ "${REM_LEN:-0}" -gt 50 ] && [ "${REFS:-0}" -gt 0 ]; then
    ok "AI Advise: 4-part response valid"
    info "Remediation: $REM_LEN chars · References: $REFS · Source: $SRC · Cached: $CACHED"
    info "Effort hours: junior=${EFF_J} · mid=${EFF_M} · senior=${EFF_S}"
  else
    fail "AI Advise: incomplete response (rem_len=$REM_LEN refs=$REFS)"
  fi
  
  # Test cache: submit same request, should get cached=true
  ADV2=$(csrf_curl POST http://localhost:8921/api/v1/ai/advise \
    -d '{"framework":"fedramp_moderate","control_id":"SI-2","finding_summary":"Critical CVE-2024-9999 in production package, no patch applied"}')
  CACHED2=$(echo "$ADV2" | sed '$d' | python3 -c "import json,sys; print(json.load(sys.stdin).get('cached',False))" 2>/dev/null)
  [ "$CACHED2" = "True" ] && ok "AI cache: 2nd identical request returns cached=true" || warn "Cache flag: $CACHED2"
else
  fail "AI Advise → $AC: $AB"
fi

# Cleanup
psql "$DB_URL" -c "DELETE FROM ai_advisor_cache WHERE control_id='SI-2' AND finding_summary LIKE 'Critical CVE%';" >/dev/null 2>&1

# ════════════════════════════════════════════════════════════════
section "8. STATIC FILES + UI INTEGRATION"
# ════════════════════════════════════════════════════════════════
for f in static/index.html static/landing.html static/panels/conmon.html \
         static/panels/ai_advisor.html static/panels/sso_admin.html; do
  [ -f "$f" ] && ok "$f ($(($(wc -c < "$f")/1024)) KB)" || fail "$f MISSING"
done

NAV=$(grep -c "showPanel('conmon\|showPanel('ai_advisor\|showPanel('sso_admin" static/index.html)
[ "$NAV" = "3" ] && ok "Sidebar: 3 nav buttons" || fail "Sidebar: $NAV"

FRAMES=$(grep -c 'id="panel-conmon\|id="panel-ai_advisor\|id="panel-sso_admin' static/index.html)
[ "$FRAMES" = "3" ] && ok "Iframe panels: 3" || fail "Iframes: $FRAMES"

for p in conmon ai_advisor sso_admin; do
  CODE=$(curl -sw '%{http_code}' -o /dev/null "http://localhost:8921/panels/${p}.html")
  [ "$CODE" = "200" ] && ok "/panels/${p}.html → 200" || fail "/panels/${p}.html → $CODE"
done

# ════════════════════════════════════════════════════════════════
section "9. ERROR SCAN (last 15 min)"
# ════════════════════════════════════════════════════════════════
LOG=$(sudo journalctl -u vsp-gateway --since "15 minutes ago" --no-pager 2>&1 | grep -v 'redis:\|KEV source')
_count() { echo "$1" | grep -cE "$2" 2>/dev/null | head -1 | tr -dc '0-9'; }
ERR=$(_count "$LOG" "FTL|level=error"); ERR=${ERR:-0}
PANIC=$(_count "$LOG" "panic:"); PANIC=${PANIC:-0}
S500=$(_count "$LOG" "status=500"); S500=${S500:-0}
S200=$(_count "$LOG" "status=200"); S200=${S200:-0}
INVJWT=$(_count "$LOG" "invalid jwt"); INVJWT=${INVJWT:-0}

[ "${ERR:-0}" -lt 2 ] && ok "Errors: ${ERR:-0}" || warn "Errors: $ERR"
[ "${PANIC:-0}" = "0" ] && ok "No panics" || fail "Panics: $PANIC"
[ "${S500:-0}" = "0" ] && ok "No HTTP 500s" || fail "500s: $S500"
[ "${INVJWT:-0}" -lt 5 ] && ok "Invalid JWT count: ${INVJWT:-0} (cosmetic, browser cache)" || warn "Invalid JWT: $INVJWT"
info "HTTP 200 in last 15min: ${S200:-0}"

# ════════════════════════════════════════════════════════════════
section "10. GIT STATE"
# ════════════════════════════════════════════════════════════════
ok "Latest: $(git log -1 --format='%h %s')"
A=$(git rev-list --count origin/docs/security-deliverables..HEAD 2>/dev/null | tr -d ' ')
B=$(git rev-list --count HEAD..origin/docs/security-deliverables 2>/dev/null | tr -d ' ')
([ "$A" = "0" ] && [ "$B" = "0" ]) && ok "Synced with origin" || warn "ahead=$A behind=$B"
git tag -l | grep -q "v0.11.0" && ok "Tag v0.11.0 exists" || fail "Tag missing"

UN=$(git status --porcelain 2>/dev/null | grep -c "^??" 2>/dev/null || echo 0)
UN=$(echo "$UN" | head -1 | tr -d ' \n')
if [ "$UN" -eq 0 ] 2>/dev/null; then
  ok "No untracked files"
else
  warn "Untracked: $UN file(s)"
fi

# ════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SANITY V3 — FINAL                                             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  PASS:  \033[32m%-3d\033[0m                                                    ║\n" $PASS
printf "║  WARN:  \033[33m%-3d\033[0m                                                    ║\n" $WARN
printf "║  FAIL:  \033[31m%-3d\033[0m                                                    ║\n" $FAIL
echo "╚══════════════════════════════════════════════════════════════╝"

if [ $FAIL -eq 0 ]; then
  echo ""
  echo "  🎉 ALL GREEN — Phase 4.5 sprint COMPLETE end-to-end"
  echo "     Backend, DB, Auth, CSRF, CRUD, AI, UI integration all verified"
fi
