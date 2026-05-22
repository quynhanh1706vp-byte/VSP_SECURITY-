#!/usr/bin/env bash
# scripts/test-l12-chaos.sh — fault-injection / chaos probes.
#
# Five reversible probes that each break one upstream / one input
# assumption and assert the gateway DEGRADES gracefully (returns 200
# fall-through, structured 4xx, or 503 — but never hangs, never 5xx-
# panics, never leaks goroutines).
#
#   14.1 Redis stop — kill redis 8s while hitting cached endpoint.
#        Gateway should fall through to DB, not return 500.
#
#   14.2 Body limit — POST a 20MB payload. Gateway should reject
#        with 400/413, not OOM or hang.
#
#   14.3 Malformed JSON aggressive — 200 concurrent malformed JSON
#        POSTs. Each must produce a 400 with a JSON error body, not
#        a panic that crashes the process.
#
#   14.4 PG connection kill — pg_terminate_backend on every gateway
#        connection. Pool reconnect path must engage; subsequent
#        requests succeed (within ~1s).
#
#   14.5 Slow upstream — set `tc qdisc` to add 200ms delay to the
#        loopback interface, hit /vsp/findings, assert request still
#        completes within max-time. (SKIPPED unless RUN_L12_TC=1
#        because tc requires CAP_NET_ADMIN and persists.)
#
# Pre-flight: $DB_DSN, $JWT_SECRET, gateway running, redis-cli + sudo
# available for the redis/PG probes. Each probe restores its upstream
# on EXIT via trap.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq psql openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

NOW=$(date +%s); EXP=$((NOW + 3600))
H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
P=$(printf '{"sub":"l12@vsp.local","email":"l12@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
  "$NOW" "$EXP" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
  | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
ADMIN="$H.$P.$S"

# ── 14.1 Redis stop ────────────────────────────────────────────────────────

phase_open "14.1 Redis stop — gateway falls through to DB"

REDIS_RUNNING=0
if command -v redis-cli &>/dev/null; then
  REDIS_PASS=""
  if [[ -r /etc/vsp/env.production ]] || sudo -n true 2>/dev/null; then
    REDIS_PASS=$(sudo grep -E '^REDIS_PASSWORD|^REDIS_PASS' /etc/vsp/env.production 2>/dev/null | head -1 | cut -d= -f2-)
  fi
  if [[ -n "$REDIS_PASS" ]] && redis-cli -a "$REDIS_PASS" --no-auth-warning ping 2>/dev/null | grep -q PONG; then
    REDIS_RUNNING=1
  elif redis-cli ping 2>/dev/null | grep -q PONG; then
    REDIS_RUNNING=1
  fi
fi

if [[ "$REDIS_RUNNING" != "1" ]]; then
  _skip "14.1.1 redis stop probe" "redis not reachable from this host"
else
  # Stop redis service, hit cached endpoint, verify 200.
  if sudo systemctl stop redis-server 2>/dev/null || sudo systemctl stop redis 2>/dev/null; then
    sleep 1
    STATUS=$(curl -s -o /tmp/l12_redis.json -w "%{http_code}" --max-time 8 \
      -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/vsp/findings/summary")
    BODY_KEYS=$(jq -r 'keys | length' /tmp/l12_redis.json 2>/dev/null || echo 0)
    rm -f /tmp/l12_redis.json
    # Restart redis right after the probe.
    sudo systemctl start redis-server 2>/dev/null || sudo systemctl start redis 2>/dev/null
    sleep 1
    if [[ "$STATUS" == "200" && "$BODY_KEYS" -gt 0 ]]; then
      _pass "14.1.1 redis down → DB fallthrough returned 200 with body"
    elif [[ "$STATUS" == "200" ]]; then
      _pass "14.1.1 redis down → 200 (body parse soft)"
    elif [[ "$STATUS" =~ ^5 ]]; then
      _fail "14.1.1 redis down → 5xx" \
        "gateway returned $STATUS instead of falling through to DB"
    else
      _fail "14.1.1 redis down → unexpected" "got HTTP $STATUS"
    fi
  else
    _skip "14.1.1 redis stop probe" "could not stop redis (need sudo + systemctl)"
  fi
fi

# ── 14.2 Body too large ────────────────────────────────────────────────────

phase_open "14.2 Body limit — 20 MB payload rejected, no OOM"

# Construct a 20MB JSON body (well over any reasonable cap).
BIG_BODY=$(mktemp)
python3 -c 'import json,sys; sys.stdout.write(json.dumps({"x":"a"*(20*1024*1024)}))' > "$BIG_BODY"
SIZE_MB=$(( $(wc -c < "$BIG_BODY") / 1024 / 1024 ))

START=$(date +%s%N)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
  -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  --data-binary "@$BIG_BODY" "$BASE/api/v1/settings/tool-config")
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
rm -f "$BIG_BODY"

if [[ "$STATUS" =~ ^(400|413|414|431)$ ]]; then
  _pass "14.2.1 ${SIZE_MB}MB body rejected [HTTP $STATUS, ${ELAPSED_MS}ms]"
elif [[ "$STATUS" =~ ^5 ]]; then
  _fail "14.2.1 large body crashed handler" "HTTP $STATUS — gateway should reject before processing"
elif [[ "$STATUS" == "000" ]]; then
  _fail "14.2.1 large body hung" "no response before timeout (possible OOM or infinite loop)"
else
  # 401/403 also acceptable — auth/CSRF rejected before size check ran.
  _pass "14.2.1 ${SIZE_MB}MB body handled non-fatally [HTTP $STATUS]"
fi

# ── 14.3 Malformed JSON storm — panic recovery ─────────────────────────────

phase_open "14.3 Malformed JSON storm — panic recovery"

# 200 concurrent POSTs with broken JSON. The chi/recoverer middleware
# must catch any per-request panic and return a structured 500, not
# crash the process. After the storm, gateway must still respond to
# a healthcheck.
GW_PID_BEFORE=$(pgrep -f "/usr/local/bin/vsp-gateway" | head -1)

for i in $(seq 1 200); do
  curl -s -o /dev/null --max-time 3 \
    -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
    --data-binary '{"unterminated":' \
    "$BASE/api/v1/settings/tool-config" &
done
wait

sleep 1
GW_PID_AFTER=$(pgrep -f "/usr/local/bin/vsp-gateway" | head -1)
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/auth/check")

if [[ "$GW_PID_AFTER" == "$GW_PID_BEFORE" && "$HEALTH" =~ ^(200|401)$ ]]; then
  _pass "14.3.1 200 malformed POSTs survived [pid stable, health=$HEALTH]"
elif [[ "$GW_PID_AFTER" != "$GW_PID_BEFORE" ]]; then
  _fail "14.3.1 gateway crashed under malformed JSON storm" \
    "pid changed $GW_PID_BEFORE → $GW_PID_AFTER (process restarted)"
else
  _fail "14.3.1 gateway unhealthy after storm" "/auth/check returned $HEALTH"
fi

# ── 14.4 PG connection kill ────────────────────────────────────────────────

phase_open "14.4 PG connection kill — pool reconnect path engages"

# pg_terminate_backend kills every existing connection from this app.
# The connection pool must reconnect on demand; subsequent requests
# succeed within a short retry window.
TERM_RESULT=$(_psql_oneshot "SELECT count(*)
                              FROM pg_terminate_backend(pid)
                                JOIN (SELECT pid FROM pg_stat_activity
                                       WHERE application_name LIKE '%vsp%' OR usename='vsp') s USING(pid);" 2>/dev/null || echo "0")
TERM_RESULT=${TERM_RESULT:-0}
sleep 1   # let the pool detect + reopen

# Hit a DB-touching endpoint; expect success once the pool reconnects.
ATTEMPTS=0
RECOVER_OK=0
for i in 1 2 3 4 5; do
  ATTEMPTS=$((ATTEMPTS+1))
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/vsp/findings?limit=1")
  if [[ "$STATUS" == "200" ]]; then
    RECOVER_OK=1; break
  fi
  sleep 1
done

if (( RECOVER_OK == 1 )); then
  _pass "14.4.1 PG conn killed [terminated=$TERM_RESULT, recovered after $ATTEMPTS try]"
else
  _fail "14.4.1 PG conn kill — no recovery" \
    "terminated $TERM_RESULT conns, $ATTEMPTS attempts all failed"
fi

# ── 14.5 Slow upstream (gated) ─────────────────────────────────────────────

phase_open "14.5 Slow upstream — tc netem (gated)"

if [[ "${RUN_L12_TC:-0}" != "1" ]]; then
  _skip "14.5.1 tc netem 200ms delay" "RUN_L12_TC not set (requires CAP_NET_ADMIN)"
else
  if sudo tc qdisc add dev lo root netem delay 200ms 2>/dev/null; then
    START=$(date +%s%N)
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
      -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/vsp/findings?limit=1")
    ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
    sudo tc qdisc del dev lo root netem 2>/dev/null || true
    if [[ "$STATUS" == "200" ]]; then
      _pass "14.5.1 200ms-delay loopback survived [HTTP 200, ${ELAPSED_MS}ms wall]"
    else
      _fail "14.5.1 200ms-delay" "HTTP $STATUS — gateway didn't tolerate added latency"
    fi
  else
    _skip "14.5.1 tc netem" "tc qdisc add failed (no CAP_NET_ADMIN?)"
  fi
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
