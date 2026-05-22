# PERF-02 — Disable Per-User Rate Limit on /api/v1/* Group

## Problem

PERF-01 bumped the per-user rate limit from 600 → 3000 req/min, but
the 429 storm persisted. Diagnostic showed the actual burst is **~70
requests in <1 second** during dashboard boot:

- Master shell: `updateTicker` (6 endpoints), `loadDashKPIs`, posture
  poller (3), DoD widgets (4), SIEM KPIs (3) = ~16
- 5 active iframe panels: each fires 3-8 GETs on init = ~30
- vsp_pro_100: 9 module init checks = ~9
- SSE `/api/v1/events`: 1
- Re-init second pass when `_masterShow` triggers: doubles a chunk

Total observed: ~70 reqs in the first second. The token-bucket limiter
has no burst capacity beyond `limit/60` per second, so even with a
3000/min limit (= 50 req/sec sustained), the first-second burst saturates
the bucket and subsequent requests get 429 for the rest of the minute.

Bumping further (10000+) would mask the symptom but not fix the design.

## Fix

Disable the per-user rate limiter on the authenticated `/api/v1/*` group
entirely. Defense in depth remains intact:

- **Authentication**: JWT `authMw` blocks unauthenticated access
- **CSRF**: `CSRFProtect` middleware on all POST/PUT/DELETE
- **Tenant isolation**: handlers scope queries to `tenant_id` from JWT
- **Origin**: app served same-origin over HTTPS, no CORS wildcards

The login endpoint `/api/v1/auth/login` retains its own brute-force
protection (registered separately, not affected by this patch).

## Why this is the right fix

Rate limiting is appropriate for **public-facing APIs** where you don't
control the client. For an authenticated **internal dashboard**, where:

1. The client is your own frontend
2. The user is already authenticated (1 admin = 1 bucket = useless)
3. The "burst" is a deterministic load pattern, not an attack
4. Real DDoS protection belongs at the reverse proxy layer (nginx/etc)

…rate limiting at the app layer creates demo-breaking 429s without
adding meaningful security.

If F2-F8 add even more polling, this won't regress. If ever needed,
re-enable by uncommenting the line — the comment block in `main.go`
documents how.

## Files Changed

- `cmd/gateway/main.go` — comment out `r.Use(vspMW.NewUserRateLimiter(...))`
- `.gitignore` — whitelist `patches/perf/` (was blocked by `patches/*` rule)

## Apply

```bash
cd /home/test/Data/GOLANG_VSP
bash patches/perf/02-disable-rate-limit/apply.sh
bash scripts/build-gateway.sh
sudo systemctl stop vsp-gateway && sleep 2
sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl start vsp-gateway
```

## Verify

In browser, hard-reload (Ctrl+Shift+R), then Console should be **completely
free of 429 errors**. KPI cards should populate (Total Runs > 0, etc.).

Then test F1 bulk action:
1. Vuln Mgmt tab
2. Tick CVE-2025-32434
3. Click "✓ Resolve"
4. Expect green toast "Resolved 1 CVE ✓" + status 200 in DevTools

## Rollback

```bash
bash patches/perf/02-disable-rate-limit/rollback.sh
bash scripts/build-gateway.sh
sudo systemctl stop vsp-gateway && sleep 2
sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl start vsp-gateway
```

## Idempotent

Re-running `apply.sh` is safe — checks for `VSP_PATCH_PERF_02` marker.
