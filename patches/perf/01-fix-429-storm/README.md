# PERF-01 — Fix 429 Storm

Bumps the per-user rate limit on the authenticated `/api/v1` group from
600 req/min to 3000 req/min.

## Why

Dashboard boot fan-out: when the user lands on `/`, the following load
in parallel:

- `index.html` master script: `updateTicker`, `loadDashKPIs`, `vsp_pro_100`,
  `loadSIEMKPIs`, `vsp_upgrade_v100` posture poller
- 5 active iframe panels: supply_chain, attestation, oscal, p4_compliance,
  sw_inventory — each fires 3-5 GETs on init
- SSE `/api/v1/events`
- Posture poller every 30s (after smart polling kicked in)

Total observed: **~50 requests in 2-3 seconds**. With limit at 600/min
(= 10 req/sec sustained), the bucket empties immediately and subsequent
requests get 429 for the rest of the minute. KPI cards stay at 0/0/0.

## Fix

Single-line bump:

```go
// Before
r.Use(vspMW.NewUserRateLimiter(600, time.Minute)) // per-user: 600 req/min

// After
r.Use(vspMW.NewUserRateLimiter(3000, time.Minute)) // per-user: 3000 req/min
```

3000/min = 50 req/sec sustained, comfortably absorbs the 50-req boot
burst with margin. Per-user (not per-IP), so multi-user scenarios still
get fair shares.

## Why not 10000+?

3000 is the sweet spot: enough headroom for current dashboard, not so
loose that a buggy poll loop could DoS the DB. If F2-F8 add more panels
and we hit 429 again, revisit then — and consider in-memory caching for
hot read endpoints rather than just bumping the limit further.

## Apply

```bash
cd /home/test/Data/GOLANG_VSP
bash patches/perf/01-fix-429-storm/apply.sh
bash scripts/build-gateway.sh
sudo systemctl stop vsp-gateway && sleep 2
sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl start vsp-gateway
```

## Verify

In browser, hard-reload (Ctrl+Shift+R), then watch DevTools Console.
Should see ZERO 429 errors during dashboard boot. KPI cards (Total Runs,
Critical, etc.) should populate with real numbers.

To verify F1 bulk action works (was blocked by 429):
1. Vuln Mgmt tab
2. Tick a CVE
3. Click "✓ Resolve"
4. Expect green toast "Resolved 1 CVE ✓"

## Rollback

```bash
bash patches/perf/01-fix-429-storm/rollback.sh
bash scripts/build-gateway.sh
sudo systemctl stop vsp-gateway && sleep 2
sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl start vsp-gateway
```

## Idempotent

Re-running `apply.sh` is safe — checks for `VSP_PATCH_PERF_01` marker.
