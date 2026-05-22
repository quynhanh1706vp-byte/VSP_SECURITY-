# PERF-03 — Disable Global Per-IP Rate Limiter (THE REAL FIX)

## The story

PERF-01 bumped per-user limit 600 → 3000. Didn't help.
PERF-02 disabled per-user limiter on `/api/v1/*`. Didn't help.

Why? Because there are **TWO rate limiters in main.go**, and the one I
addressed was the second line of defense, not the first.

## Diagnosis

```bash
$ grep -nE "RateLimit" cmd/gateway/main.go
444:    rl := vspMW.NewRateLimiter(600, time.Minute)        ← THE REAL ONE
465:    r.Use(rl.Middleware)                                ← applied to ALL routes
829:    // r.Use(vspMW.NewUserRateLimiter(3000, ...))      ← already disabled (PERF-02)
```

Line 465 applies `rl.Middleware` to the **root router**, before any auth
group, with no path filter. Combined with `chimw.RealIP` (line 451)
which reads `X-Forwarded-For` from nginx, every request from one
browser hits the same per-IP bucket.

Browser dashboard boot: ~70 requests in 1 second.
Bucket: 600 requests per minute = 10 per second sustained.
Result: bucket empty in ~6 seconds, 429 storm for the rest of the minute.

The per-USER limiter (line 829) only kicks in inside the `/api/v1/*`
group, after the IP limiter has already rejected most requests at the
root.

## Fix

Comment out both line 444 (init) and line 465 (apply). The dummy `_ = `
keeps the package import valid in case nothing else uses it.

```go
// Before
rl := vspMW.NewRateLimiter(600, time.Minute)
...
r.Use(rl.Middleware)

// After
// VSP_PATCH_PERF_03 — global per-IP rate limiter disabled. <reason>
_ = vspMW.NewRateLimiter // keep package imported
// rl := vspMW.NewRateLimiter(600, time.Minute)
...
// VSP_PATCH_PERF_03 — disabled: r.Use(rl.Middleware)
```

## Defense in depth (what remains)

- **JWT authMw** — applied per-route group on `/api/v1/*`, agents, etc.
- **CSRFProtect** — line 449, double-submit cookie pattern
- **4MB body limit** — line 459, blocks DoS via large payloads
- **60s timeout** — line 458, blocks slowloris
- **chimw.Recoverer** — line 457, recovers from panics
- **tenant isolation** — handlers scope queries by JWT tenant_id
- **nginx layer** — TLS, can add `limit_req_zone` if needed (recommended
  approach for prod-grade rate limiting)

## Apply

```bash
cd /home/test/Data/GOLANG_VSP
bash patches/perf/03-disable-global-ratelimit/apply.sh
bash scripts/build-gateway.sh
sudo systemctl stop vsp-gateway && sleep 2
sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl start vsp-gateway
```

## Verify

Hard-reload browser (Ctrl+Shift+R). Console should be **completely
free of 429 errors** for the first time. KPI dashboard populates
immediately. F1 bulk action returns 200 OK.

## Rollback

```bash
bash patches/perf/03-disable-global-ratelimit/rollback.sh
bash scripts/build-gateway.sh
sudo systemctl stop vsp-gateway && sleep 2
sudo install -m 755 bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl start vsp-gateway
```

## Future: prod-grade rate limiting

If/when this app is ever exposed to untrusted networks, add nginx-level
rate limiting in `/etc/nginx/sites-available/vsp`:

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
location /api/ {
    limit_req zone=api burst=200 nodelay;
    proxy_pass http://vsp_backend;
    ...
}
```

That gives bursting capacity (200 req in burst), sustained 100r/s, and
keeps app-layer code free of demo-breaking 429s.

## Idempotent

Re-running `apply.sh` is safe — checks for `VSP_PATCH_PERF_03` marker.
