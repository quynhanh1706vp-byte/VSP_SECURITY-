# PERF-04 — Disable nginx Edge Rate Limit

## Why this exists

PERF-01, PERF-02, and PERF-03 patched the Go gateway's rate limiting:

| Patch    | Change                                            | Effect on 429 |
|----------|---------------------------------------------------|---------------|
| PERF-01  | Bump global IP limit 600 → 3000 r/min             | None observed |
| PERF-02  | Disable per-user RL on `/api/v1`                  | None observed |
| PERF-03  | Disable global IP rate limiter in `main.go`       | None observed |

After PERF-03 the gateway was clean — `grep "rate.NewLimiter"` showed only
commented-out lines plus dead-code keep-import. Yet the browser console
still flooded with 429s on every endpoint.

## Root cause

`curl -i https://vsp.local/api/v1/events` revealed:

```
HTTP/2 401
server: nginx
```

The 429s never reached the Go gateway. nginx was rejecting them at the
edge. Body of the 429 response was an HTML page (default nginx error
page), which is the giveaway — Go gateway returns plain text or JSON.

`/etc/nginx/sites-available/vsp` had:

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m    rate=30r/m;
limit_req_zone $binary_remote_addr zone=auth_limit:10m   rate=5r/m;
limit_req_zone $binary_remote_addr zone=scan_limit:10m   rate=10r/m;
limit_req_zone $binary_remote_addr zone=global_limit:10m rate=100r/m;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

limit_conn conn_limit 20;
limit_req  zone=global_limit burst=50 nodelay;       # 100 r/min global
# ... per-route limits on /auth, /scan, /api
```

100 requests/minute is exhausted on a single dashboard load (KPI cards +
DoD widgets + SSE polling fire ~25-30 requests; refresh 4× and you're
out). Burst of 50 is consumed almost instantly, then every subsequent
request returns 429 until the leaky bucket drains.

## What this patch does

Comments out every `limit_req`, `limit_conn`, `limit_req_zone`,
`limit_conn_zone`, and `limit_req_status` directive in
`/etc/nginx/sites-available/vsp`. Adds a `# PERF-04 PATCH APPLIED` marker
at the top of the file.

After this patch, all rate limiting decisions live in the Go gateway,
which is consistent with PERF-01/02/03's intent.

## When to roll this back

This is appropriate for **dev/staging** (which matches the current
`SERVER_ENV=development` in `00-canonical.conf`).

For **production**, rate limiting at the edge is good defense in depth.
Roll back and instead **raise the limits** to something realistic:

```nginx
limit_req_zone $binary_remote_addr zone=global_limit:10m rate=6000r/m;
limit_req_zone $binary_remote_addr zone=api_limit:10m    rate=3000r/m;
limit_req  zone=global_limit burst=300 nodelay;
```

(Run separately — this patch does not do that.)

## Files

- `apply.sh` — apply patch + nginx -t + auto-rollback on syntax error
- `rollback.sh` — restore from `.bak.perf04`
- `README.md` — this file

## Apply

```bash
bash patches/perf/04-disable-nginx-ratelimit/apply.sh
sudo systemctl reload nginx
```

## Verify

```bash
# 1. nginx no longer returns 429 (should be 401 without token)
curl -k -i https://vsp.local/api/v1/events | head -3
# Expect: HTTP/2 401

# 2. Browser hard reload — console clean of 429
```

## Rollback

```bash
bash patches/perf/04-disable-nginx-ratelimit/rollback.sh
sudo systemctl reload nginx
```
