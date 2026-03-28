# VSP Platform — Changelog

## v0.10.0 — 2026-03-28

### Features
- Executive PDF/HTML report with risk score, tool breakdown, recommendations
- Dark/light mode toggle with localStorage persistence
- Notification center — real-time feed from audit log, mark read, badge count
- Scheduled scan UI — toggle enable/disable, create, run-now
- Multi-tenant switcher — API endpoint + sidebar UI
- WebSocket upgrade handler with SSE fallback (`/api/v1/ws`)
- Prometheus custom metrics: scans, findings, gate decisions, SSE clients, webhooks

### Security
- CORS wildcard → env-driven whitelist (`server.allowed_origins`)
- JWT secret guard — fatal at startup if default secret used in production
- StrictLimiter(10/min) on `/api/v1/auth/login`
- Rate limiter: realIP extraction (X-Forwarded-For), Retry-After headers

### Fixes
- Version string corrected to v0.9.0/v0.10.0 throughout
- Rate limiter memory leak fixed (cleanup goroutine)
- `.gitignore` — removed binaries, CodeQL DB, backup files from tracking

## v0.9.0 — 2026-03-28

### Summary
- 16 fixes · 12 features from v0.5
- Auth loop, compliance gauges, scan log viewer
- Bulk remediation, user management
- 213KB bundle · 0 JS errors · 0 accessibility warnings
- Production-ready ✓
