# Cookie Migration Design — HttpOnly Session Cookie

**Status:** Design ready for Sprint 5 implementation
**Author:** Sprint 4 team
**Date:** 2026-04-21
**Decision record:** supersedes assumption in roadmap that cookie infra needs to be built

## TL;DR

Backend has 100 percent of the infrastructure already. Migration is not a migration, it is an audit + flag flip + frontend cleanup. Sprint 5 effort revised from 5-7 days to 1-2 days.

## Current state audit

### Backend ready to ship

All of the following already exist in main as of commit 213dcce:

- Login sets HttpOnly cookie at internal/api/handler/auth.go:170
- Logout clears cookie at internal/api/handler/auth.go:201
- Refresh endpoint at internal/api/handler/auth.go:213, wired at main.go:468
- Auth check endpoint GET /api/v1/auth/check at internal/api/handler/auth.go:258
- Cookie session middleware at internal/api/middleware/cookie_session.go
- CSRF double-submit at internal/api/middleware/csrf.go, wired at main.go:219 via r.Use(vspMW.CSRFProtect)
- JWT lifecycle at internal/auth/middleware.go:176, HS256 sign with blacklist check

Current login flow already returns both cookie and token-in-body (dual mode). This is Scenario X from Sprint 4 research: dual-mode works, frontend just needs to stop reading body.token.

### Frontend 140 localStorage reads

Frontend currently ignores the cookie and reads localStorage:
- 98 getItem vsp_token
- 36 setItem vsp_token
- 10 removeItem vsp_token

Source: static/js/vsp_iframe_bootstrap.js writes, 25 panels + index.html read.

### CSRF currently bypassed for Bearer auth

csrf.go:55-60 skips CSRF when Authorization header starts with Bearer. Once frontend stops sending Bearer header, CSRF double-submit will kick in automatically.

## Target state

### Authentication flow after migration

1. POST /api/v1/auth/login with credentials
2. Server sets vsp_token HttpOnly cookie (already does this) and responds 200
3. Every subsequent request: browser auto-sends cookie, no JS needed
4. CSRF: vsp_csrf cookie issued on GET, frontend reads it, echoes in X-CSRF-Token header on state-changing requests
5. Cross-panel iframe: session cookie is per-origin, all panels share it automatically

### Frontend pattern change

Pattern A, explicit Bearer, common in ~80 sites:
    fetch(API + '/api/v1/foo', { headers: { Authorization: 'Bearer ' + TOKEN } })

Pattern B, credentials same-origin, ~30 sites already correct:
    fetch(API + '/api/v1/foo', { credentials: 'same-origin' })

Pattern A migrates to Pattern B. Token header comes off, credentials goes on, cookie rides along automatically.

Already-correct Pattern B sites:
- static/panels/log_pipeline.html:290,379,411,412
- static/panels/soar.html:528,616,646,717
- static/panels/threat_hunt.html:274
- static/panels/users.html:399

## Migration path

### Phase 1 Feature flag, 1 day, Sprint 5 Day 1

Add environment variable VSP_AUTH_MODE:
- bearer (default) current behavior
- cookie frontend uses cookie only, backend continues to accept both
- both explicit dual mode, logs which path was used

Flag read in cmd/gateway/main.go at startup.

### Phase 2 Frontend cleanup, 1 day, Sprint 5 Day 2

Codemod to replace Pattern A with Pattern B, similar to scripts/sprint4/migrate-text-innerhtml.py.

Edge cases:
- window.parent.TOKEN references in iframe panels, remove entirely
- localStorage.setItem vsp_token on login success, remove
- localStorage.getItem vsp_token checks for logged-in, replace with await fetch /api/v1/auth/check

### Phase 3 Flip flag, Sprint 5 Day 3 morning

Set VSP_AUTH_MODE=cookie in staging. Smoke tests:
- Login flow works
- Panel navigation doesn't break
- State-changing operations require CSRF header, expected 403 if missing

### Phase 4 Cleanup, Sprint 5 Day 3 afternoon

Remove loginResponse.Token from body response. Update API docs. Keep /api/v1/auth/api-token for CI-CD clients.

## Rollback

Feature flag allows instant rollback: set VSP_AUTH_MODE=bearer, redeploy. No data migration needed because cookie and localStorage coexist during transition.

## Testing strategy

### Existing coverage (reuse)

- internal/auth/auth_test.go JWT generation, verify, blacklist
- internal/auth/middleware_test.go Bearer header parse
- internal/auth/blacklist_test.go blacklist add check
- internal/api/middleware/middleware_test.go cookie session middleware
- internal/api/handler/auth_handler_test.go login logout refresh HTTP tests

Test count sufficient. No new Go tests required for Sprint 5.

### New coverage needed Sprint 5

1. Integration test cookie-only login works without Bearer header
2. Integration test CSRF enforcement, cookie present, header missing = 403
3. E2E smoke 25 panels + index.html login chain

## Iframe compatibility

SameSite=Strict on vsp_token cookie, iframes on same origin share cookie automatically. Bootstrap script can simplify: no token reading needed.

TODO(SEC-007) comment in vsp_iframe_bootstrap.js already anticipates this.

One edge case: cookie_session.go:52 blocks token in URL query param (security fix). Any team integration relying on URL tokens will break. Sprint 5 checklist: audit external integrations.

## Metrics for DSOMM evidence

After Sprint 5 completion:
- grep localStorage.getItem vsp_token in static/ = 0 hits (currently 98)
- grep Authorization Bearer in static/ = near 0 (currently ~80)
- Browser DevTools: vsp_token in Cookies, not in localStorage
- Attack surface: XSS can no longer steal session (HttpOnly)

## Open questions before Sprint 5

1. Does docs.html API client documentation need updating for /auth/api-token?
2. Do GitHub Actions workflows use token-in-body anywhere?
3. Any external integrations with hardcoded token-in-body parsing?

## References

- OWASP A07:2021 Identification and Authentication Failures
- OWASP ASVS 3.4 Cookie-based Session Management
- docs/SECURITY_DECISIONS.md
- docs/sprint4/SPRINT4-TRACKER.md
