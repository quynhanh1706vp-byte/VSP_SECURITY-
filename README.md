# FEAT-20c — Gateway route for /static/patches/*

## Why
FEAT-20/20b deployed JS patch to ./static/patches/ but gateway returns 404
because no route catches /static/patches/*. Browser gets MIME type 'text/plain'
because nginx serves 404 page as text, not the JS file.

## Method
Add 1 catch-all route in cmd/gateway/main.go, mirroring existing
/static/js/* pattern at line ~629.

## Files changed
- `cmd/gateway/main.go` — adds /static/patches/* route after /static/js/* route

## Apply
    cd <project-root>
    ./patches/feat-20c-gateway-patches-route/dryrun.sh    # sandbox first
    ./patches/feat-20c-gateway-patches-route/apply.sh     # real
    # then restart gateway (your usual command)

## Verify
- `curl -k -sI https://vsp.local/static/patches/feat-20-ai-analyst.js` → HTTP 200
- Reload ai_analyst panel → console shows `[FEAT-20b] ai_analyst loadAllData wrapped...`
- KPI cards (Score/Gate/Inc/Crit) shimmer briefly before showing real values

## Rollback
    ./patches/feat-20c-gateway-patches-route/rollback.sh
    # rebuild + restart gateway

## Future use
After FEAT-20c, any future patch (FEAT-21, 22, 23...) only needs:
  1. Drop JS file into ./static/patches/feat-XX-<panel>.js
  2. Inject <script src="/static/patches/feat-XX-<panel>.js"></script>
     into target panel's HTML
  3. No gateway changes needed.

## Risk
LOW — adds 1 route, doesn't modify existing behavior.
Idempotent (marker check + grep guard).
Compile-checked in apply.sh (rolls back if Go build fails).
