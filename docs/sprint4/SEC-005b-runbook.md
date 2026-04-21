# SEC-005b — Anthropic API key localStorage removal

## Root cause

Frontend code had fallback path reading `localStorage.getItem('vsp_anthropic_key')`
when server-side gateway was unavailable. Backend `/api/v1/ai/chat` proxy has
existed since early builds, making this fallback dead code with a security risk:
if any browser successfully stored a key, it became XSS-exfiltratable.

## Affected files

- `static/ai_analyst.html` line 941-942 (REMOVED)
- `static/panels/ai_analyst.html` line 942-943 (REMOVED)

## Backend truth

`ANTHROPIC_API_KEY` env var → `viper.BindEnv("anthropic.api_key", ...)` at
`cmd/gateway/main.go:71` → served via POST `/api/v1/ai/chat` with in-process
proxy to `https://api.anthropic.com/v1/messages`. Key never crosses to client.

## Client-side cleanup

Users whose browsers stored a key historically need it cleaned out. Add to
app init (already done via vsp_upgrade_v100.js):

```javascript
// SEC-005b — clean legacy key from localStorage on every page load
try {
  if (localStorage.getItem('vsp_anthropic_key')) {
    console.warn('[SEC-005b] Removing legacy vsp_anthropic_key from localStorage');
    localStorage.removeItem('vsp_anthropic_key');
  }
} catch (e) {}
```

## Verification

- `grep -rn "vsp_anthropic_key\|window\._anthropicKey" static/` → 0 hits
  (except the cleanup line itself, which only calls removeItem)
- Manual test: Open AI Analyst panel with gateway offline → sees error
  "Gateway unavailable. AI features require ANTHROPIC_API_KEY on server"
  (no localStorage fallback)
- Manual test: Open AI Analyst panel with gateway online → chat works normally

## Why not deferred

This is a new discovery during Sprint 4 research. Keeping it in Sprint 4
because: (a) fix is <15 min, (b) risk is actual (XSS → key exfil), (c) no
user-facing change (dead code path), (d) evidence contributes to DSOMM
Culture & Org score (spotting issues proactively during classification).

## Ref

- DSOMM roadmap 2026-Q2 Sprint 4
- `docs/sprint4/SPRINT4-TRACKER.md`
- `docs/sprint4/ui-debt-inventory.csv`
