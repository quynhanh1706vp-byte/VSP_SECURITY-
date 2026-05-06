# F1.1 — CSRF Header Patch

Tiny follow-up to F1. Adds `X-CSRF-Token` header (double-submit cookie pattern)
to the two bulk action POST calls in `static/js/vsp_bulk_f1.js`.

## Why

Gateway runs `vspMW.CSRFProtect` middleware on `/api/v1/*` (line 453 of
`cmd/gateway/main.go`). The middleware:

1. On GET, sets `vsp_csrf` cookie (HttpOnly=false so JS can read).
2. On POST/PUT/DELETE, requires header `X-CSRF-Token` matching the cookie.
3. Exempts only `/auth/login`, `/auth/refresh`, `/software-inventory/report`,
   `/siem/*`.

Our bulk routes are NOT exempt → without the header we get HTTP 403
"CSRF cookie missing".

## What changes in `vsp_bulk_f1.js`

1. New helper near `authFetch`:
   ```js
   function vspCsrfHeaders(base) {
     base = base || {};
     try {
       var m = document.cookie.match(/(?:^|;\s*)vsp_csrf=([^;]+)/);
       if (m && m[1]) base['X-CSRF-Token'] = decodeURIComponent(m[1]);
     } catch (e) {}
     return base;
   }
   ```
2. Both POST calls (`/api/v1/vulns/bulk` and `/api/v1/vulns/bulk/undo`)
   updated:
   - `credentials: 'include'` (so the cookie is sent)
   - `headers: vspCsrfHeaders({ 'Content-Type': 'application/json' })`

That's the entire patch. ~11 lines added.

## Apply

```bash
cd /home/test/Data/GOLANG_VSP
bash patches/findings/01-bulk-select-csrf/apply.sh
```

Then hard-reload browser (Ctrl+Shift+R) to bypass JS cache.

## Test

In Findings panel, tick a CVE, click Resolve. Should see green toast.

In DevTools → Network → `/api/v1/vulns/bulk` request:
- Request headers should include `X-CSRF-Token: <some-base64>`
- Response status: 200
- Response body: `{"ok":true,"affected":1,...}`

## Rollback

```bash
bash patches/findings/01-bulk-select-csrf/rollback.sh
```

## Idempotent

Re-running `apply.sh` is safe — checks for `VSP_F1_CSRF_PATCHED` marker.

## Why not patch all of repo?

This patches only F1's two POSTs. The rest of the repo's POST calls (in
`vsp_pro_*.js`, `vsp_fe_sync_patch_v2.js`, etc.) likely already work because:

- Many are GET requests (CSRF doesn't apply)
- Or they go through `vspAuthFetch` which may auto-include cookies due to
  same-origin / SameSite=Strict
- Or they use exempt endpoints (`/auth/*`, `/software-inventory/report`, ...)

If you discover other 403 CSRF errors elsewhere, that's a separate fix —
don't bundle into F1.1.
