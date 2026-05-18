# Super-Patch: F1 Bulk-Select FIX

Resolves 3 issues discovered after F1 was deployed but not properly committed:

1. **`.gitignore` blocks F1 files** — `patches/` and `vsp_*.js` rules prevented
   `git add` from picking up the new JS file and patch directory.
2. **Backend handler missing** — earlier snippet was for `net/http.ServeMux`,
   but the gateway uses chi router. Result: HTTP 404 on `/api/v1/vulns/bulk`.
3. **Bonus** — provides a clean `bulk_findings.go` standalone file instead of
   inline injection into `main.go` (safer to maintain & revert).

## Files

```
01-bulk-select-fix/
├── README.md            ← you are here
├── apply.sh             ← orchestrator — runs all steps
├── rollback.sh          ← reverts everything
├── 01_fix_gitignore.py  ← surgical .gitignore edit
├── 02_inject_routes.py  ← installs bulk_findings.go + injects route lines
└── bulk_findings.go     ← standalone Go file → cmd/gateway/
```

## What it changes

### 1. `.gitignore`

- Replaces `patches/` (whole tree blocked) with `patches/*` (allows re-includes)
- Appends a marked block:
  - `!patches/findings/` + `!patches/findings/**` — un-ignore Sprint 1 patches
  - `!static/js/vsp_bulk_f1.js` — explicit allow per-file
  - `patches/findings/**/*.bak*` — keep backups ignored

### 2. `cmd/gateway/main.go`

Inserts 2 lines inside the authenticated `/api/v1` route group:

```go
// VSP_PATCH_F1_ROUTES_BEGIN
r.Post("/api/v1/vulns/bulk",      handleVulnsBulk)
r.Post("/api/v1/vulns/bulk/undo", handleVulnsBulkUndo)
// VSP_PATCH_F1_ROUTES_END
```

Routes inherit:
- `auth.Middleware` (JWT bearer)
- `vspMW.NewUserRateLimiter(600, time.Minute)` — 600 req/min per user

Anchor used: line containing `r.With(...).Get("/api/v1/vsp/findings/summary", ...)`.
Insertion happens AFTER this line, preserving the parent indentation.

### 3. `cmd/gateway/bulk_findings.go` (new file)

Self-contained `package main` file with:
- `bulkActionRecord` struct + 60s in-memory undo store with GC goroutine
- `handleVulnsBulk` — accepts `{action, cve_ids, metadata}`
- `handleVulnsBulkUndo` — accepts `{undo_token}`
- Local helpers (`writeBulkJSON`, `writeBulkErr`) — prefixed to avoid collision
  with anything in main.go

DB wiring marked as `TODO(F1-DB)` for next sprint.

## How to apply

```bash
cd /home/test/Data/GOLANG_VSP
bash patches/findings/01-bulk-select-fix/apply.sh
```

Expected output:

```
Step 1/3: Fix .gitignore
[F1] Backup: .gitignore.bak.f1
[F1] Transformed `patches/` → `patches/*` for re-include support
[F1] Appended whitelist block
[F1] Wrote .gitignore

Step 2/3: Inject backend routes into cmd/gateway/main.go
✓ Backup: cmd/gateway/main.go.bak.f1
[F1] Installed: cmd/gateway/bulk_findings.go
[F1] Patched cmd/gateway/main.go (+4 lines, anchor at offset NNNN)

Step 3/3: Verification
File trackability:
  ✓ patches/findings/01-bulk-select/vsp_bulk_f1.js trackable
  ✓ static/js/vsp_bulk_f1.js trackable
  ✓ cmd/gateway/bulk_findings.go trackable

Routes registered in main.go:
  XXX:    // VSP_PATCH_F1_ROUTES_BEGIN
  XXX:    r.Post("/api/v1/vulns/bulk",      handleVulnsBulk)
  XXX:    r.Post("/api/v1/vulns/bulk/undo", handleVulnsBulkUndo)
  XXX:    // VSP_PATCH_F1_ROUTES_END

✅ Super-patch applied. Proceed with build + commit per steps above.
```

Then follow the printed manual steps:

```bash
# 1. Build
bash scripts/build-gateway.sh
sudo cp bin/vsp-gateway /usr/local/bin/vsp-gateway
sudo systemctl restart vsp-gateway

# 2. Verify route
curl -k -X POST https://vsp.local/api/v1/vulns/bulk \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"action":"resolve","cve_ids":["CVE-2025-32434"]}'

# 3. Browser test → Resolve → toast + undo
# 4. Amend commit + force-push
git add .gitignore \
        patches/findings/01-bulk-select/ \
        static/js/vsp_bulk_f1.js \
        cmd/gateway/main.go \
        cmd/gateway/bulk_findings.go
git status
git commit --amend --no-edit
git push --force-with-lease origin docs/security-deliverables
```

## Rollback

```bash
bash patches/findings/01-bulk-select-fix/rollback.sh
```

Restores `cmd/gateway/main.go` and `.gitignore` from backups, removes
`bulk_findings.go`. You'll need to rebuild + restart manually.

## Why a separate file (vs inline in main.go)?

`main.go` is ~2400 lines already. Adding 200 more lines makes review harder.
A separate `bulk_findings.go` in the same package:

- Compiles into the same binary (Go merges all `package main` files)
- Easier to read / review
- Easier to delete if rolled back
- Sets a pattern for future F2-F8 backends (`filter_f2.go`, etc.)

## Why `--force-with-lease` not `--force`?

`--force-with-lease` checks the remote hasn't moved since your last fetch.
If a teammate pushed to `docs/security-deliverables` between your fetch and
push, the force-with-lease will refuse, protecting their work. Plain `--force`
silently overwrites.
