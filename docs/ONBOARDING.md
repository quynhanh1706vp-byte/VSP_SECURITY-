# VSP Developer Onboarding

**Goal:** Get a new engineer from zero to first commit in 1 working day.
**Last updated:** 2026-04-20

If anything in this guide is wrong or missing, **update it in the same PR
as your first contribution**. That's the price of admission.

---

## Hour 1 — Accounts & read

### Access you need before starting

- [ ] GitHub access to `quynhanh1706vp-byte/VSP_SECURITY-` (ask eng lead)
- [ ] GitHub 2FA enabled (hardware key preferred, TOTP acceptable)
- [ ] SSH key added to GitHub (not HTTPS — we push over SSH)
- [ ] `gh` CLI authenticated: `gh auth login`
- [ ] Team chat access (solo-dev phase: not applicable; becomes required at team growth — consider Slack workspace with `#vsp-eng` + `#vsp-security` channels)
- [ ] On-call rotation access (solo-dev phase: single on-call = owner; becomes required at team ≥ 2. VSP SIEM has PagerDuty integration via `internal/siem/executor.go` for customer-facing alerts — separate from team rotation)

### Required reading (in this order)

1. [README.md](../README.md) — project overview
2. [ARCHITECTURE.md](ARCHITECTURE.md) — C4 diagrams, how components fit
3. [SECURITY.md](../SECURITY.md) — security posture, what VSP claims
4. [THREAT_MODEL.md](../THREAT_MODEL.md) — STRIDE threat model
5. [CONTRIBUTING.md](../CONTRIBUTING.md) — PR workflow, review checklist
6. [RUNBOOK.md](RUNBOOK.md) — skim, you'll need it when on-call
7. [SECURITY_DECISIONS.md](SECURITY_DECISIONS.md) — history of security decisions,
   **including current open exceptions (SD-0047 to SD-0049)**

**Why the order matters:** architecture first (so code isn't magic), security
second (because VSP is a security product — you'll miss signals if you don't
know what we're defending), contributing third (so you don't waste time on
a PR that'll be rejected for process).

---

## Hour 2-3 — Local setup

### System requirements

- Linux (Ubuntu 22.04+ or equivalent) or macOS (M1+ fine)
  **Windows:** use WSL2; native Windows not supported.
  **Filesystem:** ext4 or APFS. **NOT NTFS** (chmod doesn't enforce on NTFS,
  breaks secrets permissions — see SD history).
- Go 1.25.9+ (`go version` to verify)
- Docker 24+ with Docker Compose v2
- PostgreSQL client (`psql`)
- Make (GNU make, `make --version`)
- 16 GB RAM recommended (for concurrent scanners + DB)

### Install tooling

```bash
# Go tools used in VSP
go install github.com/pressly/goose/v3/cmd/goose@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest

# golangci-lint v2 (NOT v1 — config format differs)
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
    sh -s -- -b $(go env GOPATH)/bin latest
golangci-lint --version  # should show v2.11+ built with go1.25+

# Gitleaks (secrets scanner)
# Ubuntu 24.04 (verified dev env):
curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.21.2_linux_x64.tar.gz \
    | tar -xz -C /tmp gitleaks
sudo mv /tmp/gitleaks /usr/local/bin/
gitleaks version  # should print 8.x

# Pre-commit hooks
pip install pre-commit
# Or: brew install pre-commit
```

### Clone and bootstrap

```bash
git clone git@github.com:quynhanh1706vp-byte/VSP_SECURITY-.git vsp
cd vsp

# Install git hooks (gofmt, go vet, gitleaks on every commit)
pre-commit install

# Download deps
go mod download

# Start dev infrastructure (Postgres, Redis)
docker compose up -d postgres redis
# Wait ~10 seconds for Postgres to be ready
docker compose exec postgres pg_isready -U vsp

# Run migrations
goose -dir internal/migrate/sql postgres \
  "postgres://vsp:vsp_test@localhost:5432/vsp_test?sslmode=disable" up

# Seed test data
go run ./cmd/seed

# Build all binaries
go build ./cmd/...

# Run tests (race detector on — it's non-negotiable)
go test ./... -race -count=1 -timeout=120s
```

If any step above fails, **STOP** and ask in `#vsp-eng` before trying
workarounds. We've spent time making these steps work cleanly — if they
don't for you, that's a bug in onboarding, not in you.

---

## Hour 4 — Run VSP locally

```bash
# Copy env template
cp .env.production.example .env

# Edit .env — generate test secrets (NOT production values)
cat > .env << EOF
DATABASE_URL=postgres://vsp:vsp_test@localhost:5432/vsp_test?sslmode=disable
REDIS_ADDR=localhost:6379
JWT_SECRET=$(openssl rand -hex 32)
API_KEY_SECRET=$(openssl rand -hex 32)
DB_ENCRYPTION_KEY=$(openssl rand -hex 32)
SERVER_ENV=development
SERVER_ALLOWED_ORIGINS=http://localhost:8921
EOF

chmod 600 .env   # important: prevent world-reading your dev secrets

# Start gateway
./gateway &

# Verify
curl -sf http://localhost:8921/health
# Expected: {"status":"ok","version":"<git sha>"}

# Open UI
# Browser → http://localhost:8921/
# Login: admin@vsp.local / <seed password shown by `go run ./cmd/seed`>
```

### Trigger a real scan

```bash
# Via CLI (good for understanding the flow)
./vsp-cli scan --mode SAST --target ./internal/auth
# Watch scanner logs in another terminal
docker compose logs -f scanner
# (or wherever you're running ./scanner)
```

---

## Hour 5-6 — First contribution

### Pick your first task

Start with **one of these** — they touch real code but low-risk:

- **Docs fix:** find a typo in any `docs/*.md`, fix it
- **Lint warning:** pick one from `golangci-lint run ./...` output
  (586+ currently; any one is fair game)
- **Test coverage:** pick a function with no test in `internal/`, add one
- **Misspell:** `misspell` linter has 44 findings — trivial fixes

### The full flow (do this once, end-to-end)

```bash
# 1. Branch from main
git checkout main && git pull
git checkout -b docs/typo-my-first-pr-$(whoami)

# 2. Make your change
# (edit file, save)

# 3. Pre-flight checks (pre-commit runs a subset automatically)
gofmt -l -w .
go vet ./...
golangci-lint run --timeout=10m ./...   # no NEW issues
go test ./... -race -count=1

# 4. Commit
git add <files>
git commit -m "docs: fix typo in SECURITY.md

Refs: onboarding-first-pr"

# 5. Push
git push -u origin $(git branch --show-current)

# 6. Open PR (draft first!)
gh pr create --draft --title "docs: fix typo in SECURITY.md" \
  --body "My first PR following ONBOARDING.md."

# 7. Request review when ready
gh pr ready
```

### Review expectations

- Someone on the team will review within 1 business day
- You will get nitpicks. Take them as gifts, not criticism.
- Fix, push more commits, request re-review
- When approved, reviewer squash-merges (do NOT merge your own PR as a new hire)

---

## Hour 7-8 — Orient yourself in the code

Spend time reading, not coding:

### Critical paths to understand

1. **Request → response flow:** trace a single HTTP request:
   - `cmd/gateway/main.go` — route registration
   - `internal/api/middleware/*.go` — 5 middleware in order
   - `internal/api/handler/auth.go:login` — example handler
   - `internal/store/users.go` — DB layer
   Actually read the code with `grep -n "Handler" cmd/gateway/main.go`, follow
   the chain.

2. **Tenant isolation:** VSP is multi-tenant. Every query that reads user
   data has `tenant_id` in WHERE. Open `internal/store/findings.go` and
   confirm for yourself. If you find a query without tenant_id and it's
   exposed to user input — file a security issue.

3. **Audit log hash chain:** `internal/audit/` — each entry links to the
   previous via SHA-256. Read `Verify()` function; understand why
   `TRUNCATE audit_log` is forbidden (breaks integrity).

4. **Scanner integration:** `internal/scanner/<tool>/` — each subpackage
   wraps one external tool. Read `internal/scanner/gosec/` as template —
   it parses gosec JSON output into VSP's finding model.

### Repo cleanliness norms

- **Top-level directory is sacred.** Only config files + Makefile + docs.
  Random `.sh`, `.py`, `.js` at top-level is debt from rapid prototyping;
  they're being archived into `scripts/archive/`. Don't add more.
- **`cmd/` is the binary boundary.** Each subdirectory = one binary.
- **`internal/` is the code.** Hexagonal structure: handler → service → store.
- **`static/` is the frontend.** Being rebuilt in Sprint 4 (SEC-005).

---

## Day 2+ — Going deeper

### Subscribe to alerts

- [ ] GitHub Dependabot alerts (already on, just check your email)
- [ ] GitHub security advisory notifications
- [ ] `#vsp-security` Slack channel
- [ ] On-call rotation schedule (you probably won't be first on, but know the drill)

### Recommended reading (week 1)

- [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) — if working on compliance features
- [DSOMM_ASSESSMENT.md](DSOMM_ASSESSMENT.md) — current maturity baseline
- [JWT_ROTATION_RUNBOOK.md](JWT_ROTATION_RUNBOOK.md) — because secrets matter
- The 5 most recent PRs — see how your teammates review

### Tools worth learning

| Tool | Why |
|------|-----|
| `golangci-lint` | You'll run it daily. Understand every linter we enable. |
| `goose` | Migrations. If you touch `internal/migrate/sql/`, you need this. |
| `sqlc` | We generate Go from SQL files. Don't write DB code without it. |
| `docker compose` | Local dev stack. |
| `gh` CLI | Faster than web UI for PRs, runs, reviews. |
| `delve` (dlv) | Go debugger. Better than `fmt.Println`. |

---

## Frequently stuck on

### "CI fails but runs on my machine"

Likely a Go version mismatch or missing dep. See `go.mod` for required Go
version (currently 1.25.9). Check CI logs with `gh run view <id> --log-failed`.

### "I broke the main branch"

Breathe. Every engineer does this once. Rollback:
```bash
git revert <bad-commit-sha>
git push origin main  # requires admin because main is protected
```
Then open a PR with the revert + a post-mortem comment.

### "My PR is blocked by failing CI but I can't tell why"

- Check CI billing status (`docs/SECURITY_DECISIONS.md` SD-0049 might still
  be open)
- Ask in `#vsp-eng`, someone will look at the run with you

### "I don't understand what this module does"

Grep for the package name, look at its tests, look at its callers. If still
unclear after 30 min, ask — don't sink 2 hours. The person who wrote it is
probably nearby.

---

## Success criteria for onboarding

By end of day 1, you should have:
- [ ] All tooling installed and working
- [ ] Local VSP running, can login, can trigger a scan
- [ ] Read 7 required docs
- [ ] First PR opened (can still be draft)
- [ ] Joined relevant Slack channels

By end of week 1:
- [ ] First PR merged
- [ ] Understand request lifecycle through middleware stack
- [ ] Understand tenant isolation pattern
- [ ] Know who to ask for what (security, ops, db, product)

If you're not there, **speak up**. Onboarding slippage is our bug, not yours.

---

## Change log

- **2026-04-20 v1.0** — Initial onboarding doc. Team-specific items
  currently marked "solo-dev phase" become applicable at team growth.

**Review cadence:** Every new hire updates anything that didn't work. Full
review quarterly.

