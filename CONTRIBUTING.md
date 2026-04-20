# Contributing to VSP Security Platform

**Audience:** Internal engineers and (future) external contributors.

Thank you for working on VSP. This document is the authoritative source
for how to propose, review, and merge changes. VSP is a commercial
DevSecOps product — the way we build it reflects the standards we sell,
so these rules apply to every change regardless of size.

---

## TL;DR

- **Never push directly to `main`.** Always branch + PR, even for typo fixes.
  (Exceptions documented in `docs/SECURITY_DECISIONS.md` — see SD-0047/48/49
  for current exception history.)
- **Pre-commit hook must pass.** `gofmt`, `go vet`, `gitleaks` — these run
  automatically; don't bypass with `--no-verify`.
- **CI must be green.** If CI is broken for infrastructure reasons (billing,
  runners), log the bypass as a new SD-XXXX entry before admin-merge.
- **Two-person review required for:** auth, crypto, SQL changes, middleware,
  and anything in `internal/api/middleware/*.go`.
- **Link a ticket/SD/incident in every commit message.**

---

## Branch strategy

### Naming convention

```
<type>/<scope>-<short-description>
```

| Type | Purpose | Example |
|------|---------|---------|
| `feat/` | New feature | `feat/siem-playbook-triggers` |
| `fix/` | Bug or vulnerability fix | `fix/sprint3-pr-d-gosec-annotations` |
| `docs/` | Documentation only | `docs/sd-0049-ci-billing` |
| `chore/` | Refactoring, dependencies, cleanup | `chore/remove-dead-js-patches` |
| `test/` | Test infrastructure | `test/ci-debug-runner` |
| `security/` | Security-only fix (use for CVE response) | `security/cve-2026-12345` |

### Branch lifecycle

1. Cut from `main` (never from another feature branch — rebase to avoid conflicts)
2. Push early + often. Open PR as **draft** as soon as there's something to discuss.
3. Rebase on `main` before requesting review.
4. Squash-merge on merge (keeps `main` history linear).
5. Delete branch after merge.

### Protected `main` rules

- Direct push → rejected by GitHub branch protection
- Force push → rejected
- Required checks: CI `lint`, `test`, `security`, `ui-check`, `migrations`
- Required reviewers: 1 for typical changes, 2 for security-sensitive paths

---

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body explaining WHY, not what>

Refs: <ticket / SD-XXXX / CVE>
Closes: <issue number if any>
```

### Examples

**Good:**
```
fix(gosec): close 21 HIGH/MED findings via annotation

Sprint 3 PR #D. Applies //#nosec annotations with explicit rationale
at each site (not blanket -exclude). Aligns with SECURITY.md stated
practice of inline justification.

Refs: SD-0042, SD-0043 (gosec exclusion rationale)
```

**Bad:**
```
fix stuff
```

```
Fixed bugs
```

### Subject line rules

- 50 chars max
- Imperative mood: "add", not "added" or "adds"
- No trailing period
- Lowercase after the `type(scope):` prefix

### Body rules

- Wrap at 72 chars
- Explain **why**, not **what** (the diff shows what)
- Reference relevant SD-XXXX entries, issues, CVEs, customer tickets

---

## Before opening a PR

Run locally:

```bash
# 1. Formatting
gofmt -l -w .

# 2. Vet + linting
go vet ./...
golangci-lint run --timeout=10m ./...

# 3. Tests (including race detector)
go test ./... -race -count=1 -timeout=120s

# 4. Secrets
gitleaks detect --no-git --no-banner

# 5. Build all binaries
go build ./cmd/...
```

If any of these fail, **do not open the PR**. Fix locally first.

---

## PR template

When you open a PR, the template includes:

```markdown
## Summary
[2-3 sentences: what changes and why. Link the SD or ticket.]

## Test plan
- [ ] Unit tests pass locally
- [ ] Integration tests pass (if touching store/)
- [ ] Manual test: [describe]
- [ ] No regression in golangci-lint (issue count ≤ baseline)

## Security considerations
- [ ] No new secrets introduced (gitleaks clean)
- [ ] Tenant_id enforced on new queries (if touching store/)
- [ ] No new middleware bypass (if touching api/middleware/)
- [ ] CSP / CSRF / cookie behavior unchanged (or documented in SD-XXXX)

## Rollback plan
[How do we revert if this breaks prod? Usually: "revert the PR". For
migrations: "run `goose down` to revision N".]

## Reviewers
[@security-lead for auth/crypto/middleware, @ops-lead for infra,
@eng-lead for general]
```

---

## Code review checklist

**Reviewers:** use this list before approving.

### Universal checks (every PR)

- [ ] Commit messages follow Conventional Commits
- [ ] Branch name follows convention
- [ ] CI is green (or SD-XXXX bypass documented)
- [ ] PR description is complete
- [ ] No `fmt.Println` / `log.Println` / `panic` left in non-test code
- [ ] No commented-out code (use git history instead)
- [ ] Error messages are actionable for the user, not stack traces

### Security-sensitive checks

Trigger these if the PR touches any of: `internal/auth/`, `internal/api/middleware/`,
`internal/audit/`, `cmd/gateway/main.go`, `.github/workflows/`, `Dockerfile`,
`go.mod`.

- [ ] **Two reviewer approvals** (not one)
- [ ] New SQL queries include `tenant_id` in WHERE or JOIN
- [ ] No new `context.Background()` in request-scoped goroutines
  (use `context.WithoutCancel(r.Context())` if detaching cancellation)
- [ ] JWT / session / cookie behavior documented
- [ ] CSP / CSRF bypass has SD-XXXX justification
- [ ] Dependency bumps reviewed for CVEs (govulncheck clean)
- [ ] Secrets are not logged (even with DEBUG level)
- [ ] Rate limiting applied to new endpoints (`internal/api/middleware/ratelimit.go`)

### Performance checks (if touching hot path)

- [ ] Bulk operations paginated (LIMIT on queries)
- [ ] Goroutines bounded (no `for { go x() }` without semaphore)
- [ ] DB transactions short-lived (no HTTP calls inside `BEGIN...COMMIT`)
- [ ] Context timeouts set (no unbounded waits)

---

## Testing expectations

### Coverage

- New code: **70%+ line coverage** (`go test -cover`)
- Bug fixes: **regression test mandatory** — write the failing test first,
  then the fix
- Security fixes: test must show the vulnerability before fix, absence after

### Test types

- **Unit tests** — `*_test.go` alongside source. Fast, no DB.
- **Integration tests** — `//go:build integration` tag. Uses real Postgres.
- **E2E tests** — `tests/e2e/` (planned, Sprint 5).

Run integration tests:
```bash
docker compose up -d postgres redis
export TEST_DATABASE_URL=postgres://vsp:vsp_test@localhost:5432/vsp_test?sslmode=disable
go test -tags=integration ./...
```

---

## Documentation expectations

Update docs **in the same PR** as the code change:

| If you change... | Update... |
|------------------|-----------|
| Architecture / components | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Public API endpoints | `api/openapi.yaml` |
| Security controls | [SECURITY.md](SECURITY.md) + [THREAT_MODEL.md](THREAT_MODEL.md) |
| Deployment / ops | [RUNBOOK.md](docs/RUNBOOK.md) |
| Compliance controls | [COMPLIANCE_MATRIX.md](docs/COMPLIANCE_MATRIX.md) |
| Dependencies | `go.mod` + `CHANGELOG.md` |
| Breaking change | `CHANGELOG.md` + migration guide |

PRs that change code without updating relevant docs will be rejected.

---

## Handling CI failures

### Legitimate CI failure (code problem)

Fix the code. Push another commit to the same branch. CI re-runs automatically.

### Infrastructure CI failure (runners, billing, GitHub outage)

1. Document as a new SD-XXXX entry in `docs/SECURITY_DECISIONS.md`
2. If blocking a critical fix, admin-merge is allowed **with the SD referenced
   in the merge commit**:
   ```
   gh pr merge <num> --admin --squash --delete-branch
   ```
3. Create a follow-up issue: "Re-trigger CI on commit X after infra fixed"
4. When infra is fixed, close the SD-XXXX with the successful CI run URL

Current open infrastructure SDs: see `docs/SECURITY_DECISIONS.md`.

---

## Security disclosure

**Do not open GitHub issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for disclosure process.

For security fixes as a contributor:

1. Branch name: `security/cve-XXXX-XXXXX` or `security/<short-id>`
2. PR description: **do not** include exploit details (those go in private
   advisory)
3. Reference the advisory ID, not the CVE details
4. Coordinate release with security lead before merging

---

## Getting help

- **Architecture questions:** read [ARCHITECTURE.md](docs/ARCHITECTURE.md) first
- **On-call / production issues:** see [RUNBOOK.md](docs/RUNBOOK.md)
- **Security process:** see [SECURITY.md](SECURITY.md)
- **Compliance mapping:** see [COMPLIANCE_MATRIX.md](docs/COMPLIANCE_MATRIX.md)
- **Onboarding:** see [ONBOARDING.md](docs/ONBOARDING.md)

For anything else: internal Slack channel `#vsp-eng`.

---

## Change log

- **2026-04-20 v1.0** — Initial CONTRIBUTING.md. Codifies existing informal
  practice plus lessons learned from SD-0047/48/49 (CI bypass incidents).

**Review cadence:** After every major incident (update what we learned) or
quarterly (2026-07-20 next).

