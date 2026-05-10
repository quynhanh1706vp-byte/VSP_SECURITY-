# Release-Readiness Test Ladder (L1 → L7)

This document is the operator-facing reference for the seven test
levels VSP runs before any release. Every level is a Bash or Go
script under `scripts/` that can be invoked stand-alone, or via the
orchestrator `scripts/test-all.sh` which runs the whole ladder and
emits an aggregate scoreboard.

The ladder is structured so each level digs deeper into a different
class of bug. Earlier levels are cheap and fast (smoke / per-endpoint
contract); later levels are slower but catch the bugs that survive
unit tests — race conditions, cross-tenant leaks, compliance gaps.

## TL;DR — running locally

```bash
export DB_DSN="postgres://vsp:<password>@localhost:5432/vsp_go"
export JWT_SECRET="<your dev secret>"   # or set VSP_JWT_SECRET_FILE

./scripts/test-all.sh --json /tmp/report.json
```

Exit code is 0 if every level reports zero failures, non-zero with a
per-level summary otherwise. `--json` writes a machine-readable
scoreboard CI uploads as an artifact.

## Levels

### L1 — Smoke

`scripts/test-l1-smoke.sh` — 9 cases, ≈ 15 s.

Confirms the binary booted and the most-trafficked endpoints respond.
Catches: a misconfigured deploy, a missing migration, a route
unintentionally moved behind auth.

### L2 — Feature contract

`scripts/test-l2-feature.sh` — 63 cases, ≈ 30 s.

Per-endpoint shape probes: every public API returns the expected
status code, content-type, and minimum payload size; every DB
sentinel column resolves. Catches: endpoint contract drift between a
handler and the dashboard JS that consumes it.

### L3 — Comprehensive

`scripts/test-l3-comprehensive.sh` — 89 cases, ≈ 5 min.

Six phases: auth boundary attacks, input validation, IDOR, content
depth, resilience, sprint deliverables. The auth-boundary phase
spends most of its runtime exercising IPLockout and constant-time
defenses; the content-depth phase asserts that compliance frameworks
have the expected number of controls/practices.

### L4-A — Property-based (Go)

`internal/gate/property_test.go` — 10 properties × ~50 000 random
inputs, ≈ 0.5 s.

Asserts structural invariants of the gate scoring math:
`Score ∈ [0, 100]`, monotonic in finding count, hard-fail dominates
the DAST bonus, etc. Catches: math regressions that fixture-based
unit tests would miss because the regression only surfaces at unusual
input scale.

### L4-B — Multi-tenant isolation

`scripts/test-l4-tenant-isolation.sh` — 17 cases, ≈ 30 s.

Mints two tenant tokens, seeds canary rows, probes every list /
aggregate / IDOR endpoint with both, asserts no cross-pollination.
Catches: cache key collisions (we found one), missing tenant-scope on
new endpoints, IDOR via direct-by-ID fetches.

### L5 — Advanced (concurrency, RBAC, SSE)

`scripts/test-l5-advanced.sh` — 17 cases, ≈ 60 s.

Three phases:

- **6.1 SSE cross-tenant.** Open a stream as tenant A, broadcast a
  scan_complete on tenant B, assert A's stream never receives the
  payload.
- **6.2 RBAC matrix.** admin/analyst/dev/auditor probed against
  admin-only and write endpoints.
- **6.3 Concurrency.** IPLockout under 30-way burst, audit-chain
  ordering under 20-way burst, cache-stampede tenant-isolation under
  50.

### L6-A — DB integrity invariants

`scripts/test-l6-db-integrity.sh` — 30 cases, ≈ 10 s.

SQL-level audit: foreign-key orphans, audit chain (no `pending`, no
seq gaps), runs↔findings aggregate consistency, tenant scoping (NOT
NULL columns), temporal sanity, RLS policies on every tenant-scoped
table, severity enum membership, fingerprint dedup, tools_done parity.

### L6-C — Static analysis dogfood (out-of-band)

Run `gosec` against our own codebase the same way scanners run against
customer code. Gates on HIGH-severity findings only — Medium-severity
findings are reviewed manually. Wired into a separate workflow.

### L15 — HTTP hygiene (response headers, cookies, CORS)

`scripts/test-l15-http-hygiene.sh` — 19 cases, ≈ 2 s.

Six phases: required security headers (CSP, HSTS, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
cookie-attribute audit (HttpOnly + SameSite + Secure-under-HTTPS for
session cookies; SameSite for double-submit CSRF), CORS no-foreign-
origin reflection, no stack-trace leak in 5xx bodies, debug-route
gating (loopback-only IP allow-list verified in source + behavior),
TRACE/CONNECT method rejection.

### L16 — Information disclosure

`scripts/test-l16-info-disclosure.sh` — 7 cases, ≈ 2 s.

Beyond L15's stack-trace check, walks broader surface for: file
paths / package paths / internal CIDRs in error bodies, SQL syntax
or SQLSTATE markers in DB-error responses, Server / X-Powered-By
stack disclosure, 404-vs-403 IDOR oracle (foreign-tenant fetch must
return same status as nonexistent), HTML comment leakage of TODO /
FIXME / secret markers, build-version / git-SHA exposure.

### L17 — Rate-limit / abuse-vector coverage

`scripts/test-l17-ratelimit.sh` — 5 cases, ≈ 60 s.

The gateway intentionally disabled the global per-IP rate limiter
(dashboard polling triggered 429 storms). This level confirms each
remaining defense layer works: per-IP login lockout fires across
distinct usernames (credential-stuffing defense), 4 MB body cap on
JSON POSTs, slowloris read-timeout under 75 s, expensive endpoint
(audit/verify) survives 50-way concurrent burst without 5xx, and
per-tenant lockout isolation (tenant B not affected by tenant A
bursts).

### L22 — SQL injection active probe

`scripts/test-l22-sqli.sh` — 6 cases, ≈ 5 s.

Fires 8 classic SQLi payloads × 5 query-param endpoints (40 probes),
asserts no SQL state markers in any response body. Plus boolean-blind
invariant (true/false tautology payloads return same row count) and
time-based probe (`pg_sleep(3)` payload doesn't actually sleep).
Final phase tests ORDER BY column-name allow-listing.

### L23 — Trust boundary / proxy header

`scripts/test-l23-trust-boundary.sh` — 7 cases, ≈ 5 s.

Watchdog for the proxy-header-trust fix landed in main.go:
asserts `trustedRealIP` middleware is wired (not raw `chimw.RealIP`),
behavioural confirms loopback rewrite still works, IPLockout fires
per forwarded IP, fresh forwarded IP starts at 0 counter,
`X-Forwarded-Proto` stripped from non-trusted sources.

### L24 — Input validation completeness

`scripts/test-l24-input-validation.sh` — 10 cases, ≈ 3 s.

Behavioral and static input-validation audit: 100KB string,
100-deep JSON, unicode confusables, NUL bytes, and negative numerics
don't 5xx. Numeric `?limit=999999999` clamped. Malformed UUID in path
returns 400 not 500. Static watchdog: every JSON-decoding handler
has at least one length check.

### L27 — Observability completeness

`scripts/test-l27-observability.sh` — 10 cases, ≈ 2 s.

`/metrics` parseable + go runtime / process / vsp_app domains have
metrics; structured log output (JSON or zerolog console kv) majority
of lines; chimw.Recoverer wired so panics don't crash the process.
Watchdog: domain counters for auth, audit, and HTTP request
volume/latency are absent — operator can't observe these from
Prometheus until they're wired (compliance debt).

### L28 — Hardcoded secrets scan

`scripts/test-l28-secrets.sh` — 6 cases, ≈ 1 s.

Source-code grep for credential-shaped string literals (after
filtering REPLACE_ME / env-ref / dev-secret-please-change false
positives), no PEM private keys committed, config/*.yaml has no
high-entropy non-placeholder values, `.gitignore` covers `.env /
*.pem / secrets`, no real `.env` or `*.pem` tracked.

### L29 — Time correctness

`scripts/test-l29-time-correctness.sh` — 6 cases, ≈ 1 s.

Every tenant-scoped timestamp column is `timestamptz` (no naive
local times), JWT `exp` boundary respected (expired-by-1s rejected,
60s-future accepted), no future-dated rows in `audit_log` / `runs`
(clock-skew detector), locale-invariant status across `vi/en`,
no `time.Local` references in auth/audit code (ensures UTC consistency).

### L30 — Container / deploy security

`scripts/test-l30-container-deploy.sh` — 8 cases, ≈ 1 s.

Dockerfile final stage is non-root, has HEALTHCHECK, no `ADD url://`,
apt cache cleaned. Helm values declares resources + probes. systemd
unit has NoNewPrivileges + ProtectSystem + PrivateTmp (a hardened
`deploy/systemd/vsp-gateway.service` is shipped in the repo).
`.env.example` tracked, real `.env` not.

### L34 — Go native fuzzing (parsers)

`scripts/test-l34-fuzz.sh` — 3 cases × ~8 s each.

Go native fuzzing (`testing.F.Fuzz`) on parser hot-paths:
`auth.parseJWT`, `auth.ClientIP`, `handler.decodeJSON`. Each runs
a budgeted exploration, mutating seed corpus. A panic / assertion
failure persists as a `testdata/fuzz/<Target>/<hash>` regression
seed so subsequent runs replay it instantly. ~515 k random inputs
explored in the default 8-s budget per target.

### L25 — Race conditions / TOCTOU

`scripts/test-l25-race-toctou.sh` — 5 cases, ≈ 15 s.

Business-logic race probes: 5 concurrent DSR submissions don't
corrupt rows; 5 concurrent plan UPDATEs converge to one of the
attempted values; refresh+logout race correctly invalidates the
old token; 5 concurrent tool-config PUTs leave coherent JSON;
audit-verify during a 30-event insert burst returns ok=true.

### L26 — Resource cleanup audit

`scripts/test-l26-resource-cleanup.sh` — 6 cases, ≈ 5 s.

Static + behavioural cleanup audit: every `os.Open / os.Create`
has a matching Close in its function; every `http.Response.Body`
has a near-by Close; every DB `rows.Query` has a `rows.Close`
within 60 lines; every multipart `FormFile` has a Close; every
`tx.Begin` is paired with Commit or Rollback. Behavioural: open-FD
count bounded after a 100-burst.

### L18 — Schema migration safety

`scripts/test-l18-migration-safety.sh` — 6 cases, ≈ 1 s.

Static + idempotency probes against `migrations/*.sql`: filename
layout conformance, duplicate-prefix detection (with forward+rollback
pair allow-list), non-empty content, `DROP` always uses `IF EXISTS`,
re-applying the latest migration succeeds (idempotency contract),
no `SET search_path` that would clobber RLS context.

### L19 — ReDoS static scan

`scripts/test-l19-redos.sh` — 4 cases, ≈ 1 s.

Hand-rolled regex pattern audit. Asserts: no external regex engine
is imported (RE2/stdlib only), no nested-quantifier / greedy-chain /
alternation-with-prefix-overlap shapes in any compiled pattern,
every regex compiled from a string literal (never user-controllable
input), every regex inside `internal/api/handler/` is hoisted to
package level rather than re-compiled per request.

### L20 — Dependency license + supply-chain audit

`scripts/test-l20-deps-license.sh` — 4 cases, ≈ 30 s.

Runs `go-licenses csv ./cmd/gateway/...`, then asserts: every
THIRD-PARTY dep has a recognised SPDX license, no GPL / AGPL / SSPL
deps that would force open-sourcing, every license is on the
commercial-friendly allow-list (MIT, Apache-2.0, BSD-2/3, ISC, MPL-
2.0), `go mod verify` clean.

### L21 — File-upload safety

`scripts/test-l21-upload-safety.sh` — 6 cases, ≈ 5 s.

Active probes against `POST /compliance/evidence`: path-traversal
filename sanitised on download, MIME confusion blocked (attachment
disposition or `nosniff`), oversized (50 MB) rejected, zero-byte
non-fatal, CRLF in filename neutralised, no archive extraction in
upload handlers (zip slip structurally N/A).

### L11 — Mutation testing (hand-rolled)

`scripts/test-l11-mutation.sh` — 8 cases, ≈ 30 s.

Applies six semantically-meaningful mutations to `internal/gate/engine.go`
(boundary tighten, hard-fail relaxed, sign flip, floor/ceiling neutered,
hard-fail OR→AND) and runs `go test ./internal/gate/...` after each. A
mutation that PASSES the test suite is a vacuous test — it claims a
property the suite doesn't actually pin. Original source restored on
`EXIT` via trap. Score reported as N/M killed.

### L12 — Chaos / fault injection

`scripts/test-l12-chaos.sh` — 5 cases, ≈ 20 s. Gated by `RUN_CHAOS=1`
because every probe transiently mutates the live environment.

- **14.1 Redis stop**, gateway must fall through to DB.
- **14.2 Body too large**, 20 MB POST must be rejected with 4xx, not OOM.
- **14.3 Malformed-JSON storm**, 200 concurrent broken-JSON POSTs must
  not crash the process.
- **14.4 PG connection kill**, `pg_terminate_backend` on every gateway
  conn — pool reconnect path must engage in seconds.
- **14.5 Slow upstream** (gated separately by `RUN_L12_TC=1`), `tc qdisc`
  netem 200 ms loopback delay — gateway must complete within max-time.

### L13 — Frontend smoke (curl-based)

`scripts/test-l13-frontend.sh` — 6 cases, ≈ 5 s.

Trades Playwright fidelity for breadth: hits `/`, `/trust`, every panel
under `static/panels/*.html`, and every `<script src=...>` reference
on the landing page. Asserts:

- Entry points serve `text/html` with a sane DOM.
- Every panel returns 200 (catches deploy-time route drift).
- No bare `{{ identifier }}` template placeholders survive into
  rendered output (tag-stripped + script-stripped before grep).
- No `Uncaught TypeError` / `Cannot read prop` / `ReferenceError`
  visible in shipped HTML.
- Every JS bundle referenced by `<script src="…">` resolves to 200.

### L14 — Perf smoke (vegeta)

`scripts/test-l14-perf.sh` — 6 cases, ≈ 30 s. Gated by `RUN_PERF=1`.

Sustained 50 RPS for 15-30 s against `/findings/summary`, `/audit/stats`,
`/kpi/sanity`. Asserts P99 ≤ 500 ms, success rate ≥ 99%, RSS drift ≤ 30%,
goroutine drift ≤ 50 over the burst window.

### L8 — Advanced security depth

`scripts/test-l8-security-depth.sh` — 11 cases, ≈ 5 s.

Five phases:

- **9.1 Mass assignment.** PUT/PATCH bodies with extra fields
  (`tenant_id`, `role`, `id`) must be ignored, not honored.
- **9.2 Audit completeness.** Static analysis: every mutation route
  in `cmd/gateway/main.go` is mapped to its handler symbol, and the
  handler source is grepped for an audit emitter (`writeAudit`,
  `logAudit`, `InsertAudit`). Compliance watchdog — fails until every
  state-changing handler emits a row.
- **9.3 JWT lifecycle.** alg confusion (RS256 token with HS256
  verifier), wrong-signature, future-iat probes.
- **9.4 Crypto sanity.** `JWT_SECRET` length ≥ 32, bcrypt cost ≥ 10
  in source, no `math/rand` in `internal/auth`.
- **9.5 Cross-tenant admin.** Tenant-A admin must NOT mutate
  tenant-B's resources. Catches horizontal privilege escalation that
  L5's RBAC matrix (single-tenant scope) misses.

### L7 — DSR right-to-erasure residue

`scripts/test-l7-dsr-residue.sh` — 3 cases, ≈ 20 s static / 1 min live.

- **8.1 Static.** Diffs the schema's tenant_id-bearing tables
  against the erasure worker's coverage. Auto-detects the worker's
  mode (`information_schema` enumeration vs hardcoded list) and
  asserts no table is silently retained.
- **8.2 Live (gated).** Set `RUN_L7_LIVE=1` to seed a synthetic
  canary tenant, fire an immediate-due erasure, and grep every
  tenant_id-bearing table for residue. Mutates DB state, so off by
  default.

## Configuration

Every script reads three pieces of environment:

| Var | Purpose | Fallback |
|-----|---------|----------|
| `JWT_SECRET` | HMAC key signing dev-mint tokens | `VSP_JWT_SECRET_FILE` → `/etc/vsp/env.production` (sudo) |
| `DB_DSN`     | Postgres connection URI                     | `$PGHOST`/`$PGUSER`/`$PGPASSWORD`/`$PGDATABASE` |
| `BASE`       | Gateway base URL                            | `http://127.0.0.1:8921` |

The shared helper `scripts/lib/vsp-test.sh::resolve_jwt_secret` is the
single resolver — every L-script uses it so the same scripts run in
CI (env var), on an operator's laptop (sudo + file), or in a hermetic
test rig (custom file path).

## CI integration

Two GitHub Actions workflows back the ladder:

### Per-PR fast lane — `.github/workflows/release-readiness.yml`

Runs the full 32-level ladder against an ephemeral Postgres + Redis
on every PR that touches `cmd/`, `internal/`, `migrations/`,
`scripts/test-*.sh`, or `go.mod`. Cumulative FAIL > 0 blocks merge.

Inputs (via `workflow_dispatch`):

- `run_l7_live` — enable L7's live canary erasure (mutates DB).
- `run_perf` — enable L14 vegeta burst (default 15s).
- `run_chaos` — enable L12 chaos probes (Redis stop, PG conn kill).
- `fuzztime` — L34 budget per target (default 8s).

Artifacts uploaded:

- `release-readiness-report-<run_id>.json` — aggregate scoreboard.
- `gateway-log-<run_id>` — gateway stdout/stderr (only on failure).
- `fuzz-corpus-<run_id>` — `testdata/fuzz/**` if a fuzz target found
  a regression seed (only on failure).

L6-C runs **out-of-band** as a separate gate step: `gosec` HIGH-
severity findings fail the workflow even if the rest of the ladder
passes (defense in depth — gosec evolves rule packs).

### Nightly deep — `.github/workflows/nightly-deep.yml`

Cron-runs at 03:00 UTC daily with all heavy switches enabled:
`RUN_L7=1 RUN_L7_LIVE=1 RUN_PERF=1 RUN_CHAOS=1 PERF_DUR=60s
FUZZTIME=60s`. Catches the regression class fast-lane budgets are
too short to surface — memory / goroutine drift under sustained
load, slow-emerging fuzz panics, chaos cascades.

Failure attribution: when a nightly fails, the per-PR fast lane
between the last green nightly and the first red nightly is the
likely culprit window. Use `git log` between those commits to
narrow.

Both workflows upload fuzz corpus on failure — the
`internal/auth/testdata/fuzz/` and
`internal/api/handler/testdata/fuzz/` paths gather any panic-
producing input, which a follow-up commit replays as a deterministic
regression test.

## Adding a new level

If you add a new test script, follow the convention:

1. Source `scripts/lib/vsp-test.sh`.
2. Use `phase_open`, `_pass`, `_fail`, `_skip` so output parses
   cleanly.
3. End with `final_summary`.
4. Wire it into `scripts/test-all.sh` via a `run_level` line.
5. Document it here in the levels table.

The orchestrator will pick up the new level's pass/fail counts
automatically.
