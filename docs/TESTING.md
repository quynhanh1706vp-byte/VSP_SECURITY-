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

`.github/workflows/release-readiness.yml` runs L1-L7 (8.1 always,
8.2 only on workflow_dispatch with `run_l7_live=true`) against an
ephemeral Postgres+Redis on every PR that touches gateway/handler/
store/migration code. The aggregate scoreboard is uploaded as a
`release-readiness-report-<run_id>.json` artifact. Cumulative FAIL>0
blocks merge.

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
