# Sprint 4 Tracker — UI Security Hardening

**Branch:** sprint4/ui-security-hardening
**Start:** 2026-04-21
**Target end:** 2026-05-05 (2 weeks)
**Goal:** DSOMM 3.42 → 3.55 via UI security debt reduction

## Scope (option A — focused UI security)

- 140 localStorage JWT sites → HttpOnly cookie
- 53 HIGH template-literal innerHTML → DOMPurify/textContent
- 1 vsp_anthropic_key secret leak → backend proxy

**Out of scope (deferred to Sprint 5):**
- 9 nilerr bugs
- MFA enforcement flip
- 232 MED innerHTML
- 8 LOW innerHTML +=

## Daily progress

### Day 0 — 2026-04-21 (kickoff)

- [x] Local CI green baseline established (88s, commit sync with main)
- [x] UI debt inventory generated (`docs/sprint4/ui-debt-inventory.csv`)
- [x] Root pattern analysis: 144 auth sites use single key `vsp_token` + 1 bootstrap pattern
- [x] **NEW finding:** `vsp_anthropic_key` found in localStorage — escalated P0
- [ ] Research results paste + codemod tool design

### Day 1-2 — Auth bootstrap consolidation

_Planned:_
- [ ] Create `static/js/auth.js` with `getAuthToken()`, `setAuthToken()`, `clearAuthToken()`
- [ ] Backend: `/api/v1/auth/cookie-login`, `/cookie-logout`, `/cookie-refresh`
- [ ] CSRF double-submit pattern

### Day 3-4 — Codemod + replace 144 sites

_Planned:_
- [ ] `scripts/sprint4/migrate-localstorage.sh` — codemod with backup
- [ ] Manual verify each touched panel

### Day 5-6 — Anthropic key migration

_Planned:_
- [ ] Backend proxy `/api/v1/ai/chat` — key lives in `internal/secrets/` server-side
- [ ] Frontend `ai_analyst.html` call via proxy, never see key

### Day 7-9 — 53 HIGH innerHTML

_Planned:_
- [ ] Add `DOMPurify` via CDN
- [ ] Add `static/js/dom-safe.js` with `safeSetHTML()` helper
- [ ] Replace 53 sites manually (cannot codemod — each has context)

### Day 10 — Verification + retro

_Planned:_
- [ ] `bash scripts/ci/local-ci.sh` all green
- [ ] Post-fix inventory: localStorage auth = 0, HIGH innerHTML = 0
- [ ] Write `docs/retros/2026-05-05-sprint4.md`

## Evidence checklist (for DSOMM close)

- [ ] PR merged to main
- [ ] Screenshot of browser DevTools: cookie visible, localStorage empty of `vsp_token`
- [ ] `classify-ui-debt.sh` post-Sprint: CRIT=0, HIGH=0
- [ ] All 20+ touched panels smoke-test pass
- [ ] Regression: no existing feature broken (golden-path checklist in `docs/runbooks/`)

## Risks being tracked

| Risk | Mitigation |
| --- | --- |
| Iframe context — `window.parent.TOKEN` pattern may break with cookies | Test iframe panels specifically; cookie SameSite=Lax allows iframe-parent cookie share on same origin |
| Backend CSRF rollout affects existing API clients | Feature-gate `AUTH_MODE=cookie\|bearer\|both`, default `both` for 1 sprint |
| 1 codemod run may break 144 sites simultaneously | `scripts/.../migrate-*.sh` creates backup, fixes are reversible |
| `vsp_anthropic_key` fix requires AI Analyst refactor | If >1 day, split into Sprint 4.5 subtask |



---

## Sprint 4 FINAL status (2026-04-21)

### Completed

| Task | Status | Commit |
|---|---|---|
| SEC-005b frontend fix | ✅ | 4076809 |
| SEC-005b cleanup code | ✅ | 862b87b |
| Week 1 bootstrap verify | ✅ | 7c3ab2d |
| SEC-006 Phase 1a TEXT | ✅ | 8265647 |
| SEC-006 Phase 1b TEXT | ✅ | a9b8a38 |
| SEC-006 Phase 2 STRUCTURED | ✅ | a5a4696 |
| SEC-006 Phase 3 DYNAMIC | ✅ | 213dcce |
| Cookie design doc | ✅ | 811e4e3 |
| Sprint 4 retro | ✅ | 811e4e3 |

### Metrics verified post-sprint

- HIGH template-literal innerHTML: 53 → 0 (TEXT + DYNAMIC fully migrated)
- STRUCTURED: 12 marked reviewed (XSS risk = 0 by analysis)
- SEC-006 fixed markers: 5 (grep verified)
- SEC-006 reviewed markers: 12 (grep verified)
- vsp_anthropic_key: 3 references remain, ALL in SEC-005b cleanup block (intentional)
- Local CI: pass 60-98s
- PR #26: OPEN, MERGEABLE, not draft
- GitHub Actions CI: 5 FAILURE (SD-0049 billing, not code)

### Cross-references

- Cookie migration: docs/sprint4/cookie-migration-design.md
- Sprint retro: docs/retros/2026-04-21-sprint4.md
- Inventory final state: docs/sprint4/innerhtml-high-classified.csv
- DSOMM tracking: updated in FEATURE_INVENTORY.md (needs verify)
