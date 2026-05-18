# FEAT-05 — Users Panel UX States via VSPUXState

## What
First panel to use the FEAT-04 shared VSPUXState module instead of inline helpers.

Removes:
- var USERS=[5 fake users] (Admin User, SOC Analyst, Security Engineer, Auditor, CI/CD Bot)
- var ROLES=[4 fake role configs]

Adds:
- VSPUXState.skeleton/empty/error wired into loadUsers()
- New loadRoles() function with DEFAULT_ROLES fallback (since /api/v1/admin/roles
  is not implemented yet, but roles are essentially static config)

Preserves (intentional, no backend yet):
- var AUDIT=[8 fake audit logs]    — until /api/v1/admin/audit endpoint exists
- var API_KEYS=[3 fake API keys]   — until /api/v1/admin/api-keys endpoint exists

## Why
Pattern: same as FEAT-01/02/03 but uses VSPUXState (FEAT-04) instead of inline helpers.
Code is ~50% shorter than equivalent inline pattern.

## Defensive design
All VSPUXState calls guarded with typeof check:
  if (typeof VSPUXState !== 'undefined') VSPUXState.skeleton(...)
Panel works (degraded — no skeleton/empty/error UI) even if VSPUXState fails to load.

## Backend endpoints
- /api/v1/admin/users      — wired (existing endpoint)
- /api/v1/admin/roles      — wired with DEFAULT_ROLES fallback (endpoint may not exist;
                             ROLES treated as static config, fallback is OK)

## Apply
bash patches/feat/05-users-uxstates/apply.sh

## Verify
Browser console at https://vsp.local:

  fetch('/panels/users.html').then(r=>r.text()).then(t=>console.log({
    marker: t.includes('FEAT-05 PATCH APPLIED'),
    mockGone: !t.includes("name:'Admin User',email:'admin@vsp.local'"),
    emptyArrays: t.match(/var (USERS|ROLES)=\\[\\];/g)?.length || 0,
    hasUX: t.includes('VSPUXState.skeleton'),
    hasLoadRoles: t.includes('async function loadRoles')
  }))

Expected: marker true, mockGone true, emptyArrays=2, hasUX true, hasLoadRoles true.

Visual test: click Users in sidebar → skeleton 6 rows → real users from DB (or
empty state). Tab Roles → 4 default roles render.

## Rollback
bash patches/feat/05-users-uxstates/rollback.sh

## Verified state (dry-run)
- File: 835 -> 854 lines (+19: new loadUsers + loadRoles + DEFAULT_ROLES fallback)
- 6 patch steps reported success
- AUDIT + API_KEYS preserved (intentional)
- 4 VSPUXState integrations: skeleton, empty, error, typeof guard
