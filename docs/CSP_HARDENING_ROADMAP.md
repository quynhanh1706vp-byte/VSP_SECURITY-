# CSP Hardening Roadmap — VSP-CSP-001

This document tracks the multi-phase effort to harden the Content Security
Policy of the VSP gateway. It is referenced by the following commits and
must be kept up to date:

- `e16271f` — fix CSP nonce Sprintf + fail-closed RNG (Commit 1)
- `bf5f532` — close wildcard backdoor on panel routes (Commit 2a)
- `0444137` — restore nonce in strict policy (Commit 2b)
- `7228c6f` — hotfix: strict = PanelCSP while inline handlers remain (Commit 2c)

## Background

Before this effort, the gateway served the following policy to
`/panels/*`, `/static/panels/*`, and `/p4`:

    default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;
    script-src * 'unsafe-inline' 'unsafe-eval';
    style-src * 'unsafe-inline';
    connect-src *;
    frame-ancestors *;

This is functionally equivalent to having no CSP at all. It was installed
as a short-term workaround for inline event handlers present in the panel
HTML and was never removed.

## Phase 1 — Close the wildcard backdoor (DONE)

Goal: eliminate wildcards and 'unsafe-eval' from every route the gateway
serves, while keeping 'unsafe-inline' so that existing inline event
handlers continue to work. No UI regression.

Delivered:

- PanelCSP() and IsPanelPath() helpers in internal/api/middleware/csp.go.
  Single source of truth for panel CSP.
- Nonce generation still active; InjectNonceIntoHTML still runs on
  index.html. The nonce is not currently enforced in the CSP header
  (see Phase 2), but is ready for activation.
- p4ResponseWriter removed. /static/panels/* and /panels/* no longer
  override middleware CSP.
- cmd/soc-shell/main.go wildcard CSP strings replaced with
  vspMW.PanelCSP() (soc-shell production runs a separate Python proxy;
  this Go source is kept consistent for audit).
- frame-ancestors 'self', object-src 'none', base-uri 'self',
  form-action 'self' active on all routes.
- X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
  Permissions-Policy set uniformly via setCommonSecurityHeaders().

Post-Phase 1 header:

    default-src 'self';
    script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net;
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com;
    font-src 'self' https://fonts.gstatic.com;
    img-src 'self' data: blob:;
    connect-src 'self' wss: ws: https://api.anthropic.com https://cdn.jsdelivr.net;
    frame-src 'self'; frame-ancestors 'self'; object-src 'none';
    base-uri 'self'; form-action 'self';

## Phase 2 — Refactor inline handlers, restore nonce enforcement

Goal: remove 'unsafe-inline' from script-src by refactoring all inline
event handlers and inline <script> bodies in HTML to external modules
or addEventListener-based delegation. Once the count reaches 0, the
strict nonce-based policy can be reinstated for /.

### Baseline (as of Commit 2c)

Total inline event handlers across all HTML: **753**

Per-file breakdown:

| File                                     | Handlers | Sprint |
|------------------------------------------|---------:|--------|
| static/index.html                        |      241 | S5     |
| static/panels/p4_compliance.html         |       75 | S4     |
| static/panels/sw_inventory.html          |       43 | S3     |
| static/panels/ai_analyst.html            |       40 | S3     |
| static/panels/settings.html              |       29 | S2     |
| static/panels/cicd.html                  |       29 | S2     |
| static/panels/integrations.html          |       28 | S2     |
| static/panels/incident_response.html     |       28 | S2     |
| static/panels/software_risk.html         |       24 | S2     |
| static/panels/users.html                 |       21 | S1     |
| static/panels/scheduler.html             |       20 | S1     |
| static/panels/log_pipeline.html          |       18 | S1     |
| static/panels/assets.html                |       18 | S1     |
| static/panels/soar.html                  |       14 | S1     |
| static/panels/oscal.html                 |       13 | S1     |
| static/panels/correlation.html           |       13 | S1     |
| static/panels/threat_hunt.html           |       12 | S1     |
| static/panels/threat_intel.html          |       10 | S1     |
| static/panels/vuln_mgmt.html             |        8 | S1     |
| static/panels/ueba.html                  |        8 | S1     |

### Sprint plan

- S1 — Small panels (<=21 handlers each, 137 total, 11 panels).
  Establish delegator pattern. Prove it works on varied panel types.
- S2 — Medium panels (settings, cicd, integrations, incident_response,
  software_risk — 138 handlers).
- S3 — Large panels (sw_inventory, ai_analyst — 83 handlers).
- S4 — Largest panel (p4_compliance — 75 handlers).
- S5 — Main UI (index.html — 241 handlers, ~44 inline <script> blocks).
  When S5 lands, re-enable strict nonce policy in CSPNonce for non-panel
  routes.

Each sprint must:

1. Refactor handlers in the target file(s).
2. Update the baseline in docs/csp_handler_baseline.txt.
3. Confirm the CI handler-baseline guard passes.
4. Confirm no new CSP violations in the browser console on a full UI
   walkthrough (login -> dashboard -> every panel tab).

### Migration tool: static/js/vsp-actions.js

An event-delegation helper has been prepared to automate the inline
handler migration. It converts `onclick="expr"` → `data-vsp-click="expr"`
and attaches a single document-level listener that evaluates the
expression with `this` bound to the element and `event` in scope.

**Trade-off:** the current implementation uses `new Function()` to
preserve inline expression syntax (not just function names). This
requires `'unsafe-eval'` in `script-src`, which Phase 1 explicitly
removed. Two paths forward for Phase 2:

1. **Registry pattern (preferred):** convert each `data-vsp-click="foo(1)"`
   call-site to `data-vsp-action="foo" data-vsp-args="[1]"`, looking up
   named handlers from a window-scoped registry. Removes the need for
   `new Function()` entirely. Higher up-front cost but keeps Phase 1
   invariants intact.

2. **Two-step migration:** temporarily re-enable `'unsafe-eval'`
   during Phase 2.1 (strictly less harmful than today's wildcard and
   `'unsafe-inline'` combination), then drop it in Phase 2.2 after the
   registry conversion is complete.

Decision required before Phase 2 Sprint 1 begins.

### Ratchet-down policy

The CI guard (csp-guard.yml) enforces that the total handler count
**never increases**. New inline handlers in PRs are rejected at review
time. Any decrease is accepted and the baseline file is updated in the
same PR that performs the refactor.

## Phase 3 — Defense in depth

After Phase 2:

- Remove 'unsafe-inline' from style-src (requires refactoring inline
  style="" attributes — may be deferred or accepted as residual risk
  depending on threat model).
- Consider 'strict-dynamic' in script-src to eliminate the CDN whitelist
  (tighter but requires all scripts to carry the nonce and chain-load
  via DOM; no <script src="https://unpkg.com/..."> tags).
- Add CSP violation reporting endpoint (report-to / report-uri) and wire
  into SIEM for monitoring attempted XSS.

## Framework mapping

- NIST SSDF PS.1 (Protect Software from Unauthorized Access) — backdoor
  removed in Phase 1.
- NIST SSDF PW.4 (Reuse Existing Well-Secured Software Components) —
  PanelCSP() / setCommonSecurityHeaders() helpers reused by gateway +
  soc-shell.
- NIST SSDF PW.8 (Configure Software to Have Secure Settings by
  Default) — hardened CSP baseline in Phase 1.
- NIST SSDF RV.2 (Assess, Prioritize, and Remediate Vulnerabilities) —
  CI guard + ratchet baseline in Phase 1; handler refactor in Phase 2.
- OWASP SAMM Secure Build Level 2 — automated policy enforcement via CI
  guards.

## Ownership

- Phase 1: complete, sign-off after post-deploy smoke test.
- Phase 2 Sprint 1: open. Assign to first available frontend engineer.
- Phase 3: backlog.

Changes to this document require review by Security Engineering.
