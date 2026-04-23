# CodeQL Triage — Issue #62

**Status:** Grooming stub (triage work pending Sprint 2)
**Owner:** Security team
**Created:** 2026-04-23 (Sprint 0 Task 2.2c)

---

## Scope

15 CodeQL alerts flagged by `security-and-quality` suite on the JavaScript
codebase. All alerts are **pre-existing** — present before Sprint 0, not
introduced by PR #61 (VSP-SEC-001) or PR #63 (JWT rotation).

**Evidence of pre-existing status:** PR #61 commit message explicitly
documents these as out-of-scope: *"15 pre-existing alerts (9 XSS + 2 CSRF
+ 2 unreachable + 2 XSS-through-exception) tracked in issue #62 for
Sprint 2 triage. NOT introduced by this PR."*

---

## Alert Counts by Category

| Category | Count | CodeQL Rule (expected) |
|----------|-------|------------------------|
| XSS (DOM-based) | 9 | `js/xss`, `js/xss-through-dom` |
| CSRF | 2 | `js/missing-csrf-protection` |
| Unreachable code | 2 | `js/unreachable-statement` |
| XSS via exception message | 2 | `js/xss-through-exception` |
| **Total** | **15** | |

Note: Exact rule IDs will be confirmed during export (§ Step 1 below).
23 `js/missing-origin-check` alerts were dismissed as false positives in
PR #61 and are **not** in this 15-count.

---

## Triage Workflow

### Step 1 — Export current alerts from GitHub

Data is not checked into the repo; must be pulled from GitHub Security tab.

```bash
# Prerequisite: gh CLI authenticated, security-events:read scope
gh api -X GET \
  "repos/$GITHUB_REPOSITORY/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | {
    number, rule: .rule.id, severity: .rule.security_severity_level,
    file: .most_recent_instance.location.path,
    line: .most_recent_instance.location.start_line,
    message: .most_recent_instance.message.text
  }' > codeql-alerts-$(date +%F).json

wc -l codeql-alerts-$(date +%F).json
```

Alternative (UI): GitHub → Security → Code scanning alerts → filter
`tool:CodeQL is:open` → export CSV.

### Step 2 — Classify each alert

For each alert, assign one of:

| Classification | Action |
|----------------|--------|
| **TRUE POSITIVE — exploitable** | File as P0/P1 bug, fix before next release |
| **TRUE POSITIVE — theoretical** | Fix opportunistically, track in backlog |
| **FALSE POSITIVE** | Dismiss in GitHub UI with reason, add suppression comment in code |
| **ACCEPTED RISK** | Document in `docs/known-issues.md`, require security-team sign-off |

### Step 3 — For each XSS alert (9 expected)

Check:
1. Is the sink actually reachable from untrusted input?
2. Is the input sanitized upstream (e.g., by `VSPOrigin.check`, CSP, or
   server-side validation)?
3. Does CSP (`default-src 'self'`, no `unsafe-inline`) mitigate it?
4. Is the code reachable in production, or only in dev-only panels?

CSP is the primary compensating control — document CSP coverage in the
triage entry for each alert.

### Step 4 — For each CSRF alert (2 expected)

Check:
1. Endpoint state-changing? GET-only endpoints are not CSRF-relevant.
2. CSRF token enforcement in `middleware/csrf.go`?
3. Exempt list (e.g., `/api/v1/software-inventory/report` per commit
   b7198fe) — is exemption justified?

### Step 5 — For each unreachable-code alert (2 expected)

Lowest priority. Delete the dead code. Low risk of regression.

### Step 6 — For XSS-via-exception (2 expected)

Check whether error messages containing user input are rendered into
DOM without escaping. Usually mitigated by:
- Generic error messages (`err.message = "Invalid request"`)
- `textContent` instead of `innerHTML` at render site

### Step 7 — Update tracking

For each alert triaged:
- Update this file with `(handle,classification,decision)` row
- Update `docs/known-issues.md` if accepted risk
- File GitHub issue per true positive with `security` label
- Dismiss false positives in UI with written justification

---

## Triage Results

**Populate after Step 1 export. Template:**

| # | Rule | File:Line | Classification | Decision | PR/Issue |
|---|------|-----------|----------------|----------|----------|
| 1 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| … | | | | | |

---

## Related

- `.github/workflows/security-deep.yml` — CodeQL CI config
- `docs/known-issues.md` — parent tracker (issue #62 entry)
- `THREAT_MODEL.md` § Known Limitations — STRIDE context
- PR #61 commit message — original alert breakdown
- `SECURITY.md` § Out of scope — why these are deferred
