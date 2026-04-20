# THREAT_MODEL.md Sync Patch

**Date:** 2026-04-20
**Reason:** Align STRIDE claims with actual code verified in Phase 4 audit.

## Patches required in `THREAT_MODEL.md`

### Patch 1 — Token in URL (line ~25, Spoofing section)

**Current:**
```markdown
| Token in SSE/WS URL | Removed ?token= from all URLs | OK |
```

**Replace with:**
```markdown
| Token in API URL | Backend rejects ?token= with HTTP 400 (cookie_session.go:51) | OK |
| Token in SSE URL | Frontend still uses ?token= on 2 sites; backend SSE endpoint currently accepts (bypass middleware); migration SEC-009 queued Sprint 4 | IN_PROGRESS |
```

---

### Patch 2 — XSS cookie claim (line ~23, Spoofing section)

**Current:**
```markdown
| Token theft via XSS | httpOnly cookie (CWE-312) | OK |
```

**Replace with:**
```markdown
| Token theft via XSS | Backend: HttpOnly+Secure+SameSite=Strict cookie ready (cookie_session.go). Frontend: 22 sites still use localStorage in index.html — migration SEC-007 queued Sprint 4 | IN_PROGRESS |
| Inline script XSS | CSP per-request nonce on all static HTML (csp.go); inline scripts receive nonce via template injection | OK |
```

---

### Patch 3 — Tenant isolation query count (line ~55, Information Disclosure)

**Current:**
```markdown
| Tenant data leak | tenant_id on 59/59 queries (audited) | OK |
```

**Replace with:**
```markdown
| Tenant data leak | tenant_id enforced on 82/92 queries (audit 2026-04-20). 10 remaining are internal-only updates (audit log hash chain, cron schedule timestamps, counter increments) audited in SD-0045. Defense-in-depth: add tenant_id to remaining 3 user-facing updates (scan_schedules, playbooks, remediation_comments) queued Sprint 4 | PARTIAL |
```

---

### Patch 4 — MFA claim in Spoofing

Reference to MFA in STRIDE should match SECURITY.md — MFA support exists but
not enforced. Add under Elevation of Privilege:

**Add new row:**
```markdown
| Weak admin auth | TOTP available; policy enforcement pending (Sprint 4 PR #B) | IN_PROGRESS |
```

---

### Patch 5 — Add "Truth Status" legend

After the STRIDE tables, add:

```markdown
## Claim Verification Legend

| Status | Meaning |
|--------|---------|
| `OK` | Mitigation fully implemented AND enforced in code as of verification date |
| `IN_PROGRESS` | Partially implemented — backend ready, frontend migration pending |
| `PARTIAL` | Implemented for majority of cases; documented exceptions in SECURITY_DECISIONS.md |
| `PLANNED` | Mitigation designed but not yet implemented; roadmap reference required |
| `ACCEPTED_RISK` | Mitigation not planned; compensating controls documented |

**Verification cadence:** Re-audit claims quarterly. Next audit: 2026-07-20.
```

---

## Rationale

The previous THREAT_MODEL.md listed all 30+ items as `OK`. After code audit:
- 3 items were actually IN_PROGRESS (token URL, localStorage, MFA)
- 1 item had inflated claim (59/59 vs actual 82/92)
- Query count inconsistent with codebase (92 WHERE queries exist, not 59)

Marking realistic status matters for:
1. **Legal:** SECURITY.md + THREAT_MODEL.md are referenced in customer
   contracts. Overclaims create breach liability.
2. **Audit:** 3PAO assessor reading mismatched claims auto-fails the review.
3. **Team honesty:** devs reading "OK" on work they know is incomplete loses
   trust in the document.
4. **DSOMM Culture & Org / Design dimension:** Level 3 requires documented
   threat model synced with implementation.
