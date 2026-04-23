# VSP Security Session — 2026-04-23

## PRs merged
- #69 SEC-009 client SSE + openapi.yaml (fa3003b)
- #70 SEC-009 soc-shell no-inject (d00e662)
- #72 SEC-009 WS dead fallback cleanup (64427a3)
- #73 SSE initSSE regression fix (d5f2356)
- #74 SEC-009 netcap/stream + p4 cookie auth (7961aa6)
- #75 SEC-009 remove dead TokenFromQuery (8ba7227)
- #77 SEC-006 OSCAL/Attestation over-mitigation fix (d83ed70)
- #78 SQL defense-in-depth ir_incidents (3f4700e)

## CodeQL alerts
- #61 go/sql-injection: durable code fix (map pattern) + dismissed
- #38 semgrep tainted-sql-string: dismissed (false positive with justification)

## Bugs discovered
- JWT stale: login-after-restart appeared as "loạt 401" — was really fresh-login issue
- SEC-006 over-mitigation: SEC-006 codemod blindly replaced innerHTML with textContent, 
  broke OSCAL + Attestation panels (rendering raw markup as text). Fixed with 
  innerHTML + escapeHtml() defense-in-depth pattern.

## Local infra
- .env with JWT_SECRET persistent (not committed) — fixes server-restart invalidates tokens

## Open gaps for next session
- CodeQL ~75 alerts still open (11 errors, 45 notes, 9 warnings after today's triage)
- Cookie name inconsistency: vsp_token (middleware.go) vs vsp_session (cookie_session.go)
- 15 CodeQL alerts remaining in issue #62 triage backlog  
- PR-10 candidate: command injection in report.go, pdf.go, report_executive.go
- PR-11 candidate: path injection 8 alerts (report/pdf handlers)
- SSDF panel test: Ctrl+Shift+R browser verify OSCAL/Attestation render correctly
