# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.12.x | YES |
| v0.11.x | YES (security fixes only) |
| < v0.11 | NO |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

### Contact

- Email: soc@agency.gov
- PGP key: https://vsp.agency.gov/.well-known/security.txt
- Response time: 48 hours

### Process

1. Email soc@agency.gov with subject: `[VSP SECURITY] <brief description>`
2. Include: affected version, reproduction steps, potential impact
3. We will acknowledge within 48 hours
4. We target patches within 7 days for critical, 30 days for high

## Security Measures

- All endpoints authenticated via httpOnly cookie (no XSS token theft)
- Rate limiting on all auth endpoints
- MFA required for admin accounts
- JWT tokens rotated every 90 days (see docs/JWT_ROTATION_RUNBOOK.md)
- SBOM published with each release
- Trivy container scanning in CI
- govulncheck + gosec in CI pipeline
- Full STRIDE threat model: THREAT_MODEL.md

## Known Limitations

- No WAF in front of gateway (planned)
- Vault integration pending (currently env vars)

## Hall of Fame

Responsible disclosures acknowledged here.
