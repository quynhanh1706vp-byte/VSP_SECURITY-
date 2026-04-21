# Security Policy

VSP (Vietnamese Security Platform) takes security seriously. This document describes how to report vulnerabilities, what versions we support, and our commitments to researchers who help us improve.

## Supported versions

| Version     | Status            | Security fixes | End of life |
| ----------- | ----------------- | -------------- | ----------- |
| 1.4.x       | ✅ Current (GA)    | Yes            | TBD         |
| 1.3.x       | ✅ Maintained      | Yes — critical only | 2026-10-31 |
| 1.2.x       | ⚠️  Deprecated     | No             | 2026-04-30  |
| < 1.2       | ❌ End of life     | No             | Ended       |

Only versions marked **Current** or **Maintained** receive security patches. Run `vsp version` to check the version you are on; upgrade instructions are in `docs/upgrade.md`.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email: `security@vsp.vn`
PGP key: [vsp-security-pubkey.asc](./.well-known/vsp-security-pubkey.asc)
Key fingerprint: `A1B2 C3D4 E5F6 7890 1234  5678 90AB CDEF 1234 5678`

When reporting, please include:

1. **Description** — what the vulnerability is, in one paragraph.
2. **Impact** — what an attacker can do (read data, RCE, DoS, privilege escalation, etc.), and which roles/endpoints are affected.
3. **Reproduction steps** — exact commands, requests, or UI clicks that trigger it. A minimal PoC is ideal.
4. **Affected versions** — which version(s) you tested against. Commit SHA if possible.
5. **Your contact info** — for follow-up, credit, and bounty (if applicable).

You will receive an acknowledgement within **2 business days**. If you do not, please check whether your email was rejected by SPF/DMARC and retry from another address.

## Our commitments to you

- **Triage within 5 business days.** We classify the report as Critical / High / Medium / Low / Not-a-vulnerability and tell you which.
- **Fix SLA** (from date of triage):
  - Critical: 14 days
  - High: 30 days
  - Medium: 60 days
  - Low: 90 days
- **Public disclosure** happens either when a fix ships or after **90 days**, whichever comes first, per industry-standard responsible disclosure. If you need extra time, tell us — we will usually agree.
- **CVE assignment.** We request CVEs via GitHub Security Advisories for every High/Critical issue that affects a released version.
- **Credit.** If you want public credit, we list you on the Hall of Fame below and in the CVE advisory. If you prefer to remain anonymous, say so.
- **No legal threats.** Good-faith security research is explicitly authorized against `*.vsp.vn` and the code in this repository. See Safe Harbor below.

## Scope

### In scope

- The code in this repository (`main` branch and released tags).
- VSP-managed production domains: `*.vsp.vn`, `api.vsp.vn`, `docs.vsp.vn`.
- Official container images published to our registry.
- Helm charts in `deploy/helm/`.

### Out of scope

- **Social engineering** of VSP staff, customers, or partners.
- **Physical attacks** against VSP offices or data centers.
- **Denial-of-service testing** against production — use a staging environment, or ask first.
- **Customer-operated deployments.** A self-hosted VSP instance belongs to the customer; report issues with their own configuration to them. Issues in our code that enabled the misconfiguration are in scope.
- **Third-party dependencies** — report upstream, then let us know so we can pin or patch.
- **Known-issues tracker items.** Check `docs/known-issues.md` and open GitHub issues with the `security-known` label before reporting.
- **Theoretical issues without a working PoC** (e.g., "your version of X library has a CVE but we cannot show exploitation").

## Safe Harbor

We will not pursue legal action, or support any third party in doing so, against researchers who:

1. Make a good-faith effort to avoid privacy violations, degradation of user experience, disruption to production, and destruction of data.
2. Only interact with accounts they own or have explicit permission to test.
3. Report the vulnerability promptly and do not disclose it publicly before we have had a reasonable chance to fix it.
4. Do not exfiltrate data beyond the minimum necessary to demonstrate the vulnerability.

If you are unsure whether a specific test is acceptable, email us before trying it.

## What gets a CVE

We request CVE assignment for any issue meeting **any** of:

- Authenticated or unauthenticated remote code execution.
- Authentication bypass or privilege escalation crossing a trust boundary.
- Arbitrary data read/write that crosses a tenant boundary.
- Cryptographic weakness in signing, session, or secret-handling paths.
- Supply-chain compromise (signing key, build pipeline, published artifact).

Misconfigurations in customer-operated deployments do not get a CVE unless the default configuration is insecure.

## Public Advisories

Historical advisories are published at:
`https://github.com/vsp-org/vsp/security/advisories`

Each advisory includes: CVSS v3.1 score, affected versions, fixed version, workarounds if any, and credit.

## Security Hall of Fame

Researchers who have responsibly disclosed vulnerabilities to us:

_(This section is populated as valid reports come in. If you want to be listed, say so in your initial report.)_

| Name / Handle | Advisory  | Year |
| ------------- | --------- | ---- |
| _(empty)_     |           |      |

## Security features & certifications

For a list of security features VSP ships with (Zero Trust pillars, RASP, SBOM signing, OSCAL export, CIRCIA reporting, Vietnam national standards mapping, etc.), see `FEATURE_INVENTORY.md`.

Current compliance posture is documented in `docs/dsomm/` (DSOMM self-assessment) and `docs/compliance-summary.md`.

## This policy

This policy is published per CISA's "Secure by Design" pledge and follows RFC 9116. It is reviewed quarterly by the Security team and VP of Engineering. Latest version always lives at:

- `https://github.com/vsp-org/vsp/blob/main/SECURITY.md`
- `https://vsp.vn/.well-known/security.txt` (machine-readable pointer)

**Last reviewed:** 2026-04-21
**Next review:** 2026-07-21
