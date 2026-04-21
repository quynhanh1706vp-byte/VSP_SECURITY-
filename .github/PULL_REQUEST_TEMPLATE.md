<!--
Thanks for contributing to VSP. Fill in the sections below.
PRs without a completed template will be asked for more info before review.
-->

## What and why

<!-- One paragraph. What does this PR change? Why now? -->

## Linked issue / ticket

<!-- Fixes #123 / Ref SD-0049 / Closes compliance gap X -->

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix
- [ ] Documentation only
- [ ] Refactor / dependency bump / repo hygiene
- [ ] CI / build / deployment

## Security review

- [ ] No new secrets or credentials added to the repo
- [ ] No new use of `innerHTML`, `eval`, `dangerouslySetInnerHTML`, or similar
- [ ] No new use of `localStorage` / `sessionStorage` for sensitive data (tokens, PII, keys)
- [ ] New external input is validated and/or sanitized
- [ ] New external dependencies have been scanned (`trivy` / `govulncheck`)
- [ ] Authentication and authorization paths are unchanged, OR reviewed by `@security-team`
- [ ] Threat model still applies, OR updated in `docs/threat-model.md`

If any box above is unchecked, explain why:

<!-- ... -->

## Testing

- [ ] Unit tests added or updated
- [ ] Coverage for changed files did not decrease
- [ ] Manual test steps documented below (if UI change)
- [ ] `make test` passes locally
- [ ] `make lint` passes locally

**Manual test steps:**
<!-- Only for UI or operational changes. Bullet list, reproducible. -->

## Compliance impact

- [ ] No change to any control implementation
- [ ] Changes a P4 / FedRAMP / CMMC / Vietnam national standards control → updated `docs/compliance/` and OSCAL SSP
- [ ] Changes audit-logged behavior → verified logs still redact PII

## Rollout & rollback

- [ ] No migration needed
- [ ] Migration needed → plan documented in description below
- [ ] Rollback strategy: <!-- one line -->

## Screenshots / recordings

<!-- For UI changes. Include before + after. -->

## Reviewer notes

<!-- Anything you want the reviewer to pay special attention to, or context they need. -->
