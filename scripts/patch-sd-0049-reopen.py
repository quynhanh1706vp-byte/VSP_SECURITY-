#!/usr/bin/env python3
"""
patch-sd-0049-reopen.py

Rewrites the SD-0049 section in docs/SECURITY_DECISIONS.md from "RESOLVED"
(which was false) to "OPEN (REOPENED)" with evidence.

Run from repo root:
    python3 scripts/patch-sd-0049-reopen.py

Idempotent: safe to run multiple times (checks if already reopened).
"""

import re
import sys
from pathlib import Path


def main():
    path = Path('docs/SECURITY_DECISIONS.md')
    if not path.exists():
        print(f"ERROR: {path} not found")
        sys.exit(1)

    content = path.read_text()

    # Idempotency check
    if '(REOPENED 2026-04-21)' in content:
        print("SD-0049 already reopened. No changes needed.")
        return

    # Find the SD-0049 section
    start_marker = "## SD-0049 — CI suspended due to GitHub Actions billing"
    start_idx = content.find(start_marker)
    if start_idx == -1:
        print(f"ERROR: Could not find SD-0049 header")
        sys.exit(1)

    # Find end — either "### Related" (if present as part of section)
    # or next "## SD-" header
    end_idx = -1

    # Try to find "### Related" within reasonable distance
    related_idx = content.find("### Related", start_idx)
    if related_idx != -1 and related_idx - start_idx < 8000:
        # Find end of Related block — next ## or end of file
        after_related = content[related_idx:]
        next_section = re.search(r'\n## [A-Z]', after_related)
        if next_section:
            end_idx = related_idx + next_section.start() + 1
        else:
            end_idx = len(content)

    # Fallback: find next ## SD- section after start
    if end_idx == -1:
        m = re.search(r'\n## SD-', content[start_idx + 5:])
        if m:
            end_idx = start_idx + 5 + m.start() + 1
        else:
            end_idx = len(content)

    # Build new section
    new_section = '''## SD-0049 — CI suspended due to GitHub Actions billing (REOPENED 2026-04-21)

**Status:** OPEN (mis-closed then reopened with evidence)
**Severity:** P1 (downgraded from P0 — local-ci.sh fallback sustainably works)
**Detected:** 2026-04-13
**Mis-closed:** 2026-04-21 in commit dd5349e (closure claimed without verification)
**Reopened:** 2026-04-21 after audit found 3 latest CI runs still fail in 4-5s
**Duration:** 8+ days (still ongoing)

### What happened

GitHub Actions refused to start any job on repository `quynhanh1706vp-byte/VSP_SECURITY-`:

> "The job was not started because recent account payments have failed or your
> spending limit needs to be increased."

All five jobs complete in ~3-5 seconds with `failure` conclusion and empty logs.
No step in the workflow actually runs. The annotation is only visible via
`gh api /check-runs/{id}/annotations` — not in default `gh run view --log-failed`.

### Why it was mis-closed

Commit dd5349e documented SD-0049 as CLOSED with three false claims:

- "Updated payment method in GitHub billing settings"
- "Pushed empty commit to re-trigger CI"
- "Verified 5 jobs ran successfully with non-empty logs"

**None of these actually happened.** The closure doc was drafted anticipating
a user-side fix that did not occur. This is a meta-rule violation: the very
rule born from SD-0049 (evidence-gated closure) was broken by SD-0049's own
closure entry. Ironic and worth documenting as a lesson for future SD entries.

### Current evidence (reopen audit 2026-04-21)

Ran `gh run list --limit 3` after Sprint 5 Day 1 merge:

```
completed  failure  Sprint 5 Day 1 scaffold   main    push  5s  07:38:00Z
completed  failure  Sprint 5 [WIP] Day 1      sprint5/ PR    4s  07:32:08Z
completed  failure  Sprint 4 — SEC-005b+006   main    push  4s  03:46:07Z
```

3 consecutive runs on 3 different branches fail in 4-5s. This matches
exactly the billing outage pattern the original SD-0049 documented.

### Mitigation (currently working)

Not a fix, but sustainable workaround:

- `scripts/ci/local-ci.sh` runs 5 equivalent jobs locally in 30-100s.
- All 3 PRs merged 2026-04-21 (#25, #26, #27) used `--admin` bypass
  with local-ci evidence in commit messages.
- Pre-commit hooks catch most issues before push.
- Pre-push hook runs local-ci automatically for protected-branch pushes.

Why this works for now:

- Single-developer team, no external contributors requiring CI.
- local-ci is a strict superset of GitHub Actions checks.
- Security scans (gitleaks, govulncheck) run in local-ci with same tools.

Why this is not sufficient long-term:

- Branch protection cannot enforce required checks without live CI.
- External contributors would have no CI signal.
- SAST (Semgrep cloud) still runs as separate integration but not gated.

### Required to actually close this SD

1. User resolves billing at https://github.com/settings/billing/spending_limit
2. Trigger run: `gh workflow run ci.yml --ref main`
3. Verify ALL 5 jobs complete with non-empty logs and `success` conclusion
4. Update this section: status CLOSED, add resolution commit hash, evidence
5. Re-enable branch protection requirement in separate PR

### Lessons learned

1. **"Fail fast with empty log" = billing/permissions, not code.** A job that
   completes in under 10 seconds with no log output is almost never a code
   problem. Check `annotations` API first.
2. **Document annotation API usage.** `scripts/ci/diagnose-ci.sh` queries
   `/check-runs/{id}/annotations` as first step.
3. **Evidence-gated closure applies to SD entries themselves.** Writing
   RESOLVED with fabricated evidence creates false confidence and a false
   audit trail. The meta-rule only works if it applies recursively.
4. **Anticipation is not verification.** Drafting closure before the
   resolution step completes is a common anti-pattern. Keep two markers:
   `draft-closed` (pending verification) vs `closed` (evidence attached).

### Related

- `scripts/ci/local-ci.sh` — fallback CI gate
- `scripts/ci/diagnose-ci.sh` — billing-aware CI diagnostic
- `scripts/ci/pre-push-hook.sh` — protected-branch guard
- dd5349e — original mis-closure commit (rolled into f0d700a)

'''

    new_content = content[:start_idx] + new_section + content[end_idx:]
    path.write_text(new_content)

    print(f"SD-0049 rewritten:")
    print(f"  Old length: {end_idx - start_idx} chars")
    print(f"  New length: {len(new_section)} chars")
    print(f"  Status: CLOSED -> OPEN (REOPENED)")


if __name__ == '__main__':
    main()
