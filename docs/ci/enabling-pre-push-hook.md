# Enabling the pre-push local CI hook

When GitHub-hosted CI is unavailable (ref SD-0049) or when you want faster
feedback than the round-trip to GitHub Actions, enable this hook to run the
same gate locally before every push to a protected branch.

## Install

```bash
cp scripts/ci/pre-push-hook.sh .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

## Usage

```bash
# Normal push to feature branch — hook skipped
git push

# Push to main/develop/release/* — hook runs local CI
git push

# Skip when genuinely needed (e.g., shipping a doc-only change during CI outage)
git push --no-verify
```

## When to bypass

The `--no-verify` bypass should be rare and auditable. If you bypass, add a
line to the commit message:

    git push --no-verify   # SD-0049 CI unavailable, bypass + documented

Then log in `docs/SECURITY_DECISIONS.md` under SD-0049-related activity.
