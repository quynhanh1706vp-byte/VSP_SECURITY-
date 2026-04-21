# VSP Branch Protection Policy

**Owner**: Security Lead
**Applies to**: `main` branch of `VSP_SECURITY-` repository
**Review cadence**: quarterly

## Rules (enforced via GitHub)

1. **2 approving reviews required**, 1 must be a CODEOWNER
2. **Signed commits required** (GPG hoặc SSH signing)
3. **Linear history** — rebase/squash only, no merge commits
4. **Admin bypass disabled** — `enforce_admins: true`
5. **Status checks must pass**: `local-ci`, `ui-security-gate`, `incident-postmortem-gate`, `security-scan`
6. **Direct push blocked** — all changes via PR
7. **Force push disabled**, branch deletion disabled
8. **Stale reviews dismissed** when new commits push

## When revert is needed

**Không được** `git revert` thẳng lên main. Quy trình:

```bash
# 1. Tạo revert branch
git checkout -b revert/COMMIT_SHA main

# 2. Revert local
git revert COMMIT_SHA --no-edit

# 3. Sửa commit message: phải có SD-XXXX ref
git commit --amend

# 4. Push branch và mở PR
git push origin revert/COMMIT_SHA
gh pr create --title "revert: ..." --body "Reverts COMMIT_SHA. Reason: ..."

# 5. PR phải có:
#    - 2 reviewers approve
#    - Link tới SD-XXXX hoặc issue giải thích tại sao revert
#    - status checks pass
```

## Why enforce_admins matters

Nếu admin được bypass, branch protection thành security theater. Bằng chứng trong commit history VSP:

```
f7357b4 Reapply "docs(sprint-5): correct scope..."
348fbb3 Revert  "docs(sprint-5): correct scope..."  ← không rõ lý do
b9eafed docs(sprint-5): correct scope...
```

Commit 348fbb3 không có PR, không có review, không có SD reference. Với `enforce_admins: true` + `required_pull_request_reviews`, revert này không thể happen.

## Exceptions

**Emergency hotfix** (production down):
- Vẫn cần PR, nhưng có thể dùng "break-glass" procedure
- Admin có thể bypass status checks (không bypass review) nếu đăng ký trước
- Phải viết postmortem trong vòng 48h với SD-XXXX

**Bot commits** (release-bot, dependabot):
- Whitelist trong `restrictions.teams`
- Vẫn phải có status checks pass
- Vẫn phải sign commits

## Setup commands

```bash
# Apply branch protection
gh api -X PUT repos/quynhanh1706vp-byte/VSP_SECURITY-/branches/main/protection \
  --input .github/branch-protection.yml

# Enable git hooks locally
git config core.hooksPath .githooks

# Verify signed commits enabled
git config --global commit.gpgsign true
# hoặc với SSH:
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

## Audit

- Branch protection changes logged to audit panel (`/api/v1/audit`)
- Quarterly review: Security Lead kiểm tra `gh api repos/.../branches/main/protection` output
- Tracked as NIST control CM-3 (Configuration Change Control)
