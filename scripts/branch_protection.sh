#!/usr/bin/env bash
# branch_protection.sh — apply VSP's branch protection rules to a
# GitHub repo via the API.
#
# Idempotent — safe to re-run after every release / quarterly review
# to ensure no one quietly relaxed the rules.
#
# Required:
#   GITHUB_TOKEN  — personal access token or fine-grained PAT with
#                   `administration:write` on the target repo
#   GH_OWNER      — e.g. vsp-platform
#   GH_REPO       — e.g. vsp
#   GH_BRANCH     — branch to protect (default: main)
#
# What it enforces:
#   • Required pull-request review (≥1 approval)
#   • CODEOWNERS approval required
#   • Status checks must pass (Scorecard + KPI Sanity Gate)
#   • Linear history required (no merge commits)
#   • Signed commits required
#   • Dismiss stale reviews on new commits
#   • Force-push disabled
#   • Branch deletion disabled
#   • Admins included (no bypass for admins)

set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN env var required}"
: "${GH_OWNER:?GH_OWNER env var required}"
: "${GH_REPO:?GH_REPO env var required}"
GH_BRANCH="${GH_BRANCH:-main}"

api="https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/branches/${GH_BRANCH}/protection"

echo "Applying branch protection to ${GH_OWNER}/${GH_REPO}@${GH_BRANCH}…"

# JSON payload — see https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection
payload=$(cat <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "OpenSSF Scorecard / Scorecard analysis",
      "KPI Sanity Release Gate / sanity"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "required_signatures": true
}
EOF
)

http_code=$(curl -sS -o /tmp/branch-protect.out -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -H "Content-Type: application/json" \
  -d "${payload}" \
  "${api}")

if [[ "${http_code}" != "200" ]]; then
  echo "FAILED — HTTP ${http_code}" >&2
  cat /tmp/branch-protect.out >&2
  exit 1
fi

echo "OK — branch protection applied. Verify in GitHub Settings → Branches."

# Print a confirmation digest for the audit log
jq -r '
  "  • required PR review: " + (.required_pull_request_reviews.required_approving_review_count|tostring) + " approval(s), CODEOWNERS=" + (.required_pull_request_reviews.require_code_owner_reviews|tostring) +
  "\n  • required signatures: " + (.required_signatures.enabled|tostring) +
  "\n  • required linear history: " + (.required_linear_history.enabled|tostring) +
  "\n  • force push allowed: " + (.allow_force_pushes.enabled|tostring) +
  "\n  • required status checks: " + ((.required_status_checks.contexts // []) | join(", "))
' /tmp/branch-protect.out
