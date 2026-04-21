# VSP Governance — Quick Start

## Tuần này (Sprint 1 P0)

```bash
# Bước 1: Setup hooks locally (1 phút)
git config core.hooksPath .githooks

# Bước 2: Apply branch protection (cần gh CLI auth)
gh api -X PUT repos/quynhanh1706vp-byte/VSP_SECURITY-/branches/main/protection \
  --input .github/branch-protection.yml

# Bước 3: Enable signed commits
git config --global commit.gpgsign true

# Bước 4: Test ui-hygiene gate local
bash scripts/ui-hygiene-budget.sh

# Bước 5: Test demo-data gate
VSP_ENV=production bash scripts/demo-data-check.sh

# Bước 6: Mở postmortem cho SD-0049
cp docs/postmortems/TEMPLATE.md docs/postmortems/SD-0049.md
# Edit, rồi commit
git add docs/postmortems/SD-0049.md
git commit -m "docs(security): SD-0049 postmortem — billing outage root cause"
```

## Sau đó

- Sprint 2: chạy codemod innerHTML (`node codemod/innerHTML-to-safe.js panels/ --dry-run`)
- Sprint 3: Supply chain (cosign + SLSA) — docs sẽ add sau
- Sprint 4: Testing + OTel — docs sẽ add sau
- Sprint 5: DAST + DORA — docs sẽ add sau

## Files created by bootstrap

```
.github/
├── CODEOWNERS
├── branch-protection.yml
└── workflows/
    ├── ui-security-gate.yml
    └── incident-postmortem-gate.yml

.githooks/
└── commit-msg

scripts/
├── ui-hygiene-budget.sh
└── demo-data-check.sh

codemod/
└── innerHTML-to-safe.js

docs/
├── governance/
│   ├── README.md                    (this file)
│   ├── BRANCH_PROTECTION.md
│   ├── INCIDENT_LIFECYCLE.md
│   └── UI_HARDENING.md
└── postmortems/
    └── TEMPLATE.md
```
