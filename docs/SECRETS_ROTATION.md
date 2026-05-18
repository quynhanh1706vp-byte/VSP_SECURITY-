# Secrets Rotation Policy

Last reviewed: 2026-05-11

This document defines the rotation cadence and accountability for every
secret category the VSP gateway depends on. The L62 ladder probe
parses this file — categories listed here must match the env vars
referenced in code.

## Rotation matrix

| Category          | Source                  | Cadence | Owner       | Last rotated |
|-------------------|-------------------------|---------|-------------|--------------|
| `JWT_SECRET`      | env var + secret mgr    | 90 days | platform    | 2026-05-11   |
| `DATABASE_URL`    | env var, sealed secret  | 90 days | platform    | 2026-05-11   |
| `REDIS_PASSWORD`  | env var, sealed secret  | 90 days | platform    | 2026-05-11   |
| `VSP_REPO_KEY`    | env var, KMS-backed     | 30 days | security    | 2026-05-11   |
| `CSRF_KEY`        | env var, derived        | 90 days | platform    | 2026-05-11   |
| `API_KEY` (per tenant) | user-managed via /admin/api-keys | per-tenant policy | tenant admin | varies |
| `WEBHOOK_SECRET`  | per-webhook, user-set   | per-tenant policy | tenant admin | varies |

## Trigger events for off-cycle rotation

- Employee with secret access leaves
- Suspected compromise (any of: secret in commit, secret in log, IDS hit)
- Major dependency CVE that touches the secret-bearing service
- Quarterly compliance review flags drift

## Procedure

1. Generate replacement via the secret manager (1Password CLI / Vault /
   Sealed Secrets — depending on env).
2. Update the env file / Kubernetes secret.
3. Restart the gateway and re-run L1 smoke + L31 JWT-attacks to confirm
   tokens authenticate under the new secret.
4. Update the "Last rotated" column above in the same PR.
5. Document the rotation event in the audit log via a manual
   `vsp-cli rotation log` entry.

## Notes

- `VSP_REPO_KEY` has the tightest cadence (30 days) because it
  encrypts the SOAR vault content; compromise blast radius is the
  full secret store.
- API keys are user-driven and don't appear in this matrix beyond the
  envelope row. The /admin/api-keys flow handles revocation +
  re-issuance independently.
