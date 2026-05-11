# Data Classification Matrix

Last reviewed: 2026-05-11

This document classifies every persisted data element in VSP per
FedRAMP RA-2, GDPR Article 32, and SOC 2 CC6.1. L66 parses this file —
PII columns referenced by handlers must appear here.

## Classification levels

| Level         | Examples                          | Handling                                     |
|---------------|-----------------------------------|----------------------------------------------|
| **Public**    | feature flags, OSS license names  | No protection required                       |
| **Internal**  | run IDs, finding rule IDs         | Tenant-scoped; audit reads optional          |
| **Confidential** | tenant slugs, user names       | Tenant-scoped; audit every access            |
| **Restricted (PII)** | email, phone, password_hash | Tenant-scoped + audit + encryption-at-rest + log-redaction |

## Column-level matrix

| Table                  | Column           | Classification | Notes                                       |
|------------------------|------------------|----------------|---------------------------------------------|
| `users`                | `email`          | Restricted (PII) | hashed to `email_hash` in zerolog access logs |
| `users`                | `pw_hash`        | Restricted     | bcrypt; never logged, never returned via API  |
| `users`                | `mfa_secret`     | Restricted     | AES-GCM at rest; only handler reads it       |
| `users`                | `phone`          | Restricted (PII) | optional; if set, redacted in logs            |
| `audit_log`            | `ip`             | Restricted (PII in EU) | retention-capped; hash for old rows  |
| `audit_log`            | `user_id`        | Confidential   | UUID — not PII on its own                    |
| `data_subject_requests`| `email`          | Restricted (PII) | erasure target; hashed before logging        |
| `data_subject_requests`| `confirm_hash`   | Restricted     | bcrypt-shaped; token is single-use            |
| `tenants`              | `slug`           | Confidential   | visible across tenant via /admin (admin role) |
| `tenants`              | `name`           | Confidential   | display name                                  |
| `playbook_secrets`     | `value_encrypted`| Restricted     | AES-GCM; key from VSP_REPO_KEY                |
| `playbook_secrets`     | `nonce`          | Confidential   | per-row nonce; not secret but unique          |
| `sessions` / refresh   | `session_token`  | Restricted     | opaque; treat as bearer credential            |
| `sessions` / refresh   | `refresh_token`  | Restricted     | opaque; treat as bearer credential            |
| `siem_webhooks`        | `secret_hash`    | Restricted     | HMAC key — hashed before persist              |
| `runs`                 | `rid`            | Confidential   | tenant-scoped run identifier                  |
| `runs`                 | `target_url`     | Confidential   | scan target — may include internal hosts      |
| `findings`             | `message`        | Confidential   | scanner output — may include internal paths   |
| `findings`             | `path`           | Confidential   | filesystem paths from scanner                 |

## Handling rules

- **Restricted columns** MUST be encrypted at rest when the column
  stores opaque tokens / secrets (mfa_secret, value_encrypted,
  refresh_token). Use `internal/crypto.AESGCM`.
- **Logging**: zerolog `.Str(field, raw)` calls for any Restricted
  column are L66.4 violations. Use `.Str(field + "_hash",
  sha256-prefix)` instead.
- **API responses**: Restricted columns NEVER round-trip in JSON
  responses unencrypted. The remediation status endpoint returns
  status / priority / assignee — not email_hash.
- **Audit trail**: any read of a Restricted column MUST emit an
  audit event with `action="READ_PII"` and the resource ID.
- **Retention**: ip addresses in audit_log past 365 days are
  hashed in-place via a maintenance job; original value is
  overwritten.

## Known un-tagged columns

Adding a new column with a sensitive-sounding name (`ssn`, `tax_id`,
`passport_no`, `national_id`, `dob`, `credit_card`) MUST be paired
with an entry above. L66.3 fails the build if any of these names
appear in a migration but aren't documented.

## Compliance mapping

- FedRAMP RA-2: data classification is documented + enforced
- GDPR Article 32: technical measures (encryption, redaction) listed
- SOC 2 CC6.1: logical access by classification level
- Vietnam PDPA Decree 13/2023: PII = email / phone (covered)
