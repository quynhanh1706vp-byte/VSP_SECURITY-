# VSP Database Migrations

## Numbering

Migrations are numbered `NNN_<description>.sql` in execution order.

## Sequence

| # | File | Purpose |
|---|------|---------|
| 001 | `001_init.sql` | Initial schema (users, tenants, findings, runs) |
| 002 | `002_remediations_unique.sql` | Unique constraint on remediations |
| 003 | `003_mfa.sql` | MFA tables |
| 004 | `004_password_and_refresh.sql` | Password history + refresh tokens |
| 005 | `005_siem_tables.sql` | SIEM correlation tables |
| ~~006~~ | _(intentionally skipped)_ | See note below |
| 007 | `007_siem_indexes.sql` | SIEM performance indexes |
| 008 | `008_scheduler_tables.sql` | Scheduler/cron tables |
| 009 | `009_batch_tables.sql` | Batch scan tables |
| 010 | `010_add_cvss_to_findings.sql` | CVSS score column |
| 011 | `011_findings_dedup.sql` | Findings deduplication |
| 012 | `012_incidents_table.sql` | Incident response table |

## Note on 006

Migration `006` was reserved during early SIEM development but never
finalized. The numbering is preserved (skipping 006) to maintain stable
migration IDs across deployments. Do NOT add a 006 file retroactively —
it would conflict with deployed databases that already track migration
state.

If using `goose` or compatible migrate tools, the gap is handled
correctly (migrations are tracked by file name, not sequential index).

## Adding new migrations

Use the next sequential number (currently 013).
