# SOAR Marketplace — bootstrap batch 1

20 ready-to-import playbook templates for VSP SOAR engine.

- **VN-specific (10):** CMC SOC, Bộ TT&TT TT13/2023, Viettel Cloud,
  VNCERT IOC feeds, NHNN TT09 banking, Zalo OA, gov.vn cert monitor,
  WAF blocklist sync, secret rotation, daily SOC digest
- **International (10):** Slack IR channels, AWS GuardDuty,
  PagerDuty escalation, GitHub secret revoke, CrowdStrike containment,
  SOC2 evidence, Sentinel forwarding, phishing triage,
  Cloudflare rate-limit, CISA KEV prioritization

Schema: see `_SCHEMA.md`. Index + categories: see `manifest.yaml`.

## Import — single template

```bash
TOKEN=$(curl -s -XPOST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@agency.gov","password":"..."}' | jq -r .token)

# YAML → JSON (yq) → POST
yq -o json vn-01-cmc-soc-handoff.yaml | \
  curl -s -XPOST http://localhost:8921/api/v1/soar/playbooks \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d @-
```

## Import — bulk (all 20)

```bash
for f in *.yaml; do
  [ "$f" = "manifest.yaml" ] && continue
  echo "→ $f"
  yq -o json "$f" | curl -s -XPOST http://localhost:8921/api/v1/soar/playbooks \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d @- | jq '.id // .error'
done
```

## Secrets needed before enabling

Every `${SECRET_NAME}` ref must be defined in the secrets vault before
the playbook runs. Below is the consolidated list across all 20
templates — group by service:

### Slack / Teams
- `SLACK_BOT_TOKEN`        — Bot token (xoxb-...) for channel management
- `SLACK_SOC_WEBHOOK`      — Incoming webhook for #soc-*
- `SLACK_OPS_WEBHOOK`      — Incoming webhook for #ops-*
- `SLACK_DEVSEC_WEBHOOK`   — Incoming webhook for #devsec-*
- `SLACK_VULN_WEBHOOK`     — Incoming webhook for #vuln-mgmt
- `SLACK_SECURITY_WEBHOOK` — Incoming webhook for #security-alerts
- `SLACK_WORKSPACE`        — Workspace subdomain (e.g. acme for acme.slack.com)

### Ticketing
- `JIRA_API_TOKEN`         — Jira Cloud API token (basic auth)
- `JIRA_BASE_URL`          — Jira instance URL
- `GITHUB_APP_ID`          — GitHub App ID for issue/status creation
- `GITHUB_APP_KEY`         — GitHub App private key (PEM)

### Paging / SMS
- `PD_API_KEY`             — PagerDuty REST API key
- `PD_L1_SERVICE_ID`       — PD service ID for L1 oncall
- `PD_L2_SERVICE_ID`       — PD service ID for L2 oncall
- `PD_CISO_KEY`            — PD integration key for CISO alerts
- `PD_IR_KEY`              — PD integration key for IR team
- `PD_SERVICE_ID`          — Default PD service ID
- `PD_ESCALATION_POLICY_ID`— Escalation policy UUID
- `TWILIO_SID`             — Twilio account SID
- `TWILIO_TOKEN`           — Twilio auth token
- `TWILIO_FROM`            — Twilio sender number (E.164)
- `CISO_PHONE`             — CISO phone (E.164) for SMS
- `COMPLIANCE_OFFICER_PHONE`
- `CISO_EMAIL`             — CISO email for high-priority routing
- `COMPLIANCE_LEAD_EMAIL`

### Cloud providers
- `AWS_READONLY_ROLE`      — IAM role ARN for read-only enrichment
- `AWS_ROTATION_ROLE`      — IAM role for credential rotation
- `AWS_REVOKE_ROLE`        — IAM role for credential revocation
- `GCP_REVOKE_SA`          — GCP service account key (JSON, base64)
- `GCP_ROTATION_SA`        — GCP service account for rotation
- `AZURE_TENANT_ID`        — Azure AD tenant ID
- `AZURE_CLIENT_ID`        — Azure AD app client ID
- `AZURE_CLIENT_SECRET`    — Azure AD app client secret
- `AZURE_DCE_ENDPOINT`     — Sentinel Data Collection Endpoint URL
- `AZURE_DCR_ID`           — Sentinel Data Collection Rule immutable ID
- `M365_TENANT_ID`         — M365 tenant for eDiscovery purge
- `M365_CLIENT_ID`         — M365 app client ID
- `M365_CLIENT_SECRET`     — M365 app client secret
- `GSUITE_ADMIN_EMAIL`     — Workspace delegated admin
- `GSUITE_SA_KEY`          — Workspace service account key

### VN-specific
- `CMC_SOC_API_URL`        — CMC SOC API endpoint
- `CMC_SOC_API_KEY`        — CMC SOC API key
- `VIETTEL_CLOUD_API`      — Viettel Cloud API endpoint
- `VIETTEL_CLOUD_KEY`      — Viettel Cloud API key
- `VNCERT_FEED_URL`        — VNCERT IOC feed URL
- `VNCERT_API_KEY`         — VNCERT API key
- `BKAV_FEED_URL`          — BKAV threat feed URL
- `ZALO_OA_ID`             — Zalo Official Account ID
- `ZALO_OA_TOKEN`          — Zalo OA access token

### Other integrations
- `CROWDSTRIKE_API`        — Falcon API base
- `CROWDSTRIKE_CLIENT_ID`
- `CROWDSTRIKE_CLIENT_SECRET`
- `CLOUDFLARE_API_TOKEN`   — Scoped to zone WAF + rate-limit
- `CLOUDFLARE_ZONE_ID`
- `VIRUSTOTAL_API_KEY`     — VT lookups (premium tier recommended)
- `ABUSEIPDB_KEY`          — AbuseIPDB lookups
- `STRIPE_ADMIN_KEY`       — Stripe admin key for token revocation
- `AUDIT_SIGNING_KEY`      — Private key for SOC2 evidence signing

## Notes

- Playbooks ship with `enabled: true`. After import, **disable any
  template you haven't configured secrets for** to avoid runtime errors:
  `PATCH /api/v1/soar/playbooks/{id} {"enabled": false}`.
- `config:` blocks use YAML block-scalar syntax; the executor parses
  them per step type. Schema is intentionally loose to allow per-tenant
  customization.
- Conditional logic uses simple `expr:` strings and `only_if:` /
  `else_action:` keys — kept minimal for v1. Branching DAG is roadmap.
- All VN templates have Vietnamese-language message templates referenced
  by `template_vi:` or `subject_vi:`. Templates themselves live in
  `templates/notifications/` (not part of this batch).
