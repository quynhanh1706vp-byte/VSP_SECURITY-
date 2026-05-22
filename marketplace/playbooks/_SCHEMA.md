# Playbook YAML schema (v1)

Imported via `POST /api/v1/soar/playbooks` — body matches the YAML below
1:1 (YAML parsed → JSON payload).

```yaml
id: pb-<slug>                    # string, unique
name: <human readable name>      # string
description: <one-line summary>  # string
trigger: <event>                 # enum: gate_fail | critical_finding |
                                 #       sla_breach | secret_detected | manual
sev_filter: <severity>           # enum: any | CRITICAL | HIGH
enabled: true                    # bool
tags: [vn, soc, compliance]      # list[string], free-form
steps:
  - type: <step_type>            # enum: condition | enrich | block |
                                 #       ticket | notify | remediate
    name: <step name>            # string
    desc: <one-line description> # string
    config: |                    # YAML block-scalar; opaque to engine,
      key: value                 # parsed by the corresponding executor
      foo: ${SECRET_NAME}        # ${...} → resolved from secrets vault
```

## Secrets refs convention

Use `${SECRET_NAME}` in `config:` block-scalars. The executor resolves
them from the secrets vault before dispatching. Example:

```yaml
config: |
  webhook_url: ${SLACK_SECURITY_WEBHOOK}
  ping: "@security-oncall"
```

## Step type cheatsheet

| type       | executor handles                              |
|------------|-----------------------------------------------|
| condition  | gate / severity / field-match guard           |
| enrich     | NVD/OSV/EPSS/KEV lookup, asset metadata join  |
| block      | CI status (GitHub/GitLab), pipeline halt      |
| ticket     | Jira/PagerDuty/GitHub issue create            |
| notify     | Slack/Teams/Discord/Email/SMS                 |
| remediate  | auto-assign, auto-close, ACL fix, key rotate  |

## Trigger semantics

- `gate_fail`        — scan run finishes with gate=FAIL
- `critical_finding` — any new finding with severity=CRITICAL
- `sla_breach`       — finding past SLA window without remediation
- `secret_detected`  — gitleaks/trufflehog match on protected branch
- `manual`           — only invokable via UI / `POST /soar/runs`

## Severity filter semantics

- `any`      — fire regardless of finding severity
- `CRITICAL` — fire only when at least one CRITICAL finding present
- `HIGH`     — fire when severity ≥ HIGH (CRITICAL or HIGH)
