# VSP Sigma Detection Rules

**Format:** [Sigma v2 spec](https://github.com/SigmaHQ/sigma)
**Maintained by:** Security Engineering
**Distribution:** open — customers can re-use these in their SIEM.

This directory contains detection rules in Sigma format for VSP-
specific security events. They serve two audiences:

1. **Internal SOC** — load into our correlation engine alongside the
   built-in rule set. Existing UEBA detects the same patterns
   (impossible_travel, brute_force, etc.); Sigma format makes them
   reusable in customer SIEMs.

2. **Customer SOC teams** — drop these into Splunk / Elastic / Sentinel
   / Chronicle / Kusto and correlate VSP audit_log with their broader
   network and host telemetry.

## Rule index

| File | Severity | MITRE ATT&CK |
|------|----------|--------------|
| [auth_brute_force.yml](auth_brute_force.yml) | medium | T1110 (Brute Force) |
| [impossible_travel.yml](impossible_travel.yml) | high | T1078.004 (Cloud Account) |
| [audit_chain_break.yml](audit_chain_break.yml) | critical | T1070.002 (Indicator Removal) |
| [supply_chain_tampered.yml](supply_chain_tampered.yml) | critical | T1554 (Compromise Software Supply Chain) |
| [dsr_erasure_token_brute.yml](dsr_erasure_token_brute.yml) | high | T1485 (Data Destruction) |

## Conversion to other SIEM formats

Use [pySigma](https://github.com/SigmaHQ/pySigma) or [sigmac](https://github.com/SigmaHQ/sigma) backend converters:

```bash
# Splunk SPL
sigma convert -t splunk -p splunk_sysmon detections/sigma/

# Microsoft Sentinel KQL
sigma convert -t sentinel detections/sigma/

# Elastic ECS / EQL
sigma convert -t elasticsearch -f eql detections/sigma/
```

## Contribution

Add a new rule:
1. Pick an unused id (`vsp00N`)
2. Follow the [Sigma rule structure](https://sigmahq.io/docs/basics/rules.html)
3. Reference the corresponding MITRE technique
4. List honest false positives
5. Open PR — CODEOWNERS will tag security@vsp.vn

When code changes invalidate a rule (e.g. a new audit action name),
update the rule in the same PR. CI will not lint the YAML for you,
but reviewers should run `sigma check` locally.
