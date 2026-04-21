# VSP Incident Lifecycle

**Owner**: Incident Commander (rotating)
**Reference**: NIST SP 800-61r2, ISO/IEC 27035

## States

```
  Detected → Triaged → Investigating → Mitigated → Resolved → Closed
     │          │            │             │           │
     └──────────┴────────────┴─────────────┴───────────┘
                        SLA clocks running
```

Rule khắc: **KHÔNG được transition `Resolved → Closed` nếu postmortem chưa publish.**

CI gate `incident-postmortem-gate` enforce rule này tự động.

## Severity ladder

| Severity | Criteria | Response time | Postmortem required |
|---|---|---|---|
| SEV-1 | Production down, data loss, auth bypass, compliance breach | 15 min | Yes (48h) |
| SEV-2 | Feature down, degraded performance, single-tenant impact | 1 hour | Yes (7 days) |
| SEV-3 | Minor bug, cosmetic, internal only | 1 business day | Optional |
| SEV-4 | Tracking only | N/A | No |

## SD-XXXX numbering

- Format: `SD-NNNN` (monotonically increasing)
- Assigned by SIEM correlation panel on detection
- Every security-impacting fix commit MUST reference an SD-ID

## Why this matters — SD-0049 case

Commit log cho thấy:
```
bb53769 docs(security): reopen SD-0049 — billing outage still active
```

SD-0049 đã bị close trước đó nhưng "billing outage still active" → close premature. Điều này vi phạm:
- NIST IR-4 (Incident Handling — incident eradication phải confirmed)
- CMMC IR.L2-3.6.1 (Establish incident-handling capability)

Với postmortem gate enforced:
- PR close SD-0049 đầu tiên sẽ **bị block** nếu không có `docs/postmortems/SD-0049.md`
- Postmortem forces "resolved = verified" conversation
- Premature close giảm đáng kể

## Roles during incident

| Role | Responsibility |
|---|---|
| Incident Commander (IC) | Overall coordination, decisions, stakeholder comms |
| Technical Lead | Debug, mitigate, implement fix |
| Communications Lead | Customer comms, status page, exec brief |
| Scribe | Timeline, evidence, Slack thread curator |

**SEV-1**: all 4 roles assigned, distinct people
**SEV-2**: IC + Tech Lead minimum
**SEV-3**: single on-call engineer

## Postmortem requirements (checklist)

- [ ] File tạo tại `docs/postmortems/SD-XXXX.md`
- [ ] Template từ `docs/postmortems/TEMPLATE.md` followed
- [ ] Timeline UTC, minute-accurate
- [ ] Root cause analysis (not just "human error")
- [ ] Action items với owner + deadline + ticket link
- [ ] Signed off by IC + Security Lead
- [ ] Reviewed in weekly security standup
- [ ] Action items tracked trong sprint board

## Automation hooks

1. **Detection**: SIEM correlation rule tạo incident → auto-assign SD-ID
2. **Triage**: UEBA anomaly score > threshold → page on-call
3. **Mitigation**: SOAR playbook auto-runs containment (if policy allows)
4. **Postmortem reminder**: day-2 cron posts Slack nag if SD-XXXX resolved but no .md
5. **Close gate**: PR với "close SD-XXXX" blocked bởi GH Action until .md exists
