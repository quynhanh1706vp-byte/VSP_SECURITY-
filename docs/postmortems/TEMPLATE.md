# SD-XXXX — [Short Title]

<!--
Filename MUST match: docs/postmortems/SD-XXXX.md
CI gate `incident-postmortem-gate` sẽ block PR "close SD-XXXX" nếu file này không tồn tại.
-->

| Field | Value |
|---|---|
| Incident ID | SD-XXXX |
| Severity | SEV-1 / SEV-2 / SEV-3 |
| Status | Resolved / Monitoring / Closed |
| Detected | YYYY-MM-DD HH:MM UTC |
| Mitigated | YYYY-MM-DD HH:MM UTC |
| Resolved | YYYY-MM-DD HH:MM UTC |
| Duration | Xh Ym |
| Reporter | @username |
| Incident Commander | @username |
| Compliance Impact | FedRAMP / CMMC / ZT / none |

---

## 1. Summary

Một đoạn ngắn (3-5 câu) mô tả chuyện gì xảy ra, ảnh hưởng ai, hậu quả gì.

## 2. Timeline (UTC)

| Time | Event |
|---|---|
| HH:MM | First signal — what triggered detection |
| HH:MM | On-call paged |
| HH:MM | Root cause identified |
| HH:MM | Mitigation applied |
| HH:MM | Full resolution verified |

## 3. Impact

- **User impact**: tenants affected, duration, requests failed
- **Data impact**: records lost / exposed / corrupted? PII? credentials?
- **Compliance impact**: SLA breach? control failure? reportable?
- **Financial impact**: revenue loss, SLA credits, customer churn risk

## 4. Root cause

Phân tích 5-Why hoặc Ishikawa. Không đổ lỗi cá nhân ("human error" KHÔNG phải root cause).

**Trigger**: cái gì kích hoạt incident này?
**Contributing factors**: các yếu tố hệ thống / process làm incident tệ hơn
**Detection gap**: tại sao không phát hiện sớm hơn?

## 5. What went well

- ...
- ...

## 6. What went poorly

- ...
- ...

## 7. Lucky factors

Những điều may mắn — nếu lặp lại, có thể không may như vậy lần nữa.

## 8. Action items

Checklist với owner + deadline. **Mỗi item phải link tới issue/ticket.**

| # | Action | Owner | Due | Ticket |
|---|---|---|---|---|
| 1 | Add correlation rule for X | @user | YYYY-MM-DD | #123 |
| 2 | Update runbook section Y | @user | YYYY-MM-DD | #124 |
| 3 | Add test covering regression | @user | YYYY-MM-DD | #125 |

## 9. Lessons learned

Rút ra cho toàn team. Ghi vào runbook / training materials.

## 10. References

- Slack thread: [link]
- Grafana dashboard snapshot: [link]
- PRs: #xxx, #yyy
- Related incidents: SD-XXXX

---

**Sign-off**: @incident-commander · @security-lead · YYYY-MM-DD
