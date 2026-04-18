# VSP Full System Test Checklist

**Date:** _(fill in)_  
**Tester:** _(fill in)_  
**Gateway version:** _(fill in)_

## Instructions

Mở http://127.0.0.1:8080, đăng nhập, tick ✅ / ❌ cho từng mục.

---

## 🔐 Authentication

- [ ] Login với admin@vsp.local / admin → vào dashboard
- [ ] Logout → redirect về login page
- [ ] Login sai password → báo lỗi

---

## 📊 OPERATIONS

### Dashboard
- [ ] Top KPI cards: SECURITY SCORE, TOTAL RUNS, GATE PASS RATE, OPEN REMEDIATIONS hiển thị số
- [ ] CRITICAL / HIGH / MEDIUM / LOW findings count đúng (khác 0)
- [ ] INCIDENTS, PLAYBOOK RUNS, LOG SOURCES, ANOMALIES có data
- [ ] ATO COUNTDOWN, POA&M, CONMON SCORE, CISA KEV có data
- [ ] Security posture card: Grade, Gate, SLA breaches, Total findings
- [ ] "Top critical findings" liệt kê ≥3 entries
- [ ] "Gate decisions trend" chart render
- [ ] "Recent runs" table có 5+ rows

### Scan log
- [ ] Select dropdown hiển thị list runs
- [ ] Chọn 1 run → log text hiển thị
- [ ] Filter ALL/INFO/WARN/ERROR/DONE work

### Runs
- [ ] List 20+ runs với cột: RUN ID, MODE, STATUS, GATE, FINDINGS, CREATED
- [ ] Click run → xem detail (findings list, summary)
- [ ] Filter/search work
- [ ] Trigger scan button → tạo run mới

### Findings
- [ ] KPI cards: CRITICAL=28, HIGH=391, MEDIUM=1221, LOW=1652
- [ ] Table list 3841 findings
- [ ] Filter by severity (CRITICAL → chỉ hiện 28)
- [ ] Filter by tool (trivy/kics/gitleaks/...)
- [ ] Search work
- [ ] Export CSV button

### Remediation
- [ ] Donut chart render
- [ ] 382 open remediations
- [ ] Assign action work
- [ ] Filter status work

---

## 🛡️ SECURITY

### Policy
- [ ] Rules list hiển thị
- [ ] Evaluate policy work
- [ ] Policy standards section có data

### Audit
- [ ] Activity timeline có events
- [ ] Filter theo user/action work

### SOC
- [ ] Scorecard 3 frameworks (FedRAMP/CMMC/NIST)
- [ ] Incidents list có data
- [ ] Correlation rules active

---

## 📋 COMPLIANCE

### Governance
- [ ] Framework list
- [ ] Control mapping

### FedRAMP
- [ ] Moderate baseline controls
- [ ] Pass/fail rate

### P4 Compliance (đã fix session này)
- [ ] Overview tab: 4 cards + 7 pillars ZT + pipeline summary
- [ ] ATO STATUS = AUTHORIZED (green) + Steps 6/6
- [ ] P4 ACHIEVED badge (green)
- [ ] DoD RMF tab: 6 steps complete, POA&M items
- [ ] Zero Trust tab: 7 pillars ≥85
- [ ] Pipeline tab: ConMon timeline, drift events
- [ ] Micro-Seg tab: 13 rules
- [ ] RASP Events tab: 5 events, modal detail work
- [ ] POA&M tab: 11 items (6 closed, 5 open)
- [ ] ATO Expiry tab: 1064 days remaining
- [ ] SBOM View tab: 412 components, NTIA 91.67%, libexpat không HIGH
- [ ] VN Standards tab: 7 frameworks hiển thị

### SBOM (standalone)
- [ ] 412 components list
- [ ] CVE count đúng (jwt-go: 1 HIGH)
- [ ] License breakdown
- [ ] Download CycloneDX button

### SLA
- [ ] Breach report
- [ ] SLA timer

---

## 📈 REPORTS

### Analytics
- [ ] Charts render (trends)
- [ ] Date range filter

### Executive
- [ ] Exec score + grade
- [ ] Trend chart
- [ ] Summary text

### Export
- [ ] Download PDF button work (test at least 1)
- [ ] Download XLSX button work

---

## 👥 PANELS

### Users
- [ ] User list
- [ ] Role badges
- [ ] Add user form

### CI/CD
- [ ] Pipeline templates
- [ ] Run history
- [ ] Trigger scan button

### Integrations
- [ ] Connector list
- [ ] Status indicators

### Settings
- [ ] Theme toggle
- [ ] Tenant switcher
- [ ] API keys

---

## 🔍 SIEM EXTRAS

### AI Analyst
- [ ] Chat interface
- [ ] Preset questions
- [ ] Send message → receive reply

### Scheduler
- [ ] 5 schedules listed
- [ ] Enable/disable toggle

### Correlation
- [ ] Rules list
- [ ] Incidents generated

### SOAR
- [ ] Playbooks list
- [ ] Playbook runs history

### Log Sources
- [ ] 7+ sources connected
- [ ] Stats per source

### UEBA
- [ ] Anomalies detected
- [ ] User risk scores

### Assets
- [ ] Asset inventory
- [ ] Risk categorization

### SW Inventory
- [ ] Software list
- [ ] Whitelist/blacklist
- [ ] License compliance

### Netflow
- [ ] Traffic flows
- [ ] Top talkers

### Threat Hunt
- [ ] Query builder
- [ ] Saved queries

### Vuln Mgmt
- [ ] Vulnerabilities list
- [ ] Priority ranking

### Threat Intel
- [ ] IOCs 48.2k
- [ ] MITRE ATT&CK mapping
- [ ] Feed sources active

---

## 🚨 Critical Paths (MUST work)

- [ ] Login → Dashboard → P4 Compliance → ATO Letter export
- [ ] Login → Findings → Filter CRITICAL → Export CSV
- [ ] Login → CI/CD → Trigger scan → Check Runs → View findings
- [ ] Login → SBOM → Download CycloneDX

---

## 📊 Results

| Category | Pass | Fail | Skip |
|----------|------|------|------|
| Auth | | | |
| Operations | | | |
| Security | | | |
| Compliance | | | |
| Reports | | | |
| Panels | | | |
| SIEM | | | |
| **TOTAL** | | | |

## 🐛 Bugs found

_(List here)_

1. 
2. 
3. 
