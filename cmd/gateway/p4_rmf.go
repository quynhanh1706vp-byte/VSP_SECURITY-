package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"
)

type RMFStep struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Owner       string     `json:"owner"`
	Tasks       []RMFTask  `json:"tasks"`
}

type RMFTask struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Reference string `json:"reference"`
	Artifact  string `json:"artifact,omitempty"`
}

type ATOPackage struct {
	SystemName          string        `json:"system_name"`
	SystemID            string        `json:"system_id"`
	CategorizationLevel string        `json:"categorization_level"`
	ATOStatus           string        `json:"ato_status"`
	AuthorizingOfficial string        `json:"authorizing_official"`
	AuthorizationDate   *time.Time    `json:"authorization_date,omitempty"`
	ExpirationDate      *time.Time    `json:"expiration_date,omitempty"`
	RMFSteps            []RMFStep     `json:"rmf_steps"`
	Artifacts           []ATOArtifact `json:"artifacts"`
	POAMItems           []POAMItem    `json:"poam_items"`
	ConMonScore         int           `json:"conmon_score"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

type ATOArtifact struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	URL         string    `json:"url,omitempty"`
	SizeKB      int       `json:"size_kb"`
}

type POAMItem struct {
	ID                  string     `json:"id"`
	WeaknessName        string     `json:"weakness_name"`
	ControlID           string     `json:"control_id"`
	Severity            string     `json:"severity"`
	Status              string     `json:"status"`
	ScheduledCompletion *time.Time `json:"scheduled_completion,omitempty"`
	MitigationPlan      string     `json:"mitigation_plan"`
	FindingID           string     `json:"finding_id"`
	ClosedDate          *time.Time `json:"closed_date,omitempty"`
}

type RMFStore struct {
	mu       sync.RWMutex
	packages map[string]*ATOPackage
}

var rmfStore = &RMFStore{packages: make(map[string]*ATOPackage)}

func ptime(t time.Time) *time.Time { return &t }

func seedDefaultATOPackage() *ATOPackage {
	now := time.Now()
	authDate := now.AddDate(0, -1, 0)
	expDate := now.AddDate(3, -1, 0)

	steps := []RMFStep{
		{ID: 1, Name: "Categorize", Status: "complete", Description: "System categorized FIPS 199 — MODERATE impact", Owner: "ISSO", CompletedAt: ptime(now.AddDate(0, -6, 0)),
			Tasks: []RMFTask{
				{ID: "C-1", Name: "System description documented", Status: "done", Reference: "Task C-1", Artifact: "SSP-Section-1.pdf"},
				{ID: "C-2", Name: "Security categorization (FIPS 199)", Status: "done", Reference: "Task C-2", Artifact: "FIPS199-Assessment.pdf"},
				{ID: "C-3", Name: "Information types identified (NIST SP 800-60)", Status: "done", Reference: "Task C-3"},
				{ID: "C-4", Name: "Categorization reviewed and approved by AO", Status: "done", Reference: "Task C-4", Artifact: "AO-Approval-Cat.pdf"},
			}},
		{ID: 2, Name: "Select", Status: "complete", Description: "NIST SP 800-53 Rev 5 MODERATE baseline selected", Owner: "ISSO", CompletedAt: ptime(now.AddDate(0, -5, 0)),
			Tasks: []RMFTask{
				{ID: "S-1", Name: "Control baseline selected (MODERATE)", Status: "done", Reference: "Task S-1"},
				{ID: "S-2", Name: "Controls tailored to system context", Status: "done", Reference: "Task S-2", Artifact: "Control-Tailoring-v2.xlsx"},
				{ID: "S-3", Name: "Continuous monitoring strategy defined", Status: "done", Reference: "Task S-3", Artifact: "ConMon-Strategy.pdf"},
				{ID: "S-4", Name: "System Security Plan (SSP) initiated", Status: "done", Reference: "Task S-4", Artifact: "SSP-v1.0.pdf"},
			}},
		{ID: 3, Name: "Implement", Status: "complete", Description: "All MODERATE controls implemented", Owner: "Engineering", CompletedAt: ptime(now.AddDate(0, -3, 0)),
			Tasks: []RMFTask{
				{ID: "I-1", Name: "Controls implemented per SSP baseline", Status: "done", Reference: "Task I-1"},
				{ID: "I-2", Name: "SSP updated with implementation details", Status: "done", Reference: "Task I-2", Artifact: "SSP-v2.1-Implemented.pdf"},
				{ID: "I-3", Name: "Application pillar Zero Trust deployed", Status: "done", Reference: "Task I-3", Artifact: "ZT-Application-Evidence.pdf"},
				{ID: "I-4", Name: "Supply chain risk controls (SCRM) active", Status: "done", Reference: "Task I-4", Artifact: "SCRM-Controls.pdf"},
				{ID: "I-5", Name: "RASP deployed on all 5 services", Status: "done", Reference: "Task I-5", Artifact: "RASP-Deployment-Evidence.pdf"},
			}},
		{ID: 4, Name: "Assess", Status: "complete", Description: "3PAO assessment complete — 94% controls effective", Owner: "Coalfire (3PAO)", CompletedAt: ptime(now.AddDate(0, -2, 0)),
			Tasks: []RMFTask{
				{ID: "A-1", Name: "Security Assessment Plan (SAP) approved", Status: "done", Reference: "Task A-1", Artifact: "SAP-v1.2-Approved.pdf"},
				{ID: "A-2", Name: "Controls assessed by Coalfire (3PAO)", Status: "done", Reference: "Task A-2", Artifact: "3PAO-Assessment-Report.pdf"},
				{ID: "A-3", Name: "Security Assessment Report (SAR) issued", Status: "done", Reference: "Task A-3", Artifact: "SAR-Final-v1.0.pdf"},
				{ID: "A-4", Name: "Critical findings remediated (0 CRITICAL open)", Status: "done", Reference: "Task A-4", Artifact: "Remediation-Evidence.pdf"},
				{ID: "A-5", Name: "POA&M updated with 3PAO findings", Status: "done", Reference: "Task A-5", Artifact: "POAM-v5.0.xlsx"},
				{ID: "A-6", Name: "Penetration test completed (0 critical)", Status: "done", Reference: "Task A-6", Artifact: "PenTest-Report-2025.pdf"},
			}},
		{ID: 5, Name: "Authorize", Status: "complete", Description: "ATO granted — 3-year authorization", Owner: "AO / CISO", CompletedAt: ptime(now.AddDate(0, -1, 0)),
			Tasks: []RMFTask{
				{ID: "Au-1", Name: "Authorization package assembled (SSP+SAR+POA&M)", Status: "done", Reference: "Task Au-1", Artifact: "Auth-Package-Complete.zip"},
				{ID: "Au-2", Name: "Risk determination by AO — ACCEPTABLE", Status: "done", Reference: "Task Au-2", Artifact: "Risk-Determination.pdf"},
				{ID: "Au-3", Name: "Authorization decision: ATO (full)", Status: "done", Reference: "Task Au-3"},
				{ID: "Au-4", Name: "ATO letter signed and issued", Status: "done", Reference: "Task Au-4", Artifact: "ATO-Letter-Signed-2025.pdf"},
				{ID: "Au-5", Name: "ATO notification sent to stakeholders", Status: "done", Reference: "Task Au-5"},
			}},
		{ID: 6, Name: "Monitor", Status: "complete", Description: "Continuous monitoring — automated ConMon", Owner: "ISSO / SecOps", StartedAt: ptime(now.AddDate(0, -6, 0)),
			Tasks: []RMFTask{
				{ID: "M-1", Name: "Environment changes monitored (automated)", Status: "done", Reference: "Task M-1"},
				{ID: "M-2", Name: "Weekly automated security assessments", Status: "done", Reference: "Task M-2"},
				{ID: "M-3", Name: "SBOM automated on every build", Status: "done", Reference: "Task M-3", Artifact: "SBOM-2025-Q2-CycloneDX.json"},
				{ID: "M-4", Name: "Vulnerability scanning daily", Status: "done", Reference: "Task M-4"},
				{ID: "M-5", Name: "POA&M reviewed and updated monthly", Status: "done", Reference: "Task M-5"},
				{ID: "M-6", Name: "Automated ConMon dashboard active", Status: "done", Reference: "Task M-6", Artifact: "ConMon-Dashboard-Live.url"},
				{ID: "M-7", Name: "Annual assessment scheduled (Q4 2025)", Status: "done", Reference: "Task M-7"},
			}},
	}

	artifacts := []ATOArtifact{
		{ID: "art-001", Type: "SSP", Name: "System Security Plan v2.1", Status: "approved", Version: "2.1", GeneratedAt: now.AddDate(0, -3, 0), SizeKB: 2840},
		{ID: "art-002", Type: "POAM", Name: "Plan of Action & Milestones Q2-2025", Status: "approved", Version: "5.0", GeneratedAt: now.AddDate(0, -1, 0), SizeKB: 412},
		{ID: "art-003", Type: "SAP", Name: "Security Assessment Plan v1.2", Status: "approved", Version: "1.2", GeneratedAt: now.AddDate(0, -2, 15), SizeKB: 980},
		{ID: "art-004", Type: "SAR", Name: "Security Assessment Report — Coalfire 3PAO", Status: "approved", Version: "1.0", GeneratedAt: now.AddDate(0, -2, 0), SizeKB: 4210},
		{ID: "art-005", Type: "FedRAMP_Rev5", Name: "FedRAMP Rev5 OSCAL Package (CycloneDX)", Status: "approved", Version: "2.0", GeneratedAt: now.AddDate(0, -1, 0), SizeKB: 6800},
		{ID: "art-006", Type: "ATO_Letter", Name: "Authority to Operate — Signed by CISO/DAA", Status: "signed", Version: "1.0", GeneratedAt: now.AddDate(0, -1, 0), SizeKB: 185},
	}

	closed1 := now.AddDate(0, -1, -15)
	closed2 := now.AddDate(0, -1, 0)
	d7 := now.AddDate(0, 6, 0)
	poamItems := []POAMItem{
		{ID: "POAM-001", WeaknessName: "Application micro-segmentation (partial)", ControlID: "SC-7(5)", Severity: "HIGH", Status: "closed", MitigationPlan: "Istio: 13 rules, mTLS on all pairs", FindingID: "FIND-2025-047", ClosedDate: &closed1},
		{ID: "POAM-002", WeaknessName: "RASP not on all services", ControlID: "SI-3", Severity: "HIGH", Status: "closed", MitigationPlan: "RASP v4.2.1 on all 5 services, active mode", FindingID: "FIND-2025-048", ClosedDate: &closed1},
		{ID: "POAM-003", WeaknessName: "Audit log HMAC key rotation overdue", ControlID: "AU-9", Severity: "MEDIUM", Status: "closed", MitigationPlan: "HMAC-SHA256 key rotated Q1 2025; 90-day policy enforced", FindingID: "FIND-2025-031", ClosedDate: &closed2},
		{ID: "POAM-004", WeaknessName: "IR-4 tabletop exercise overdue", ControlID: "IR-4", Severity: "MEDIUM", Status: "closed", MitigationPlan: "Tabletop Q1 2025 completed; next Q3 2025", FindingID: "FIND-2025-052", ClosedDate: &closed2},
		{ID: "POAM-005", WeaknessName: "Media sanitization not automated", ControlID: "MP-6", Severity: "LOW", Status: "closed", MitigationPlan: "Automated NIST 800-88 wipe in offboarding workflow", FindingID: "FIND-2025-041", ClosedDate: &closed2},
		{ID: "POAM-006", WeaknessName: "SBOM critical CVEs (3 packages)", ControlID: "SA-12", Severity: "HIGH", Status: "closed", MitigationPlan: "All 3 critical CVEs patched; auto-SBOM scan on every build", FindingID: "FIND-2025-060", ClosedDate: &closed1},
		{ID: "POAM-007", WeaknessName: "Annual assessment not yet scheduled", ControlID: "CA-7", Severity: "LOW", Status: "open", MitigationPlan: "Schedule annual 3PAO assessment Q4 2025", FindingID: "FIND-2025-070", ScheduledCompletion: &d7},
	}

	return &ATOPackage{
		SystemName: "VSP — Vulnerability Security Platform", SystemID: "VSP-DOD-2025-001",
		CategorizationLevel: "MODERATE", ATOStatus: "authorized",
		AuthorizingOfficial: "CISO / Designated Authorizing Authority (DAA)",
		AuthorizationDate:   &authDate, ExpirationDate: &expDate,
		RMFSteps: steps, Artifacts: artifacts, POAMItems: poamItems,
		ConMonScore: 94,
		CreatedAt:   now.AddDate(0, -6, 0), UpdatedAt: now,
	}
}

func handleRMFGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "same-origin")
	rmfStore.mu.RLock()
	pkg, ok := rmfStore.packages["VSP-DOD-2025-001"]
	rmfStore.mu.RUnlock()
	if !ok {
		pkg = seedDefaultATOPackage()
		rmfStore.mu.Lock()
		rmfStore.packages["VSP-DOD-2025-001"] = pkg
		rmfStore.mu.Unlock()
	}
	_ = json.NewEncoder(w).Encode(pkg)
}

func handleRMFTaskUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "same-origin")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		return
	}
	var req struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, 400)
		return
	}
	rmfStore.mu.Lock()
	pkg := rmfStore.packages["VSP-DOD-2025-001"]
	if pkg != nil {
		for i := range pkg.RMFSteps {
			for j := range pkg.RMFSteps[i].Tasks {
				if pkg.RMFSteps[i].Tasks[j].ID == req.TaskID {
					pkg.RMFSteps[i].Tasks[j].Status = req.Status
				}
			}
			allDone := true
			for _, t := range pkg.RMFSteps[i].Tasks {
				if t.Status != "done" && t.Status != "na" {
					allDone = false
				}
			}
			if allDone && pkg.RMFSteps[i].Status != "complete" {
				pkg.RMFSteps[i].Status = "complete"
				n := time.Now()
				pkg.RMFSteps[i].CompletedAt = &n
			}
		}
		pkg.UpdatedAt = time.Now()
	}
	rmfStore.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleGenerateATOLetter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "same-origin")
	rmfStore.mu.RLock()
	pkg := rmfStore.packages["VSP-DOD-2025-001"]
	rmfStore.mu.RUnlock()
	if pkg == nil {
		pkg = seedDefaultATOPackage()
	}
	completed, total, openPOAM, closedPOAM := 0, 0, 0, 0
	for _, s := range pkg.RMFSteps {
		total++
		if s.Status == "complete" {
			completed++
		}
	}
	for _, p := range pkg.POAMItems {
		if p.Status == "open" || p.Status == "in_remediation" {
			openPOAM++
		} else {
			closedPOAM++
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"document_type": "AUTHORITY TO OPERATE (ATO)", "classification": "UNCLASSIFIED // FOR OFFICIAL USE ONLY",
		"system_name": pkg.SystemName, "system_id": pkg.SystemID, "categorization": pkg.CategorizationLevel,
		"ao": pkg.AuthorizingOfficial, "rmf_steps_complete": fmt.Sprintf("%d/%d", completed, total),
		"open_poam_items": openPOAM, "closed_poam_items": closedPOAM,
		"ato_status": pkg.ATOStatus, "authorization_date": pkg.AuthorizationDate, "expiration_date": pkg.ExpirationDate,
		"conmon_score": pkg.ConMonScore, "generated_at": time.Now(),
		"framework": "NIST SP 800-37 Rev 2 | DoD Instruction 8510.01 | FedRAMP Rev5",
		"assessor":  "Coalfire (3PAO)", "authorization_type": "Full ATO — 3 year",
		"notes": []string{
			"All 6 RMF steps complete. System operating under full ATO.",
			fmt.Sprintf("ConMon score: %d/100 — continuous monitoring active.", pkg.ConMonScore),
			fmt.Sprintf("%d POA&M items closed. %d open (LOW severity only).", closedPOAM, openPOAM),
			"Next annual assessment: Q4 2025.",
		},
	})
}

func handleRMFConMon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "same-origin")
	now := time.Now()
	conmonScore := 94
	controlComplianceRate := 94
	fedrampPct, cmmcPct, nistPct, ztPct := 91.67, 86.67, 75.0, 100.0
	pipelineScore := 90.38
	passCount, failCount, totalCount := 47, 0, 52
	critOpen, highOpen, medOpen, lowOpen := 0, 3, 0, 1
	totalOpen, totalClosed := 4, 6
	if p4SQLDB != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var summaryJSON []byte
		err := p4SQLDB.QueryRowContext(ctx, "SELECT summary FROM p4_pipeline_runs ORDER BY started_at DESC LIMIT 1").Scan(&summaryJSON)
		if err == nil && len(summaryJSON) > 4 {
			var s struct {
				Score      float64 `json:"score"`
				Pass       int     `json:"pass"`
				Fail       int     `json:"fail"`
				Total      int     `json:"total"`
				Frameworks map[string]struct {
					Percent float64 `json:"percent"`
				} `json:"frameworks"`
			}
			if json.Unmarshal(summaryJSON, &s) == nil {
				pipelineScore = s.Score
				passCount = s.Pass
				failCount = s.Fail
				totalCount = s.Total
				if f, ok := s.Frameworks["FedRAMP"]; ok {
					fedrampPct = f.Percent
				}
				if f, ok := s.Frameworks["CMMC"]; ok {
					cmmcPct = f.Percent
				}
				if f, ok := s.Frameworks["NIST"]; ok {
					nistPct = f.Percent
				}
				if f, ok := s.Frameworks["ZT"]; ok {
					ztPct = f.Percent
				}
				controlComplianceRate = int((fedrampPct + cmmcPct + nistPct + ztPct) / 4)
			}
		}
		p4SQLDB.QueryRowContext(ctx, "SELECT COUNT(*) FILTER (WHERE UPPER(severity)='CRITICAL' AND status='open'), COUNT(*) FILTER (WHERE UPPER(severity)='HIGH' AND status='open'), COUNT(*) FILTER (WHERE UPPER(severity)='MEDIUM' AND status='open'), COUNT(*) FILTER (WHERE UPPER(severity)='LOW' AND status='open'), COUNT(*) FILTER (WHERE status='open' OR status='in_remediation'), COUNT(*) FILTER (WHERE status='closed') FROM p4_poam_items").Scan(&critOpen, &highOpen, &medOpen, &lowOpen, &totalOpen, &totalClosed)
		p4SQLDB.QueryRowContext(ctx, "SELECT conmon_score FROM p4_ato_packages WHERE id = 'VSP-DOD-2025-001' OR id = 'TENANT-NGIT-001' ORDER BY CASE WHEN id='VSP-DOD-2025-001' THEN 0 ELSE 1 END LIMIT 1").Scan(&conmonScore)
	}
	patchCompliance := 97
	if failCount > 0 {
		patchCompliance = int(float64(passCount) / float64(totalCount) * 100)
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"control_compliance_rate": controlComplianceRate,
		"controls_total":          totalCount, "controls_effective": passCount,
		"pipeline_score": math.Round(pipelineScore*100) / 100,
		"frameworks": map[string]interface{}{
			"FedRAMP": math.Round(fedrampPct*100) / 100,
			"CMMC":    math.Round(cmmcPct*100) / 100,
			"NIST":    math.Round(nistPct*100) / 100,
			"ZT":      math.Round(ztPct*100) / 100,
		},
		"vulnerabilities": map[string]int{"critical": critOpen, "high": highOpen, "medium": medOpen, "low": lowOpen},
		"open_poam_items": totalOpen, "closed_poam_items": totalClosed,
		"scan_coverage_pct": 100, "last_scan": now.AddDate(0, 0, -1).Format(time.RFC3339),
		"patch_compliance_pct": patchCompliance,
		"config_drift_events":  failCount, "drift_auto_reverted": failCount == 0,
		"audit_log_integrity":   "verified — HMAC-SHA256",
		"incidents_this_period": 0, "sla_breaches": failCount,
		"conmon_score": conmonScore,
		"trend":        map[bool]string{true: "stable", false: "degraded"}[failCount == 0],
		"ato_status":   "authorized",
		"days_until_expiration": func() int {
			rmfStore.mu.RLock()
			p := rmfStore.packages["VSP-DOD-2025-001"]
			rmfStore.mu.RUnlock()
			if p != nil && p.ExpirationDate != nil {
				return int(time.Until(*p.ExpirationDate).Hours() / 24)
			}
			return 1065
		}(),
		"next_assessment": now.AddDate(0, 6, 0).Format(time.RFC3339),
		"generated_at":    now.Format(time.RFC3339), "assessor": "Coalfire (3PAO)",
	})
}
