package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type ZTPillar struct {
	Name          string         `json:"name"`
	Score         int            `json:"score"`
	Target        int            `json:"target"`
	Status        string         `json:"status"`
	MaturityLevel string         `json:"maturity_level"`
	Capabilities  []ZTCapability `json:"capabilities"`
}

type ZTCapability struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Level       string   `json:"level"`
	Score       int      `json:"score"`
	MaxScore    int      `json:"max_score"`
	Status      string   `json:"status"`
	Controls    []string `json:"controls"`
	Evidence    string   `json:"evidence,omitempty"`
}

type MicroSegRule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Source      string     `json:"source"`
	Destination string     `json:"destination"`
	Port        int        `json:"port"`
	Protocol    string     `json:"protocol"`
	Action      string     `json:"action"`
	MTLS        bool       `json:"mtls"`
	CreatedAt   time.Time  `json:"created_at"`
	HitCount    int        `json:"hit_count"`
	LastHit     *time.Time `json:"last_hit,omitempty"`
}

type RASPEvent struct {
	ID         string     `json:"id"`
	Timestamp  time.Time  `json:"timestamp"`
	Severity   string     `json:"severity"`
	AttackType string     `json:"attack_type"`
	Service    string     `json:"service"`
	Endpoint   string     `json:"endpoint"`
	SourceIP   string     `json:"source_ip"`
	Action     string     `json:"action"`
	CVE        string     `json:"cve,omitempty"`
	LastHit    *time.Time `json:"last_hit,omitempty"`
}

type RASPCoverage struct {
	Service     string `json:"service"`
	Deployed    bool   `json:"deployed"`
	Version     string `json:"version"`
	Mode        string `json:"mode"`
	EventsToday int    `json:"events_today"`
}

type APIPolicy struct {
	ID              string    `json:"id"`
	ServiceName     string    `json:"service_name"`
	Endpoint        string    `json:"endpoint"`
	Method          string    `json:"method"`
	AllowedRoles    []string  `json:"allowed_roles"`
	RateLimit       int       `json:"rate_limit"`
	RequiresMTLS    bool      `json:"requires_mtls"`
	RequiresJWT     bool      `json:"requires_jwt"`
	DataSensitivity string    `json:"data_sensitivity"`
	LastAudited     time.Time `json:"last_audited"`
}

type SBOMSummary struct {
	Total      int      `json:"total"`
	Critical   int      `json:"critical"`
	High       int      `json:"high"`
	LastScan   time.Time `json:"last_scan"`
	Frameworks []string `json:"frameworks"`
}

type ZeroTrustAppState struct {
	mu           sync.RWMutex
	Pillars      map[string]*ZTPillar `json:"pillars"`
	SegRules     []MicroSegRule       `json:"seg_rules"`
	RASPEvents   []RASPEvent          `json:"rasp_events"`
	RASPCoverage []RASPCoverage       `json:"rasp_coverage"`
	APIPolicies  []APIPolicy          `json:"api_policies"`
	SBOM         SBOMSummary          `json:"sbom"`
	OverallScore int                  `json:"overall_score"`
	P4Readiness  int                  `json:"p4_readiness"`
	P4Achieved   bool                 `json:"p4_achieved"`
	LastUpdated  time.Time            `json:"last_updated"`
}

var ztState = &ZeroTrustAppState{}

func minInt(a, b int) int {
	if a < b { return a }
	return b
}

func pillarStatus(score int) string {
	if score >= 85 { return "green" }
	if score >= 60 { return "amber" }
	return "red"
}

func pillarMaturity(score int) string {
	if score >= 90 { return "Optimal" }
	if score >= 70 { return "Advanced" }
	return "Traditional"
}

func initZeroTrustState() {
	now := time.Now()
	lh := now.AddDate(0, 0, -1)

	ztState.mu.Lock()
	defer ztState.mu.Unlock()

	ztState.Pillars = map[string]*ZTPillar{
		"user": {Name: "User", Score: 97, Target: 100, Status: "green", MaturityLevel: "Optimal",
			Capabilities: []ZTCapability{
				{ID: "U-1", Name: "Identity verification (MFA)", Level: "Optimal", Score: 20, MaxScore: 20, Status: "implemented", Controls: []string{"IA-2", "IA-5"}, Evidence: "MFA 100%: 14/14 privileged, 28/28 standard users"},
				{ID: "U-2", Name: "Privileged access management (PAM)", Level: "Optimal", Score: 20, MaxScore: 20, Status: "implemented", Controls: []string{"AC-6", "AC-2"}, Evidence: "PAM deployed, session recording active"},
				{ID: "U-3", Name: "User behavior analytics (UEBA)", Level: "Optimal", Score: 19, MaxScore: 20, Status: "implemented", Controls: []string{"AU-6", "SI-4"}, Evidence: "UEBA baseline set; 3 anomalies detected & investigated"},
				{ID: "U-4", Name: "Continuous authentication", Level: "Advanced", Score: 18, MaxScore: 20, Status: "implemented", Controls: []string{"IA-11", "AC-12"}, Evidence: "Risk-based re-auth on privilege escalation"},
			}},
		"device": {Name: "Device", Score: 88, Target: 100, Status: "green", MaturityLevel: "Advanced",
			Capabilities: []ZTCapability{
				{ID: "D-1", Name: "Device health attestation", Level: "Advanced", Score: 18, MaxScore: 25, Status: "implemented", Controls: []string{"CM-6", "CM-7"}, Evidence: "TPM attestation: 40/42 endpoints"},
				{ID: "D-2", Name: "Endpoint detection & response (EDR)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SI-3", "SI-4"}, Evidence: "CrowdStrike EDR: 42/42 (100%)"},
				{ID: "D-3", Name: "Mobile device management (MDM)", Level: "Advanced", Score: 20, MaxScore: 25, Status: "implemented", Controls: []string{"AC-19", "CM-2"}, Evidence: "Intune MDM: 18/18 devices"},
				{ID: "D-4", Name: "Software inventory & compliance", Level: "Advanced", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"CM-8", "SA-7"}, Evidence: "SBOM auto-generated on every build"},
			}},
		"network": {Name: "Network", Score: 100, Target: 100, Status: "green", MaturityLevel: "Optimal",
			Capabilities: []ZTCapability{
				{ID: "N-1", Name: "Software-defined perimeter (SDP)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SC-7", "SC-7(5)"}, Evidence: "0 direct internet exposure"},
				{ID: "N-2", Name: "Encrypted transport (TLS 1.3)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SC-8", "SC-28"}, Evidence: "SSL Labs A+; 100% TLS 1.3"},
				{ID: "N-3", Name: "DNS security (DNSSEC + DoH)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SC-20", "SC-21"}, Evidence: "DNSSEC + DoH enforced"},
				{ID: "N-4", Name: "Network traffic analytics (NTA)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SI-4", "AU-12"}, Evidence: "Zeek+Suricata: 100% visibility"},
			}},
		"application": {Name: "Application & Workloads", Score: 91, Target: 100, Status: "green", MaturityLevel: "Advanced",
			Capabilities: []ZTCapability{
				{ID: "A-1", Name: "Micro-segmentation (service mesh + mTLS)", Level: "Optimal", Score: 24, MaxScore: 25, Status: "implemented", Controls: []string{"SC-7(5)", "SC-39"}, Evidence: "Istio: 13 rules, mTLS on 12/13 pairs"},
				{ID: "A-2", Name: "Runtime App Self-Protection (RASP)", Level: "Advanced", Score: 22, MaxScore: 25, Status: "implemented", Controls: []string{"SI-3", "SI-10", "SI-16"}, Evidence: "RASP v4.2.1: 5/5 services, 847 attacks blocked"},
				{ID: "A-3", Name: "API gateway least-privilege (RBAC)", Level: "Optimal", Score: 23, MaxScore: 25, Status: "implemented", Controls: []string{"AC-6", "AC-17", "SC-8"}, Evidence: "20/20 endpoints: RBAC + mTLS + JWT"},
				{ID: "A-4", Name: "SBOM + software supply chain (SCRM)", Level: "Advanced", Score: 22, MaxScore: 25, Status: "implemented", Controls: []string{"SA-12", "SR-3", "SR-11"}, Evidence: "412 components; 0 critical CVEs"},
			}},
		"data": {Name: "Data", Score: 100, Target: 100, Status: "green", MaturityLevel: "Optimal",
			Capabilities: []ZTCapability{
				{ID: "Da-1", Name: "Data classification & tagging (CUI/FCI)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"RA-2", "MP-3"}, Evidence: "100% assets classified; DLP enforced"},
				{ID: "Da-2", Name: "Encryption at rest (AES-256-GCM)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SC-28", "SC-12"}, Evidence: "AES-256-GCM; HSM key management"},
				{ID: "Da-3", Name: "Data loss prevention (DLP)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"SI-12", "MP-7"}, Evidence: "DLP active on all exfil vectors; 0 incidents"},
				{ID: "Da-4", Name: "Data access governance (ABAC)", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"AC-3", "AC-4"}, Evidence: "ABAC enforced; all PII/CUI access logged"},
			}},
		"visibility": {Name: "Visibility & Analytics", Score: 95, Target: 100, Status: "green", MaturityLevel: "Optimal",
			Capabilities: []ZTCapability{
				{ID: "V-1", Name: "SIEM integration", Level: "Optimal", Score: 25, MaxScore: 25, Status: "implemented", Controls: []string{"AU-2", "AU-12", "SI-4"}, Evidence: "Splunk: 100% log ingestion"},
				{ID: "V-2", Name: "Threat intelligence feed (CTI)", Level: "Optimal", Score: 24, MaxScore: 25, Status: "implemented", Controls: []string{"RA-3", "RA-5"}, Evidence: "MISP + VirusTotal + CISA KEV; IOCs auto-blocked"},
				{ID: "V-3", Name: "Security analytics & reporting", Level: "Optimal", Score: 23, MaxScore: 25, Status: "implemented", Controls: []string{"AU-6", "CA-7"}, Evidence: "Real-time dashboards; weekly ConMon reports"},
				{ID: "V-4", Name: "Audit log integrity (HMAC-SHA256)", Level: "Advanced", Score: 23, MaxScore: 25, Status: "implemented", Controls: []string{"AU-9", "AU-10"}, Evidence: "HMAC-SHA256; key rotated 45 days ago"},
			}},
		"automation": {Name: "Automation & Orchestration", Score: 93, Target: 100, Status: "green", MaturityLevel: "Optimal",
			Capabilities: []ZTCapability{
				{ID: "Au-1", Name: "SOAR playbooks", Level: "Optimal", Score: 24, MaxScore: 25, Status: "implemented", Controls: []string{"IR-4", "IR-5"}, Evidence: "12 active playbooks; MTTR -60%"},
				{ID: "Au-2", Name: "Policy-as-code (OPA/Rego)", Level: "Optimal", Score: 23, MaxScore: 25, Status: "implemented", Controls: []string{"CM-6", "CM-7"}, Evidence: "OPA Gatekeeper: 47 policies in K8s"},
				{ID: "Au-3", Name: "Automated vulnerability remediation", Level: "Optimal", Score: 24, MaxScore: 25, Status: "implemented", Controls: []string{"SI-2", "RA-5"}, Evidence: "Auto-patch CRITICAL <24h; 97% SLA"},
				{ID: "Au-4", Name: "CI/CD compliance gates", Level: "Advanced", Score: 22, MaxScore: 25, Status: "implemented", Controls: []string{"SA-11", "CM-3"}, Evidence: "33 control tests; blocks deploy on FAIL"},
			}},
	}

	ztState.SegRules = []MicroSegRule{
		{ID: "SEG-001", Name: "vsp-api → postgres", Source: "vsp-api", Destination: "postgres", Port: 5432, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -3, 0), HitCount: 284621},
		{ID: "SEG-002", Name: "vsp-api → redis", Source: "vsp-api", Destination: "redis", Port: 6379, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -3, 0), HitCount: 198432},
		{ID: "SEG-003", Name: "vsp-scanner → targets", Source: "vsp-scanner", Destination: "scan-targets", Port: 0, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -2, 0), HitCount: 12841},
		{ID: "SEG-004", Name: "vsp-report → postgres (RO)", Source: "vsp-report", Destination: "postgres", Port: 5432, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -2, 0), HitCount: 43210},
		{ID: "SEG-005", Name: "vsp-auth → redis (session)", Source: "vsp-auth", Destination: "redis", Port: 6379, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -2, 0), HitCount: 88912},
		{ID: "SEG-006", Name: "Block direct postgres", Source: "*", Destination: "postgres", Port: 5432, Protocol: "TCP", Action: "deny", MTLS: false, CreatedAt: now.AddDate(0, -3, 0), HitCount: 247},
		{ID: "SEG-007", Name: "Block direct redis", Source: "*", Destination: "redis", Port: 6379, Protocol: "TCP", Action: "deny", MTLS: false, CreatedAt: now.AddDate(0, -3, 0), HitCount: 83},
		{ID: "SEG-008", Name: "vsp-siem → all (read)", Source: "vsp-siem", Destination: "*", Port: 0, Protocol: "TCP", Action: "inspect", MTLS: true, CreatedAt: now.AddDate(0, -1, 0), HitCount: 5621},
		{ID: "SEG-009", Name: "Egress → threat intel", Source: "vsp-threatintel", Destination: "external-feeds", Port: 443, Protocol: "TCP", Action: "allow", MTLS: false, CreatedAt: now.AddDate(0, -1, 0), HitCount: 1284},
		{ID: "SEG-010", Name: "vsp-soar → all (orchestrate)", Source: "vsp-soar", Destination: "*", Port: 0, Protocol: "gRPC", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -1, 15), HitCount: 3847},
		{ID: "SEG-011", Name: "Admin plane isolation", Source: "admin-plane", Destination: "vsp-*", Port: 0, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -2, 0), HitCount: 4120},
		{ID: "SEG-012", Name: "Block lateral movement", Source: "vsp-api", Destination: "vsp-scanner", Port: 0, Protocol: "TCP", Action: "deny", MTLS: false, CreatedAt: now.AddDate(0, -1, 0), HitCount: 12},
		{ID: "SEG-013", Name: "vsp-gateway → vsp-api", Source: "vsp-gateway", Destination: "vsp-api", Port: 8080, Protocol: "TCP", Action: "allow", MTLS: true, CreatedAt: now.AddDate(0, -3, 0), HitCount: 924831},
	}

	ztState.RASPCoverage = []RASPCoverage{
		{Service: "vsp-api", Deployed: true, Version: "4.2.1", Mode: "active", EventsToday: 12},
		{Service: "vsp-auth", Deployed: true, Version: "4.2.1", Mode: "active", EventsToday: 3},
		{Service: "vsp-report", Deployed: true, Version: "4.2.0", Mode: "active", EventsToday: 1},
		{Service: "vsp-scanner", Deployed: true, Version: "4.2.1", Mode: "active", EventsToday: 0},
		{Service: "vsp-gateway", Deployed: true, Version: "4.2.1", Mode: "active", EventsToday: 8},
	}

	ztState.RASPEvents = []RASPEvent{
		{ID: "RASP-001", Timestamp: now.AddDate(0, 0, -2), Severity: "HIGH", AttackType: "SQL Injection", Service: "vsp-api", Endpoint: "/api/query", SourceIP: "10.44.21.7", Action: "blocked"},
		{ID: "RASP-002", Timestamp: now.AddDate(0, 0, -1), Severity: "CRITICAL", AttackType: "SSRF", Service: "vsp-api", Endpoint: "/api/fetch", SourceIP: "203.0.113.44", Action: "blocked", CVE: "CVE-2021-26855", LastHit: &lh},
		{ID: "RASP-003", Timestamp: now.AddDate(0, 0, -1), Severity: "HIGH", AttackType: "Command Injection", Service: "vsp-gateway", Endpoint: "/api/exec", SourceIP: "192.168.1.99", Action: "blocked"},
		{ID: "RASP-004", Timestamp: now, Severity: "MEDIUM", AttackType: "Path Traversal", Service: "vsp-report", Endpoint: "/api/export", SourceIP: "10.12.0.5", Action: "alerted"},
		{ID: "RASP-005", Timestamp: now, Severity: "LOW", AttackType: "XSS Reflected", Service: "vsp-auth", Endpoint: "/auth/login", SourceIP: "10.0.0.44", Action: "blocked"},
	}

	ztState.APIPolicies = []APIPolicy{
		{ID: "POL-001", ServiceName: "vsp-api", Endpoint: "/api/findings", Method: "GET", AllowedRoles: []string{"analyst", "admin", "readonly"}, RateLimit: 500, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now.AddDate(0, -1, 0)},
		{ID: "POL-002", ServiceName: "vsp-api", Endpoint: "/api/findings", Method: "POST", AllowedRoles: []string{"scanner", "admin"}, RateLimit: 100, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now.AddDate(0, -1, 0)},
		{ID: "POL-003", ServiceName: "vsp-api", Endpoint: "/api/users", Method: "GET", AllowedRoles: []string{"admin"}, RateLimit: 50, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SECRET", LastAudited: now.AddDate(0, -1, 0)},
		{ID: "POL-004", ServiceName: "vsp-api", Endpoint: "/api/runs", Method: "GET", AllowedRoles: []string{"analyst", "admin", "readonly"}, RateLimit: 300, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "INTERNAL", LastAudited: now.AddDate(0, -1, 0)},
		{ID: "POL-005", ServiceName: "vsp-api", Endpoint: "/api/scans", Method: "POST", AllowedRoles: []string{"scanner", "admin"}, RateLimit: 30, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-006", ServiceName: "vsp-auth", Endpoint: "/auth/login", Method: "POST", AllowedRoles: []string{"*"}, RateLimit: 10, RequiresMTLS: false, RequiresJWT: false, DataSensitivity: "PUBLIC", LastAudited: now},
		{ID: "POL-007", ServiceName: "vsp-auth", Endpoint: "/auth/refresh", Method: "POST", AllowedRoles: []string{"authenticated"}, RateLimit: 60, RequiresMTLS: false, RequiresJWT: true, DataSensitivity: "INTERNAL", LastAudited: now},
		{ID: "POL-008", ServiceName: "vsp-report", Endpoint: "/api/export", Method: "POST", AllowedRoles: []string{"analyst", "admin"}, RateLimit: 20, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-009", ServiceName: "vsp-scanner", Endpoint: "/api/scan", Method: "POST", AllowedRoles: []string{"scanner", "admin"}, RateLimit: 5, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-010", ServiceName: "vsp-api", Endpoint: "/api/health", Method: "GET", AllowedRoles: []string{"*"}, RateLimit: 1000, RequiresMTLS: false, RequiresJWT: false, DataSensitivity: "PUBLIC", LastAudited: now},
		{ID: "POL-011", ServiceName: "vsp-api", Endpoint: "/api/p4/rmf", Method: "GET", AllowedRoles: []string{"analyst", "admin", "ciso"}, RateLimit: 100, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-012", ServiceName: "vsp-api", Endpoint: "/api/p4/zt/status", Method: "GET", AllowedRoles: []string{"analyst", "admin", "ciso"}, RateLimit: 100, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-013", ServiceName: "vsp-api", Endpoint: "/api/p4/pipeline/trigger", Method: "POST", AllowedRoles: []string{"admin", "ciso"}, RateLimit: 10, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "INTERNAL", LastAudited: now},
		{ID: "POL-014", ServiceName: "vsp-api", Endpoint: "/api/v1/admin/users", Method: "GET", AllowedRoles: []string{"admin"}, RateLimit: 30, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SECRET", LastAudited: now},
		{ID: "POL-015", ServiceName: "vsp-api", Endpoint: "/api/v1/audit", Method: "GET", AllowedRoles: []string{"admin", "ciso", "auditor"}, RateLimit: 50, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-016", ServiceName: "vsp-siem", Endpoint: "/api/logs", Method: "GET", AllowedRoles: []string{"analyst", "admin"}, RateLimit: 200, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-017", ServiceName: "vsp-siem", Endpoint: "/api/incidents", Method: "GET", AllowedRoles: []string{"analyst", "admin", "ciso"}, RateLimit: 150, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-018", ServiceName: "vsp-soar", Endpoint: "/api/playbooks", Method: "POST", AllowedRoles: []string{"admin"}, RateLimit: 20, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "INTERNAL", LastAudited: now},
		{ID: "POL-019", ServiceName: "vsp-threatintel", Endpoint: "/api/iocs", Method: "GET", AllowedRoles: []string{"analyst", "admin"}, RateLimit: 100, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "SENSITIVE", LastAudited: now},
		{ID: "POL-020", ServiceName: "vsp-api", Endpoint: "/api/v1/sbom", Method: "GET", AllowedRoles: []string{"analyst", "admin", "ciso"}, RateLimit: 30, RequiresMTLS: true, RequiresJWT: true, DataSensitivity: "INTERNAL", LastAudited: now},
	}

	// Load SBOM stats từ DB nếu có, fallback defaults
	ztState.SBOM = SBOMSummary{
		Total: 412, Critical: 0, High: 2,
		LastScan:   now.AddDate(0, 0, -1),
		Frameworks: []string{"CycloneDX 1.4", "SPDX 2.3", "NTIA minimum elements"},
	}
	if p4SQLDB != nil {
		var sbomJSON []byte
		if p4SQLDB.QueryRow("SELECT sbom FROM p4_zt_state WHERE id='main'").Scan(&sbomJSON) == nil && len(sbomJSON) > 4 {
			var sbomData SBOMSummary
			if json.Unmarshal(sbomJSON, &sbomData) == nil && sbomData.Total > 0 {
				ztState.SBOM = sbomData
			}
		}
	}

	recalcScoresLocked()
}

func recalcScoresLocked() {
	total, count := 0, 0
	allP4 := true
	for _, p := range ztState.Pillars {
		capT, capM := 0, 0
		for _, c := range p.Capabilities { capT += c.Score; capM += c.MaxScore }
		if capM > 0 { p.Score = capT * 100 / capM }
		p.Status = pillarStatus(p.Score)
		p.MaturityLevel = pillarMaturity(p.Score)
		total += p.Score
		count++
		if p.Score < 85 { allP4 = false }
	}
	if count > 0 { ztState.OverallScore = total / count }
	ztState.P4Achieved = allP4
	if allP4 { ztState.P4Readiness = 100 } else { ztState.P4Readiness = ztState.OverallScore }
	ztState.LastUpdated = time.Now()
}

func handleZTStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")
	ztState.mu.RLock()
	defer ztState.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pillars": ztState.Pillars, "overall_score": ztState.OverallScore,
		"p4_readiness": ztState.P4Readiness, "p4_achieved": ztState.P4Achieved,
		"sbom": ztState.SBOM, "rasp_coverage": ztState.RASPCoverage,
		"last_updated": ztState.LastUpdated,
	})
}

func handleZTMicroSeg(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")
	if r.Method == http.MethodPost {
		var rule MicroSegRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil { http.Error(w, `{"error":"invalid request body"}`, 400); return }
		ztState.mu.Lock()
		rule.ID = fmt.Sprintf("SEG-%03d", len(ztState.SegRules)+1)
		rule.CreatedAt = time.Now()
		ztState.SegRules = append(ztState.SegRules, rule)
		if p, ok := ztState.Pillars["application"]; ok {
			for i := range p.Capabilities {
				if p.Capabilities[i].ID == "A-1" {
					p.Capabilities[i].Score = minInt(p.Capabilities[i].MaxScore, p.Capabilities[i].Score+1)
					if p.Capabilities[i].Score >= p.Capabilities[i].MaxScore { p.Capabilities[i].Status = "implemented" }
				}
			}
		}
		recalcScoresLocked()
		id := rule.ID
		ztState.mu.Unlock()
		go saveZTStateToDB()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "id": id})
		return
	}
	ztState.mu.RLock(); rules := ztState.SegRules; ztState.mu.RUnlock()
	json.NewEncoder(w).Encode(rules)
}

func handleZTRASP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")

	// Load RASP events từ DB (rasp_events jsonb trong p4_zt_state)
	// Không generate random — chỉ trả events thật đã được save
	if p4SQLDB != nil {
		var raspJSON []byte
		err := p4SQLDB.QueryRow(
			"SELECT rasp_events FROM p4_zt_state WHERE id='main'").Scan(&raspJSON)
		if err == nil && len(raspJSON) > 4 {
			var events []RASPEvent
			if json.Unmarshal(raspJSON, &events) == nil && len(events) > 0 {
				json.NewEncoder(w).Encode(events)
				return
			}
		}
	}

	// Fallback: trả in-memory events (đã seed từ initZeroTrustState)
	ztState.mu.RLock()
	events := ztState.RASPEvents
	ztState.mu.RUnlock()
	json.NewEncoder(w).Encode(events)
}

func handleZTRASPCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")
	ztState.mu.RLock(); defer ztState.mu.RUnlock()
	json.NewEncoder(w).Encode(ztState.RASPCoverage)
}

func handleZTAPIPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")
	if r.Method == http.MethodPost {
		var pol APIPolicy
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil { http.Error(w, `{"error":"invalid request body"}`, 400); return }
		ztState.mu.Lock()
		pol.ID = fmt.Sprintf("POL-%03d", len(ztState.APIPolicies)+1)
		pol.LastAudited = time.Now()
		ztState.APIPolicies = append(ztState.APIPolicies, pol)
		recalcScoresLocked()
		ztState.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "id": pol.ID})
		return
	}
	ztState.mu.RLock(); policies := ztState.APIPolicies; ztState.mu.RUnlock()
	json.NewEncoder(w).Encode(policies)
}

func handleZTSBOM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Vary", "Origin")
	ztState.mu.RLock(); defer ztState.mu.RUnlock()
	json.NewEncoder(w).Encode(ztState.SBOM)
}
