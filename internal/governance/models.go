package governance

import "time"

type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

type RiskItem struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Level       RiskLevel `json:"level"`
	Status      string    `json:"status"` // open|mitigated|accepted|closed
	Owner       string    `json:"owner"`
	FindingID   string    `json:"finding_id,omitempty"`
	DueDate     time.Time `json:"due_date"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ControlOwner struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Control   string `json:"control"`   // e.g. "AC-2", "SI-10"
	Framework string `json:"framework"` // NIST|ISO27001|SOC2|PCI
	Owner     string `json:"owner"`
	Team      string `json:"team"`
	Status    string `json:"status"` // implemented|partial|planned|not-implemented
}

type Evidence struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Title     string     `json:"title"`
	Type      string     `json:"type"` // scan|screenshot|policy|attestation
	RunID     string     `json:"run_id,omitempty"`
	Path      string     `json:"path"`
	Hash      string     `json:"hash"`
	Frozen    bool       `json:"frozen"`
	FrozenAt  *time.Time `json:"frozen_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type TraceabilityRow struct {
	FindingID  string `json:"finding_id"`
	Severity   string `json:"severity"`
	RuleID     string `json:"rule_id"`
	Control    string `json:"control"`
	Framework  string `json:"framework"`
	EvidenceID string `json:"evidence_id"`
	Status     string `json:"status"`
}

type FrameworkScore struct {
	Framework string        `json:"framework"`
	Score     int           `json:"score"`
	Domains   []DomainScore `json:"domains"`
}

type DomainScore struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
	Items int    `json:"items"`
	Pass  int    `json:"pass"`
}

type RoadmapItem struct {
	Quarter  string `json:"quarter"`
	Title    string `json:"title"`
	Priority string `json:"priority"`
	Status   string `json:"status"`
	Category string `json:"category"`
}

type ZeroTrustPillar struct {
	Pillar   string   `json:"pillar"`
	Score    int      `json:"score"`
	Level    string   `json:"level"` // Traditional|Advanced|Optimal
	Findings int      `json:"open_findings"`
	Controls []string `json:"key_controls"`
}
