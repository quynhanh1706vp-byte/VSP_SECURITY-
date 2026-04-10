package compliance

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vsp/platform/internal/store"
)

// AssessmentResult is a minimal OSCAL AR structure.
type AssessmentResult struct {
	UUID      string     `json:"uuid"`
	Metadata  ARMetadata `json:"metadata"`
	Results   []ARResult `json:"results"`
	Generated time.Time  `json:"generated"`
}

type ARMetadata struct {
	Title        string    `json:"title"`
	LastModified time.Time `json:"last-modified"`
	Version      string    `json:"version"`
	OSCALVersion string    `json:"oscal-version"`
}

type ARResult struct {
	UUID         string          `json:"uuid"`
	Title        string          `json:"title"`
	Start        time.Time       `json:"start"`
	End          *time.Time      `json:"end,omitempty"`
	Findings     []ARFinding     `json:"findings"`
	Observations []ARObservation `json:"observations"`
	Risks        []ARRisk        `json:"risks"`
}

type ARFinding struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Target      ARTarget `json:"target"`
	RelatedObs  []string `json:"related-observations"`
}

type ARTarget struct {
	Type   string   `json:"type"`
	ID     string   `json:"target-id"`
	Status ARStatus `json:"status"`
}

type ARStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type ARObservation struct {
	UUID        string    `json:"uuid"`
	Title       string    `json:"title"`
	Methods     []string  `json:"methods"`
	Collected   time.Time `json:"collected"`
	Description string    `json:"description"`
}

type ARRisk struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Statement   string `json:"risk-statement"`
	Status      string `json:"status"`
}

// BuildAR generates an OSCAL Assessment Result from scan runs and findings.
func BuildAR(tenantID string, runs []store.Run, findings []store.Finding) *AssessmentResult {
	now := time.Now()
	ar := &AssessmentResult{
		UUID:      fmt.Sprintf("ar-%s-%d", tenantID[:8], now.Unix()),
		Generated: now,
		Metadata: ARMetadata{
			Title:        "VSP Automated Security Assessment",
			LastModified: now,
			Version:      "1.0",
			OSCALVersion: "1.1.2",
		},
	}

	// One result per run
	for _, run := range runs {
		result := ARResult{
			UUID:  fmt.Sprintf("result-%s", run.ID),
			Title: fmt.Sprintf("Scan %s — %s", run.RID, run.Mode),
			Start: run.CreatedAt,
			End:   run.FinishedAt,
		}

		// Add observation for the run
		result.Observations = append(result.Observations, ARObservation{
			UUID:      fmt.Sprintf("obs-%s", run.ID),
			Title:     "Automated Security Scan",
			Methods:   []string{"AUTOMATED"},
			Collected: run.CreatedAt,
			Description: fmt.Sprintf("Mode: %s, Profile: %s, Gate: %s, Posture: %s, Findings: %d",
				run.Mode, run.Profile, run.Gate, run.Posture, run.TotalFindings),
		})

		// Add findings for this run
		for _, f := range findings {
			if f.RunID != run.ID {
				continue
			}
			state := "not-satisfied"
			if f.Severity == "LOW" || f.Severity == "INFO" {
				state = "not-applicable"
			}
			obsID := fmt.Sprintf("obs-f-%s", f.ID)
			result.Findings = append(result.Findings, ARFinding{
				UUID:        fmt.Sprintf("finding-%s", f.ID),
				Title:       fmt.Sprintf("[%s] %s", f.Severity, f.RuleID),
				Description: f.Message,
				Target: ARTarget{
					Type:   "statement-id",
					ID:     f.Path,
					Status: ARStatus{State: state, Reason: f.CWE},
				},
				RelatedObs: []string{obsID},
			})
			// Risk for HIGH/CRITICAL
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				result.Risks = append(result.Risks, ARRisk{
					UUID:        fmt.Sprintf("risk-%s", f.ID),
					Title:       fmt.Sprintf("%s: %s", f.RuleID, f.CWE),
					Description: f.Message,
					Statement:   fmt.Sprintf("File %s line %d presents %s risk", f.Path, f.LineNum, f.Severity),
					Status:      "open",
				})
			}
		}
		ar.Results = append(ar.Results, result)
	}
	return ar
}

// BuildPOAM generates an OSCAL Plan of Action & Milestones.
type POAM struct {
	UUID      string     `json:"uuid"`
	Metadata  ARMetadata `json:"metadata"`
	Items     []POAMItem `json:"poam-items"`
	Generated time.Time  `json:"generated"`
}

type POAMItem struct {
	UUID        string    `json:"uuid"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Origins     []string  `json:"origins"`
	Risk        string    `json:"related-risk"`
	Status      string    `json:"status"`
	DueDate     time.Time `json:"due-date"`
	Remediation string    `json:"remediation"`
}

func BuildPOAM(tenantID string, findings []store.Finding) *POAM {
	now := time.Now()
	poam := &POAM{
		UUID:      fmt.Sprintf("poam-%s-%d", tenantID[:8], now.Unix()),
		Generated: now,
		Metadata: ARMetadata{
			Title:        "VSP Plan of Action & Milestones",
			LastModified: now,
			Version:      "1.0",
			OSCALVersion: "1.1.2",
		},
	}

	for _, f := range findings {
		if f.Severity == "INFO" || f.Severity == "TRACE" {
			continue
		}
		due := now.AddDate(0, 0, dueDays(f.Severity))
		poam.Items = append(poam.Items, POAMItem{
			UUID:        fmt.Sprintf("poam-item-%s", f.ID),
			Title:       fmt.Sprintf("[%s] %s in %s", f.Severity, f.RuleID, f.Path),
			Description: f.Message,
			Origins:     []string{"VSP-Automated-Scanner", f.Tool},
			Risk:        f.CWE,
			Status:      "open",
			DueDate:     due,
			Remediation: f.FixSignal,
		})
	}
	return poam
}

func dueDays(sev string) int {
	switch sev {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 14
	case "MEDIUM":
		return 30
	default:
		return 90
	}
}

func ToJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
