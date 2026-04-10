package report

import (
	"encoding/json"
	"fmt"
	"github.com/vsp/platform/internal/store"
)

// SARIF 2.1.0 structures
type SARIFDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription SARIFMessage   `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysical `json:"physicalLocation"`
}

type SARIFPhysical struct {
	ArtifactLocation SARIFArtifact `json:"artifactLocation"`
	Region           SARIFRegion   `json:"region"`
}

type SARIFArtifact struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

func severityToLevel(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// BuildSARIF creates a SARIF 2.1.0 document from findings.
func BuildSARIF(run store.Run, findings []store.Finding) *SARIFDoc {
	// Group findings by tool
	byTool := make(map[string][]store.Finding)
	for _, f := range findings {
		if f.RunID == run.ID {
			byTool[f.Tool] = append(byTool[f.Tool], f)
		}
	}

	runs := make([]SARIFRun, 0, len(byTool))
	for tool, toolFindings := range byTool {
		rules := make([]SARIFRule, 0)
		ruleSet := make(map[string]bool)
		results := make([]SARIFResult, 0, len(toolFindings))

		for _, f := range toolFindings {
			if !ruleSet[f.RuleID] && f.RuleID != "" {
				rules = append(rules, SARIFRule{
					ID:               f.RuleID,
					Name:             f.RuleID,
					ShortDescription: SARIFMessage{Text: f.Message},
					Properties:       map[string]any{"cwe": f.CWE, "fix": f.FixSignal},
				})
				ruleSet[f.RuleID] = true
			}
			results = append(results, SARIFResult{
				RuleID:  f.RuleID,
				Level:   severityToLevel(f.Severity),
				Message: SARIFMessage{Text: f.Message},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysical{
						ArtifactLocation: SARIFArtifact{URI: f.Path},
						Region:           SARIFRegion{StartLine: f.LineNum},
					},
				}},
			})
		}

		runs = append(runs, SARIFRun{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:    fmt.Sprintf("VSP/%s", tool),
				Version: "0.3.0",
				Rules:   rules,
			}},
			Results: results,
		})
	}

	return &SARIFDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	}
}

func SARIFToJSON(doc *SARIFDoc) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
