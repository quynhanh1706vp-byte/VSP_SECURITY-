// Package cspm aggregates IaC scan findings from kics, checkov, hadolint
// into Cloud Security Posture Management style metrics.
package cspm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type CloudProvider string

const (
	AWS   CloudProvider = "aws"
	GCP   CloudProvider = "gcp"
	Azure CloudProvider = "azure"
	K8s   CloudProvider = "kubernetes"
	Other CloudProvider = "other"
)

type PostureScore struct {
	Provider     CloudProvider `json:"provider"`
	Score        float64       `json:"score"` // 0-100
	Critical     int           `json:"critical"`
	High         int           `json:"high"`
	Medium       int           `json:"medium"`
	Low          int           `json:"low"`
	TotalChecks  int           `json:"total_checks"`
	PassedChecks int           `json:"passed_checks"`
}

type Aggregator struct {
	Findings []Finding
}

type Finding struct {
	Tool      string `json:"tool"`     // kics / checkov / hadolint
	Severity  string `json:"severity"` // critical / high / medium / low
	Resource  string `json:"resource"` // e.g., aws_s3_bucket
	Provider  CloudProvider `json:"provider"`
	RuleID    string `json:"rule_id"`
	Message   string `json:"message"`
	File      string `json:"file"`
}

// New creates an aggregator from raw scanner findings.
func New(findings []Finding) *Aggregator {
	return &Aggregator{Findings: findings}
}

// Score returns posture score per provider.
func (a *Aggregator) Score(ctx context.Context) []PostureScore {
	groups := make(map[CloudProvider][]Finding)
	for _, f := range a.Findings {
		groups[f.Provider] = append(groups[f.Provider], f)
	}

	var scores []PostureScore
	for prov, fs := range groups {
		score := PostureScore{Provider: prov, TotalChecks: len(fs)}
		for _, f := range fs {
			switch strings.ToLower(f.Severity) {
			case "critical":
				score.Critical++
			case "high":
				score.High++
			case "medium":
				score.Medium++
			case "low":
				score.Low++
			}
		}
		// Weighted score: critical=10, high=5, medium=2, low=1
		penalty := score.Critical*10 + score.High*5 + score.Medium*2 + score.Low*1
		base := score.TotalChecks * 10
		if base > 0 {
			score.Score = float64(base-penalty) / float64(base) * 100.0
			if score.Score < 0 {
				score.Score = 0
			}
		} else {
			score.Score = 100.0
		}
		score.PassedChecks = score.TotalChecks - score.Critical - score.High - score.Medium - score.Low
		scores = append(scores, score)
	}
	return scores
}

// DetectProvider attempts to identify cloud provider from resource type.
func DetectProvider(resource string) CloudProvider {
	r := strings.ToLower(resource)
	switch {
	case strings.HasPrefix(r, "aws_"), strings.Contains(r, "s3"), strings.Contains(r, "ec2"), strings.Contains(r, "iam"):
		return AWS
	case strings.HasPrefix(r, "google_"), strings.Contains(r, "gcp"), strings.Contains(r, "gke"):
		return GCP
	case strings.HasPrefix(r, "azurerm_"), strings.Contains(r, "azure"):
		return Azure
	case strings.Contains(r, "kubernetes"), strings.Contains(r, "k8s"), strings.Contains(r, "deployment"), strings.Contains(r, "pod"):
		return K8s
	default:
		return Other
	}
}

// Summary returns a human-readable posture summary.
func (a *Aggregator) Summary() string {
	scores := a.Score(context.Background())
	var sb strings.Builder
	sb.WriteString("CSPM Posture Summary:\n")
	for _, s := range scores {
		sb.WriteString(fmt.Sprintf("  %s: %.1f/100 (C:%d H:%d M:%d L:%d / %d checks)\n",
			s.Provider, s.Score, s.Critical, s.High, s.Medium, s.Low, s.TotalChecks))
	}
	return sb.String()
}

// MarshalScores returns scores as JSON.
func (a *Aggregator) MarshalScores() ([]byte, error) {
	return json.MarshalIndent(a.Score(context.Background()), "", "  ")
}
