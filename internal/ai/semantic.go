package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// SemanticAnalyzer dùng Claude API để phân tích sâu findings
type SemanticAnalyzer struct {
	httpClient *http.Client
	apiKey     string
}

func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     os.Getenv("ANTHROPIC_API_KEY"),
	}
}

type SemanticResult struct {
	FindingID        string   `json:"finding_id"`
	IsFalsePositive  bool     `json:"is_false_positive"`
	Confidence       float64  `json:"confidence"`    // 0-1
	RealSeverity     string   `json:"real_severity"` // adjusted severity
	Explanation      string   `json:"explanation"`
	ExploitScenario  string   `json:"exploit_scenario"`
	RemediationSteps []string `json:"remediation_steps"`
	References       []string `json:"references"`
	Priority         int      `json:"priority"` // 1-10
}

type BatchSemanticResult struct {
	Results        []SemanticResult `json:"results"`
	Processed      int              `json:"processed"`
	FalsePositives int              `json:"false_positives"`
	Escalated      int              `json:"escalated"`
}

// AnalyzeFinding phân tích 1 finding với Claude
func (a *SemanticAnalyzer) AnalyzeFinding(ctx context.Context, f store.Finding) (*SemanticResult, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	prompt := buildAnalysisPrompt(f)

	reply, err := a.callClaude(ctx, prompt)
	if err != nil {
		return nil, err
	}

	result, err := parseSemanticResult(f.ID, reply)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// AnalyzeBatch phân tích nhiều findings, ưu tiên severity cao
func (a *SemanticAnalyzer) AnalyzeBatch(ctx context.Context, findings []store.Finding, maxItems int) (*BatchSemanticResult, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	// Prioritize: CRITICAL > HIGH, then by tool reliability
	prioritized := prioritizeFindings(findings, maxItems)

	batch := &BatchSemanticResult{}
	for _, f := range prioritized {
		result, err := a.AnalyzeFinding(ctx, f)
		if err != nil {
			log.Warn().Err(err).Str("finding", f.ID).Msg("semantic: analyze failed")
			continue
		}
		batch.Results = append(batch.Results, *result)
		batch.Processed++
		if result.IsFalsePositive {
			batch.FalsePositives++
		}
		if result.RealSeverity == "CRITICAL" && f.Severity != "CRITICAL" {
			batch.Escalated++
		}
	}
	return batch, nil
}

func buildAnalysisPrompt(f store.Finding) string {
	return fmt.Sprintf(`You are a senior security engineer performing triage on a security finding.

Analyze this finding and respond ONLY with a JSON object:

Finding:
- Tool: %s
- Rule ID: %s  
- Severity: %s
- Message: %s
- File: %s (line %d)
- CWE: %s

Respond with ONLY this JSON (no markdown, no explanation outside JSON):
{
  "is_false_positive": false,
  "confidence": 0.9,
  "real_severity": "HIGH",
  "explanation": "brief explanation of why this is/isn't a real issue",
  "exploit_scenario": "how an attacker could exploit this",
  "remediation_steps": ["step 1", "step 2"],
  "references": ["https://..."],
  "priority": 8
}

Consider:
1. Is this a real vulnerability or test/example code?
2. Is the severity accurate given the context?
3. What's the actual exploitability?
4. Priority 1-10 (10 = most urgent)`,
		f.Tool, f.RuleID, f.Severity, f.Message,
		f.Path, f.LineNum, f.CWE,
	)
}

func (a *SemanticAnalyzer) callClaude(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages",
		bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Error != nil {
		return "", fmt.Errorf("claude api: %s", result.Error.Message)
	}
	for _, c := range result.Content {
		if c.Type == "text" {
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("no text content in response")
}

func parseSemanticResult(findingID, reply string) (*SemanticResult, error) {
	// Strip markdown if present
	reply = strings.TrimSpace(reply)
	if idx := strings.Index(reply, "{"); idx >= 0 {
		reply = reply[idx:]
	}
	if idx := strings.LastIndex(reply, "}"); idx >= 0 {
		reply = reply[:idx+1]
	}

	var r struct {
		IsFalsePositive  bool     `json:"is_false_positive"`
		Confidence       float64  `json:"confidence"`
		RealSeverity     string   `json:"real_severity"`
		Explanation      string   `json:"explanation"`
		ExploitScenario  string   `json:"exploit_scenario"`
		RemediationSteps []string `json:"remediation_steps"`
		References       []string `json:"references"`
		Priority         int      `json:"priority"`
	}

	if err := json.Unmarshal([]byte(reply), &r); err != nil {
		return nil, fmt.Errorf("parse failed: %v — raw: %.100s", err, reply)
	}

	return &SemanticResult{
		FindingID:        findingID,
		IsFalsePositive:  r.IsFalsePositive,
		Confidence:       r.Confidence,
		RealSeverity:     r.RealSeverity,
		Explanation:      r.Explanation,
		ExploitScenario:  r.ExploitScenario,
		RemediationSteps: r.RemediationSteps,
		References:       r.References,
		Priority:         r.Priority,
	}, nil
}

func prioritizeFindings(findings []store.Finding, max int) []store.Finding {
	// Sort: CRITICAL first, then HIGH, then by tool reliability
	result := make([]store.Finding, 0, len(findings))
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
		for _, f := range findings {
			if f.Severity == sev {
				result = append(result, f)
				if len(result) >= max {
					return result
				}
			}
		}
	}
	return result
}
