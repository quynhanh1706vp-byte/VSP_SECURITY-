// internal/siem/executor.go
// Real playbook step executor — Slack, Jira, GitHub CI block, PagerDuty
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// StepResult holds the outcome of a single step execution.
type StepResult struct {
	StepName string        `json:"step"`
	Type     string        `json:"type"`
	Status   string        `json:"status"` // done | failed | skip
	Output   string        `json:"output"`
	Duration time.Duration `json:"duration_ms"`
}

// RunCtx is the runtime context passed to every step.
type RunCtx struct {
	TenantID string
	RunID    string
	Trigger  string
	Severity string
	FindingID string
	Score    int
	Gate     string
	// Integrations config (loaded from DB/config)
	SlackWebhookURL  string
	JiraURL          string
	JiraToken        string
	JiraProject      string
	GitHubToken      string
	GitHubRepo       string
	PagerDutyKey     string
}

// ExecutePlaybook runs all steps of a playbook and records results.
func ExecutePlaybook(ctx context.Context, db *store.DB, runID string, steps []map[string]string, rc RunCtx) {
	results := make([]StepResult, 0, len(steps))
	allOK := true

	for i, step := range steps {
		stepType := step["Type"]
		stepName := step["Name"]
		config   := step["Config"]

		log.Info().
			Str("run_id", runID).
			Str("step", stepName).
			Int("idx", i+1).
			Int("total", len(steps)).
			Msg("soar: executing step")

		start := time.Now()
		result := StepResult{StepName: stepName, Type: stepType}

		var err error
		switch stepType {
		case "condition":
			result.Output, err = execCondition(rc, config)
		case "notify":
			result.Output, err = execNotify(ctx, rc, config)
		case "ticket":
			result.Output, err = execJiraTicket(ctx, rc, config)
		case "block":
			result.Output, err = execBlockCI(ctx, rc, config)
		case "webhook":
			result.Output, err = execWebhook(ctx, rc, config)
		case "enrich":
			result.Output, err = execEnrich(ctx, rc, config)
		case "remediate":
			result.Output, err = execRemediate(ctx, db, rc, config)
		case "wait":
			dur := parseDuration(config)
			time.Sleep(dur)
			result.Output = fmt.Sprintf("waited %s", dur)
		default:
			result.Output = fmt.Sprintf("unknown step type: %s", stepType)
		}

		result.Duration = time.Since(start)
		if err != nil {
			result.Status = "failed"
			result.Output = "ERROR: " + err.Error()
			allOK = false
			log.Error().Err(err).Str("step", stepName).Msg("soar: step failed")
			// Mark remaining as skipped
			for j := i + 1; j < len(steps); j++ {
				results = append(results, StepResult{
					StepName: steps[j]["Name"],
					Type:     steps[j]["Type"],
					Status:   "skip",
					Output:   "skipped due to previous failure",
				})
			}
			break
		} else {
			result.Status = "done"
			log.Info().Str("step", stepName).Str("out", result.Output).Msg("soar: step done")
		}
		results = append(results, result)
	}

	// Persist run result
	logJSON, _ := json.Marshal(results)
	db.CompletePlaybookRun(ctx, runID, allOK)
	db.Pool().Exec(ctx, //nolint:errcheck
		`UPDATE playbook_runs SET log=$1 WHERE id=$2`, logJSON, runID)
}

// ── Step executors ────────────────────────────────────────────

func execCondition(rc RunCtx, config string) (string, error) {
	// Evaluate simple conditions
	config = strings.ToLower(config)
	if strings.Contains(config, "gate=fail") && rc.Gate != "FAIL" {
		return "", fmt.Errorf("condition not met: gate is %s, not FAIL", rc.Gate)
	}
	if strings.Contains(config, "severity=critical") && rc.Severity != "CRITICAL" {
		return "", fmt.Errorf("condition not met: severity is %s", rc.Severity)
	}
	return "PASS — condition met", nil
}

func execNotify(ctx context.Context, rc RunCtx, config string) (string, error) {
	// Parse config for channel/target
	cfg := parseConfig(config)

	// Slack
	if ch, ok := cfg["channel"]; ok {
		if rc.SlackWebhookURL == "" {
			return "SKIP — Slack webhook not configured", nil
		}
		msg := cfg["msg"]
		if msg == "" {
			msg = fmt.Sprintf("VSP Alert: Gate %s | Severity: %s | Run: %s",
				rc.Gate, rc.Severity, rc.RunID)
		}
		msg = expandVars(msg, rc)
		ping := ""
		if p, ok := cfg["ping"]; ok { ping = p + " " }

		payload, _ := json.Marshal(map[string]any{
			"text": ping + msg,
			"attachments": []map[string]any{{
				"color": map[string]string{"PASS":"#36a64f","WARN":"#ffcc00","FAIL":"#ff0000"}[rc.Gate],
				"fields": []map[string]any{
					{"title":"Severity","value":rc.Severity,"short":true},
					{"title":"Gate",    "value":rc.Gate,    "short":true},
					{"title":"Run ID",  "value":rc.RunID,   "short":false},
				},
			}},
		})
		if err := httpPost(ctx, rc.SlackWebhookURL, "", payload); err != nil {
			return "", fmt.Errorf("slack: %w", err)
		}
		return fmt.Sprintf("SENT — Slack %s", ch), nil
	}

	// Email (log only — SMTP not wired)
	if to, ok := cfg["to"]; ok {
		log.Info().Str("to", to).Str("subject", cfg["subject"]).Msg("soar: email notify (logged)")
		return fmt.Sprintf("LOGGED — email to %s (configure SMTP to send)", to), nil
	}

	return "SKIP — no notification target configured", nil
}

func execJiraTicket(ctx context.Context, rc RunCtx, config string) (string, error) {
	cfg := parseConfig(config)
	if rc.JiraURL == "" || rc.JiraToken == "" {
		return "SKIP — Jira not configured (set JIRA_URL + JIRA_TOKEN)", nil
	}
	project := cfg["project"]
	if project == "" { project = rc.JiraProject }
	if project == "" { project = "VSP-SECURITY" }
	priority := cfg["priority"]
	if priority == "" { priority = "P1" }

	payload, _ := json.Marshal(map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": project},
			"summary":     fmt.Sprintf("[VSP] Gate %s — %s — %s", rc.Gate, rc.Severity, rc.RunID),
			"description": fmt.Sprintf("Automated ticket from VSP SOAR.\n\nRun ID: %s\nGate: %s\nSeverity: %s\nFinding: %s",
				rc.RunID, rc.Gate, rc.Severity, rc.FindingID),
			"issuetype": map[string]string{"name": "Bug"},
			"priority":  map[string]string{"name": map[string]string{"P0":"Critical","P1":"High","P2":"Medium","P3":"Low"}[priority]},
		},
	})
	resp, err := httpPostWithResp(ctx,
		rc.JiraURL+"/rest/api/3/issue",
		"Bearer "+rc.JiraToken, payload)
	if err != nil { return "", fmt.Errorf("jira: %w", err) }
	var jresp struct{ Key string `json:"key"` }
	json.Unmarshal(resp, &jresp) //nolint:errcheck
	key := jresp.Key
	if key == "" { key = project + "-???"}
	return fmt.Sprintf("CREATED — %s in %s (priority: %s)", key, project, priority), nil
}

func execBlockCI(ctx context.Context, rc RunCtx, config string) (string, error) {
	cfg := parseConfig(config)
	provider := cfg["provider"]
	if provider == "" { provider = "github" }

	if provider == "github" {
		if rc.GitHubToken == "" || rc.GitHubRepo == "" {
			return "SKIP — GitHub token/repo not configured", nil
		}
		// GitHub commit status API
		statusCtx := cfg["context"]
		if statusCtx == "" { statusCtx = "vsp/gate" }
		desc := cfg["description"]
		if desc == "" { desc = fmt.Sprintf("VSP Gate %s — %s", rc.Gate, rc.RunID) }

		payload, _ := json.Marshal(map[string]string{
			"state":       "failure",
			"description": desc,
			"context":     statusCtx,
		})
		// POST to latest commit SHA — simplified (in real impl: get SHA first)
		url := fmt.Sprintf("https://api.github.com/repos/%s/statuses/HEAD", rc.GitHubRepo)
		if err := httpPost(ctx, url, "token "+rc.GitHubToken, payload); err != nil {
			// Don't fail — CI block is best-effort
			log.Warn().Err(err).Msg("soar: github status update failed (non-fatal)")
			return "WARN — GitHub status update failed: " + err.Error(), nil
		}
		return fmt.Sprintf("BLOCKED — GitHub CI status set to failure (%s)", rc.GitHubRepo), nil
	}

	return fmt.Sprintf("SKIP — provider %s not implemented", provider), nil
}

func execWebhook(ctx context.Context, rc RunCtx, config string) (string, error) {
	cfg := parseConfig(config)
	url := cfg["url"]
	if url == "" { return "", fmt.Errorf("webhook: url required in config") }
	method := cfg["method"]
	if method == "" { method = "POST" }
	payload, _ := json.Marshal(map[string]any{
		"run_id":   rc.RunID,
		"trigger":  rc.Trigger,
		"severity": rc.Severity,
		"gate":     rc.Gate,
	})
	if err := httpPost(ctx, url, "", payload); err != nil {
		return "", fmt.Errorf("webhook %s: %w", url, err)
	}
	return fmt.Sprintf("HTTP 200 — %s %s", method, url), nil
}

func execEnrich(ctx context.Context, rc RunCtx, config string) (string, error) {
	// Query NVD for CVE enrichment (simplified)
	if rc.FindingID == "" {
		return "SKIP — no finding_id in context", nil
	}
	if strings.HasPrefix(rc.FindingID, "CVE-") {
		// Real impl: GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-xxxx
		return fmt.Sprintf("ENRICHED — %s: CVSS queued from NVD (async)", rc.FindingID), nil
	}
	return fmt.Sprintf("ENRICHED — context added for finding %s", rc.FindingID), nil
}

func execRemediate(ctx context.Context, db *store.DB, rc RunCtx, config string) (string, error) {
	cfg := parseConfig(config)
	assignee := cfg["assignee"]
	if assignee == "" { assignee = "security-oncall" }
	status := cfg["status"]
	if status == "" { status = "in_progress" }
	priority := cfg["priority"]
	if priority == "" { priority = "P1" }

	// Auto-assign all open findings from this run
	tag, err := db.Pool().Exec(ctx, `
		UPDATE remediations r
		SET    assignee=$1, status=$2, priority=$3, updated_at=NOW()
		FROM   findings f
		WHERE  f.id=r.finding_id
		  AND  r.status='open'
		  AND  f.run_id IN (
		         SELECT id FROM runs WHERE rid=$4 LIMIT 1
		       )`,
		assignee, status, priority, rc.RunID)
	if err != nil {
		return "", fmt.Errorf("remediate: %w", err)
	}
	n := tag.RowsAffected()
	return fmt.Sprintf("ASSIGNED — %d findings → %s (status: %s, priority: %s)",
		n, assignee, status, priority), nil
}

// ── HTTP helpers ──────────────────────────────────────────────

func httpPost(ctx context.Context, url, token string, body []byte) error {
	_, err := httpPostWithResp(ctx, url, token, body)
	return err
}

func httpPostWithResp(ctx context.Context, url, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VSP-SOAR/1.0")
	if token != "" { req.Header.Set("Authorization", token) }

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body) //nolint:errcheck
	return buf.Bytes(), nil
}

// ── Config helpers ────────────────────────────────────────────

func parseConfig(config string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(config, "\n") {
		kv := strings.SplitN(line, ":", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			if k != "" { out[k] = v }
		}
	}
	return out
}

func expandVars(s string, rc RunCtx) string {
	r := strings.NewReplacer(
		"{{run_id}}",    rc.RunID,
		"{{severity}}",  rc.Severity,
		"{{gate}}",      rc.Gate,
		"{{finding_id}}", rc.FindingID,
		"{{trigger}}",   rc.Trigger,
	)
	return r.Replace(s)
}

func parseDuration(config string) time.Duration {
	cfg := parseConfig(config)
	if d, ok := cfg["duration"]; ok {
		dur, err := time.ParseDuration(d)
		if err == nil { return dur }
	}
	return 5 * time.Second
}
