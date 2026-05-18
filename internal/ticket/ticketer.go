// Package ticket provides a multi-provider implementation of soar.Ticketer.
//
// Supported systems (case-insensitive):
//
//	jira       — Jira Cloud REST API v3 issue create
//	pagerduty  — PagerDuty Events API v2 trigger
//	github     — GitHub Issues create (token or App)
//
// All providers fail soft when their respective config is missing — they
// return an error explaining the missing config so playbooks remain
// inspectable in dev environments without leaking real credentials.
package ticket

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Config carries credentials and defaults for ticketing providers. All fields
// are optional; only providers with required fields populated are usable.
type Config struct {
	// Jira Cloud
	JiraBaseURL  string // e.g. https://acme.atlassian.net
	JiraEmail    string // login email
	JiraAPIToken string // user API token (basic auth)

	// PagerDuty Events API v2
	PagerDutyRoutingKey string // integration routing key

	// GitHub
	GitHubBaseURL string // default https://api.github.com
	GitHubToken   string // PAT or App installation token
	GitHubRepo    string // default "owner/repo" if not given in project

	HTTPTimeout time.Duration
}

// MultiTicketer dispatches Create calls to the right provider. Implements
// soar.Ticketer.
type MultiTicketer struct {
	cfg    Config
	client *http.Client
}

// New constructs a MultiTicketer with the given config.
func New(cfg Config) *MultiTicketer {
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 20 * time.Second
	}
	if cfg.GitHubBaseURL == "" {
		cfg.GitHubBaseURL = "https://api.github.com"
	}
	return &MultiTicketer{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.HTTPTimeout},
	}
}

// Create routes to the correct provider. Returns ticket ID + URL on success.
func (t *MultiTicketer) Create(ctx context.Context, system, project, summary, desc string, params map[string]interface{}) (string, string, error) {
	system = strings.ToLower(strings.TrimSpace(system))

	switch system {
	case "jira":
		return t.createJira(ctx, project, summary, desc, params)
	case "pagerduty", "pd":
		return t.createPagerDuty(ctx, summary, desc, params)
	case "github":
		return t.createGitHub(ctx, project, summary, desc, params)
	default:
		return "", "", fmt.Errorf("ticket: unsupported system %q", system)
	}
}

// ── Jira ──────────────────────────────────────────────────────────────────

type jiraIssueCreate struct {
	Fields jiraFields `json:"fields"`
}
type jiraFields struct {
	Project   jiraKey       `json:"project"`
	Summary   string        `json:"summary"`
	IssueType jiraIssueType `json:"issuetype"`
	Priority  *jiraName     `json:"priority,omitempty"`
	Labels    []string      `json:"labels,omitempty"`
	// Description: ADF (Atlassian Document Format) wrapper for plain text.
	Description map[string]interface{} `json:"description,omitempty"`
}
type jiraKey struct {
	Key string `json:"key"`
}
type jiraName struct {
	Name string `json:"name"`
}
type jiraIssueType struct {
	Name string `json:"name"`
}
type jiraCreateResp struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	// Self URL
}

func (t *MultiTicketer) createJira(ctx context.Context, project, summary, desc string, params map[string]interface{}) (string, string, error) {
	if t.cfg.JiraBaseURL == "" || t.cfg.JiraEmail == "" || t.cfg.JiraAPIToken == "" {
		return "", "", fmt.Errorf("ticket[jira]: base_url, email, api_token required")
	}
	if project == "" {
		return "", "", fmt.Errorf("ticket[jira]: project key required")
	}
	issueType := "Task"
	if it, ok := params["issue_type"].(string); ok && it != "" {
		issueType = it
	}
	body := jiraIssueCreate{
		Fields: jiraFields{
			Project:     jiraKey{Key: project},
			Summary:     summary,
			IssueType:   jiraIssueType{Name: issueType},
			Description: adfPlain(desc),
		},
	}
	if pr, ok := params["priority"].(string); ok && pr != "" {
		body.Fields.Priority = &jiraName{Name: pr}
	}
	if labels, ok := params["labels"].([]string); ok {
		body.Fields.Labels = labels
	} else if labelsAny, ok := params["labels"].([]interface{}); ok {
		for _, l := range labelsAny {
			if s, ok := l.(string); ok {
				body.Fields.Labels = append(body.Fields.Labels, s)
			}
		}
	}

	auth := base64.StdEncoding.EncodeToString([]byte(t.cfg.JiraEmail + ":" + t.cfg.JiraAPIToken))
	endpoint := strings.TrimRight(t.cfg.JiraBaseURL, "/") + "/rest/api/3/issue"

	respBody, err := t.doJSON(ctx, http.MethodPost, endpoint, body, map[string]string{
		"Authorization": "Basic " + auth,
	}, "jira")
	if err != nil {
		return "", "", err
	}
	var parsed jiraCreateResp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", fmt.Errorf("ticket[jira]: parse response: %w", err)
	}
	url := strings.TrimRight(t.cfg.JiraBaseURL, "/") + "/browse/" + parsed.Key
	return parsed.Key, url, nil
}

// adfPlain wraps a plain-text string in Atlassian Document Format for v3 API.
func adfPlain(text string) map[string]interface{} {
	if text == "" {
		return nil
	}
	return map[string]interface{}{
		"type":    "doc",
		"version": 1,
		"content": []map[string]interface{}{
			{
				"type": "paragraph",
				"content": []map[string]interface{}{
					{"type": "text", "text": text},
				},
			},
		},
	}
}

// ── PagerDuty ─────────────────────────────────────────────────────────────

type pdEvent struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	DedupKey    string    `json:"dedup_key,omitempty"`
	Payload     pdPayload `json:"payload"`
}
type pdPayload struct {
	Summary       string `json:"summary"`
	Source        string `json:"source"`
	Severity      string `json:"severity"`
	CustomDetails any    `json:"custom_details,omitempty"`
}
type pdResp struct {
	Status   string `json:"status"`
	DedupKey string `json:"dedup_key"`
	Message  string `json:"message"`
}

func (t *MultiTicketer) createPagerDuty(ctx context.Context, summary, desc string, params map[string]interface{}) (string, string, error) {
	if t.cfg.PagerDutyRoutingKey == "" {
		return "", "", fmt.Errorf("ticket[pagerduty]: routing_key required")
	}
	severity := "error"
	if s, ok := params["severity"].(string); ok && s != "" {
		// Normalize: PD accepts: critical | error | warning | info
		switch strings.ToLower(s) {
		case "critical", "p0":
			severity = "critical"
		case "high", "error", "p1":
			severity = "error"
		case "medium", "warning", "warn", "p2":
			severity = "warning"
		case "low", "info", "p3", "p4":
			severity = "info"
		default:
			severity = strings.ToLower(s)
		}
	}
	source := "vsp-soar"
	if src, ok := params["source"].(string); ok && src != "" {
		source = src
	}
	dedup, _ := params["dedup_key"].(string)
	ev := pdEvent{
		RoutingKey:  t.cfg.PagerDutyRoutingKey,
		EventAction: "trigger",
		DedupKey:    dedup,
		Payload: pdPayload{
			Summary:       summary,
			Source:        source,
			Severity:      severity,
			CustomDetails: map[string]interface{}{"description": desc},
		},
	}
	respBody, err := t.doJSON(ctx, http.MethodPost,
		"https://events.pagerduty.com/v2/enqueue", ev, nil, "pagerduty")
	if err != nil {
		return "", "", err
	}
	var parsed pdResp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", fmt.Errorf("ticket[pagerduty]: parse response: %w", err)
	}
	if parsed.Status != "success" {
		return "", "", fmt.Errorf("ticket[pagerduty]: %s — %s", parsed.Status, parsed.Message)
	}
	// PagerDuty doesn't return a browser URL for enqueue; dedup_key is the handle.
	return parsed.DedupKey, "", nil
}

// ── GitHub ────────────────────────────────────────────────────────────────

type ghIssueCreate struct {
	Title    string   `json:"title"`
	Body     string   `json:"body,omitempty"`
	Labels   []string `json:"labels,omitempty"`
	Assignee string   `json:"assignee,omitempty"`
}
type ghIssueResp struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	NodeID  string `json:"node_id"`
}

func (t *MultiTicketer) createGitHub(ctx context.Context, project, summary, desc string, params map[string]interface{}) (string, string, error) {
	if t.cfg.GitHubToken == "" {
		return "", "", fmt.Errorf("ticket[github]: token required")
	}
	repo := project
	if repo == "" {
		repo = t.cfg.GitHubRepo
	}
	if repo == "" || !strings.Contains(repo, "/") {
		return "", "", fmt.Errorf("ticket[github]: project must be 'owner/repo'")
	}
	body := ghIssueCreate{Title: summary, Body: desc}
	if labels, ok := params["labels"].([]string); ok {
		body.Labels = labels
	} else if labelsAny, ok := params["labels"].([]interface{}); ok {
		for _, l := range labelsAny {
			if s, ok := l.(string); ok {
				body.Labels = append(body.Labels, s)
			}
		}
	}
	if a, ok := params["assignee"].(string); ok {
		body.Assignee = a
	}
	endpoint := strings.TrimRight(t.cfg.GitHubBaseURL, "/") + "/repos/" + repo + "/issues"
	respBody, err := t.doJSON(ctx, http.MethodPost, endpoint, body, map[string]string{
		"Authorization": "Bearer " + t.cfg.GitHubToken,
		"Accept":        "application/vnd.github+json",
	}, "github")
	if err != nil {
		return "", "", err
	}
	var parsed ghIssueResp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", fmt.Errorf("ticket[github]: parse response: %w", err)
	}
	id := fmt.Sprintf("%s#%d", repo, parsed.Number)
	return id, parsed.HTMLURL, nil
}

// ── Helper ────────────────────────────────────────────────────────────────

func (t *MultiTicketer) doJSON(ctx context.Context, method, url string, payload interface{}, headers map[string]string, provider string) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("ticket[%s]: marshal: %w", provider, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ticket[%s]: build request: %w", provider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VSP-SOAR-Ticketer/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ticket[%s]: post: %w", provider, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody := bytes.NewBuffer(nil)
	_, _ = respBody.ReadFrom(resp.Body)

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ticket[%s]: http %d — %s", provider, resp.StatusCode, truncate(respBody.String(), 200))
	}
	log.Info().Str("provider", provider).Int("status", resp.StatusCode).Msg("ticket: created")
	return respBody.Bytes(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
