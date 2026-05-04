package soar

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────────────────────────
// http — HTTP request with retry, timeout, SSRF guard
//
// Config:
//   {
//     "url": "https://hooks.slack.com/...",
//     "method": "POST",
//     "headers": {"Authorization": "Bearer ${secrets.token}"},
//     "body": {"text":"alert"},  // auto-JSON-encoded if object
//     "body_raw": "raw string",  // alternative
//     "timeout_seconds": 10,
//     "expect_status": [200, 201, 204]  // optional; default any 2xx
//   }
// ─────────────────────────────────────────────────────────────────

type httpExecutor struct {
	client HTTPDoer
}

// NewHTTPExecutor — pass SafeHTTPClient or any HTTPDoer impl.
func NewHTTPExecutor(client HTTPDoer) StepExecutor {
	return &httpExecutor{client: client}
}

type httpConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers"`
	Body           json.RawMessage   `json:"body,omitempty"`     // object → JSON
	BodyRaw        string            `json:"body_raw,omitempty"` // string → as-is
	TimeoutSeconds int               `json:"timeout_seconds"`
	ExpectStatus   []int             `json:"expect_status,omitempty"`
}

func (e *httpExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[httpConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.URL == "" {
		return nil, "", fmt.Errorf("http: url required")
	}

	// Resolve ${secrets.X} and ${ctx.X} in URL + headers
	resolvedURL := resolveTemplate(cfg.URL, ec, ctx)
	resolvedHeaders := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		resolvedHeaders[k] = resolveTemplate(v, ec, ctx)
	}

	// Body: raw takes precedence; else marshal Body object
	var bodyBytes []byte
	switch {
	case cfg.BodyRaw != "":
		bodyBytes = []byte(resolveTemplate(cfg.BodyRaw, ec, ctx))
	case len(cfg.Body) > 0:
		bodyBytes = []byte(resolveTemplate(string(cfg.Body), ec, ctx))
		// Set default content-type if not set
		if _, ok := resolvedHeaders["Content-Type"]; !ok {
			resolvedHeaders["Content-Type"] = "application/json"
		}
	}

	if ec.IsTest {
		// Mock response in test mode — don't actually send
		mock := map[string]interface{}{
			"_test_mode":  true,
			"would_call":  resolvedURL,
			"method":      defaultStr(cfg.Method, "GET"),
			"status_code": 200,
		}
		out, err := json.Marshal(mock)
		return out, "", err
	}

	if e.client == nil {
		return nil, "", fmt.Errorf("http: no client configured")
	}

	req := &HTTPReq{
		Method:         cfg.Method,
		URL:            resolvedURL,
		Headers:        resolvedHeaders,
		Body:           bodyBytes,
		TimeoutSeconds: cfg.TimeoutSeconds,
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("http: %w", err)
	}

	// Check expected status
	if len(cfg.ExpectStatus) > 0 {
		ok := false
		for _, s := range cfg.ExpectStatus {
			if s == resp.StatusCode {
				ok = true
				break
			}
		}
		if !ok {
			return nil, "", fmt.Errorf("http: status %d not in expected %v", resp.StatusCode, cfg.ExpectStatus)
		}
	} else if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("http: status %d", resp.StatusCode)
	}

	// Try to parse JSON response
	var bodyJSON interface{}
	if err := json.Unmarshal(resp.Body, &bodyJSON); err != nil {
		bodyJSON = string(resp.Body)
	}

	result := map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers":     resp.Headers,
		"body":        bodyJSON,
	}
	out, err := json.Marshal(result)
	return out, "", err
}

// ─────────────────────────────────────────────────────────────────
// notify — multi-channel notification
//
// Config:
//   {
//     "channel": "slack",  // slack | email | teams | discord | webhook
//     "to": "#security-alerts" or "user@example.com",
//     "message": "Alert: ${ctx.severity}",
//     "template": "incident_summary",  // optional named template
//     "params": {...}                  // template params
//   }
//
// This is a thin wrapper that builds a request descriptor. Actual delivery
// happens in handler layer (which has SMTP/Slack creds wired in).
// In runtime production use, engine wires `notifier` callback that
// translates to actual send.
// ─────────────────────────────────────────────────────────────────

type Notifier interface {
	Send(ctx context.Context, channel, to, message, template string, params map[string]interface{}) error
}

type notifyExecutor struct {
	notifier Notifier
}

// NewNotifyExecutor — pass nil to make this a descriptor-only step (test mode).
func NewNotifyExecutor(n Notifier) StepExecutor {
	return &notifyExecutor{notifier: n}
}

type notifyConfig struct {
	Channel  string                 `json:"channel"`
	To       string                 `json:"to"`
	Message  string                 `json:"message"`
	Template string                 `json:"template,omitempty"`
	Params   map[string]interface{} `json:"params,omitempty"`
}

func (e *notifyExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[notifyConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.Channel == "" {
		// Try legacy: parse YAML config_raw
		legacy := parseLegacyConfig(n.ConfigRaw)
		if legacy["channel"] != "" {
			cfg.Channel = "slack" // legacy notify with #channel implies slack
			cfg.To = legacy["channel"]
			cfg.Message = legacy["template"]
			if cfg.Message == "" {
				cfg.Message = legacy["ping"]
			}
		} else if legacy["to"] != "" {
			cfg.Channel = "email"
			cfg.To = legacy["to"]
			cfg.Template = legacy["template"]
		}
	}
	if cfg.Channel == "" {
		return nil, "", fmt.Errorf("notify: channel required")
	}

	// Resolve templates
	cfg.Message = resolveTemplate(cfg.Message, ec, ctx)
	cfg.To = resolveTemplate(cfg.To, ec, ctx)

	if ec.IsTest || e.notifier == nil {
		mock := map[string]interface{}{
			"_test_mode": ec.IsTest,
			"channel":    cfg.Channel,
			"to":         cfg.To,
			"message":    cfg.Message,
			"template":   cfg.Template,
			"sent":       false,
			"reason":     "test mode or notifier not configured",
		}
		out, err := json.Marshal(mock)
		return out, "", err
	}

	if err := e.notifier.Send(ctx, cfg.Channel, cfg.To, cfg.Message, cfg.Template, cfg.Params); err != nil {
		return nil, "", fmt.Errorf("notify: %w", err)
	}

	result := map[string]interface{}{
		"channel": cfg.Channel,
		"to":      cfg.To,
		"sent":    true,
	}
	out, err := json.Marshal(result)
	return out, "", err
}

// ─────────────────────────────────────────────────────────────────
// ticket — create or update issue in tracking system
//
// Config:
//   {
//     "system": "jira",  // jira | github | gitlab | servicenow | pagerduty
//     "action": "create",  // create | comment | transition | close
//     "project": "VSP-SEC",
//     "summary": "[CRITICAL] ${ctx.title}",
//     "description": "...",
//     "priority": "P1",
//     "assignee": "security-team",
//     "labels": ["security", "auto"]
//   }
// ─────────────────────────────────────────────────────────────────

type Ticketer interface {
	Create(ctx context.Context, system, project, summary, desc string, params map[string]interface{}) (ticketID, url string, err error)
}

type ticketExecutor struct {
	ticketer Ticketer
}

func NewTicketExecutor(t Ticketer) StepExecutor {
	return &ticketExecutor{ticketer: t}
}

type ticketConfig struct {
	System      string                 `json:"system"`
	Action      string                 `json:"action"`
	Project     string                 `json:"project"`
	Summary     string                 `json:"summary"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority,omitempty"`
	Assignee    string                 `json:"assignee,omitempty"`
	Labels      []string               `json:"labels,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

func (e *ticketExecutor) Run(ctx context.Context, n *Node, ec *ExecCtx) (json.RawMessage, string, error) {
	cfg, err := parseConfig[ticketConfig](n)
	if err != nil {
		return nil, "", err
	}
	if cfg.System == "" {
		// Try legacy
		legacy := parseLegacyConfig(n.ConfigRaw)
		if legacy["project"] != "" {
			cfg.System = "jira" // default for legacy
			cfg.Project = legacy["project"]
			cfg.Priority = legacy["priority"]
			cfg.Assignee = legacy["auto_assign"]
			cfg.Action = "create"
			cfg.Summary = "Auto-created from playbook"
		}
	}
	if cfg.System == "" {
		return nil, "", fmt.Errorf("ticket: system required")
	}
	if cfg.Action == "" {
		cfg.Action = "create"
	}

	// Resolve templates
	cfg.Summary = resolveTemplate(cfg.Summary, ec, ctx)
	cfg.Description = resolveTemplate(cfg.Description, ec, ctx)

	if ec.IsTest || e.ticketer == nil {
		mock := map[string]interface{}{
			"_test_mode":          ec.IsTest,
			"system":              cfg.System,
			"action":              cfg.Action,
			"project":             cfg.Project,
			"summary":             cfg.Summary,
			"would_create_ticket": true,
		}
		out, err := json.Marshal(mock)
		return out, "", err
	}

	params := map[string]interface{}{
		"priority": cfg.Priority,
		"assignee": cfg.Assignee,
		"labels":   cfg.Labels,
	}
	for k, v := range cfg.Extra {
		params[k] = v
	}

	id, url, err := e.ticketer.Create(ctx, cfg.System, cfg.Project, cfg.Summary, cfg.Description, params)
	if err != nil {
		return nil, "", fmt.Errorf("ticket: %w", err)
	}

	result := map[string]interface{}{
		"system":    cfg.System,
		"action":    cfg.Action,
		"ticket_id": id,
		"url":       url,
	}
	out, err := json.Marshal(result)
	return out, "", err
}

// ─────────────────────────────────────────────────────────────────
// Template resolver: ${secrets.X}, ${ctx.X.Y}, ${steps.NID.X}
// ─────────────────────────────────────────────────────────────────

// resolveTemplate substitutes ${...} placeholders in s.
//
// Supported:
//   - ${ctx.path}      — from ec.Vars via resolvePath
//   - ${steps.id.path} — from ec.StepOutputs
//   - ${secrets.name}  — from ec.Secrets.Resolve
//
// Missing values become empty string. Errors from secret lookup propagate
// as the literal string "[SECRET_ERROR]" (we don't fail the step here;
// caller can detect and abort if needed).
func resolveTemplate(s string, ec *ExecCtx, ctx context.Context) string {
	if !strings.Contains(s, "${") {
		return s
	}
	var sb strings.Builder
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			end := strings.Index(s[i+2:], "}")
			if end < 0 {
				sb.WriteString(s[i:])
				break
			}
			expr := s[i+2 : i+2+end]
			sb.WriteString(resolveExpr(expr, ec, ctx))
			i = i + 2 + end + 1
		} else {
			sb.WriteByte(s[i])
			i++
		}
	}
	return sb.String()
}

func resolveExpr(expr string, ec *ExecCtx, ctx context.Context) string {
	if strings.HasPrefix(expr, "secrets.") {
		name := strings.TrimPrefix(expr, "secrets.")
		if ec.Secrets == nil {
			return ""
		}
		v, err := ec.Secrets.Resolve(ctx, name)
		if err != nil {
			return "[SECRET_ERROR]"
		}
		return v
	}
	if strings.HasPrefix(expr, "ctx.") || strings.HasPrefix(expr, "steps.") {
		v := resolvePath(ec, expr)
		if v == nil {
			return ""
		}
		switch x := v.(type) {
		case string:
			return x
		default:
			b, _ := json.Marshal(x)
			return string(b)
		}
	}
	// Unknown root — return literal
	return "${" + expr + "}"
}
