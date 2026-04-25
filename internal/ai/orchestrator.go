package ai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Orchestrator selects between LLM and local-rules sources based on
// configuration, and handles caching transparently.
type Orchestrator struct {
	DB           *sql.DB
	APIKey       string
	AirGapMode   bool
	HTTPClient   *http.Client
	Model        string
	MaxTokens    int
}

// NewOrchestrator constructs an Orchestrator. If apiKey is empty or
// airGap is true, all calls fall back to local rules.
func NewOrchestrator(db *sql.DB, apiKey string, airGap bool) *Orchestrator {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	// Treat placeholder values as absent.
	if strings.Contains(apiKey, "REPLACE_WITH") || strings.HasPrefix(apiKey, "sk-ant-...") {
		apiKey = ""
	}
	return &Orchestrator{
		DB:         db,
		APIKey:     apiKey,
		AirGapMode: airGap,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		Model:      "claude-sonnet-4-20250514",
		MaxTokens:  2000,
	}
}

// Mode returns "claude" or "local" depending on current configuration.
func (o *Orchestrator) Mode() string {
	if o.AirGapMode || o.APIKey == "" {
		return "local"
	}
	return "claude"
}

// Advise is the top-level entry point. It checks cache first, then routes
// to the configured backend, then stores the response.
func (o *Orchestrator) Advise(ctx context.Context, req AdviseRequest) (AdviseResponse, error) {
	if req.Framework == "" || req.ControlID == "" {
		return AdviseResponse{}, fmt.Errorf("framework and control_id required")
	}

	// Try cache
	if o.DB != nil {
		key := req.CacheKey()
		if cached, _, err := CacheLookup(ctx, o.DB, key); err == nil && cached != nil {
			return *cached, nil
		}
	}

	// Fresh call
	var (
		resp     AdviseResponse
		tokIn    int
		tokOut   int
		model    string
		callErr  error
	)

	if o.Mode() == "claude" {
		resp, tokIn, tokOut, model, callErr = o.adviseViaClaude(ctx, req)
		if callErr != nil {
			// Graceful degrade to local on Claude failure.
			resp = LocalAdvise(req.Framework, req.ControlID, req.FindingSummary)
		}
	} else {
		resp = LocalAdvise(req.Framework, req.ControlID, req.FindingSummary)
		model = "local-rules-v1"
	}

	// Store in cache
	if o.DB != nil {
		if id, err := CacheStore(ctx, o.DB, req, resp, tokIn, tokOut, model); err == nil {
			resp.CacheID = id
		}
	}

	return resp, nil
}

// adviseViaClaude calls the Anthropic /messages endpoint with the
// framework-specific system prompt.
func (o *Orchestrator) adviseViaClaude(ctx context.Context, req AdviseRequest) (
	AdviseResponse, int, int, string, error) {

	systemPrompt := FrameworkPrompt(req.Framework, req.ControlID)
	userMsg := UserMessage(req.Framework, req.ControlID, req.FindingSummary, req.Evidence)

	body, _ := json.Marshal(map[string]any{
		"model":      o.Model,
		"max_tokens": o.MaxTokens,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userMsg},
		},
	})

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages",
		bytes.NewReader(body))
	if err != nil {
		return AdviseResponse{}, 0, 0, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", o.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := o.HTTPClient.Do(httpReq)
	if err != nil {
		return AdviseResponse{}, 0, 0, "", err
	}
	defer httpResp.Body.Close()

	respBytes, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != 200 {
		return AdviseResponse{}, 0, 0, "", fmt.Errorf("anthropic %d: %s", httpResp.StatusCode, string(respBytes))
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBytes, &apiResp); err != nil {
		return AdviseResponse{}, 0, 0, "", err
	}

	if len(apiResp.Content) == 0 {
		return AdviseResponse{}, 0, 0, "", fmt.Errorf("empty response from claude")
	}

	// Parse JSON out of the text content (LLM may wrap in markdown fences)
	text := apiResp.Content[0].Text
	text = stripCodeFence(text)

	var advise AdviseResponse
	if err := json.Unmarshal([]byte(text), &advise); err != nil {
		// LLM returned malformed JSON — wrap into a basic response so
		// the user still sees the raw guidance.
		advise = AdviseResponse{
			Remediation: text,
			EffortHours: EffortHours{Junior: 8, Mid: 4, Senior: 2},
			Evidence:    "See remediation section above.",
			References:  []string{req.ControlID},
		}
	}
	advise.Source = "claude"
	return advise, apiResp.Usage.InputTokens, apiResp.Usage.OutputTokens, apiResp.Model, nil
}

// stripCodeFence removes common ```json ... ``` wrappers around LLM output.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Drop first line
		if nl := strings.Index(s, "\n"); nl > 0 {
			s = s[nl+1:]
		}
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	return s
}
