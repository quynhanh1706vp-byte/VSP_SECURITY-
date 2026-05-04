package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OllamaProvider talks to a local Ollama server (default :11434).
// Loopback-only by construction.
type OllamaProvider struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

// NewOllamaProvider constructs an OllamaProvider after validating the URL
// is loopback (127.0.0.1 / localhost / ::1). Returns an error otherwise.
//
// timeoutSec applies per-request. Set to 30 for production, 60+ for CPU.
func NewOllamaProvider(baseURL, model string, timeoutSec int) (*OllamaProvider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, fmt.Errorf("LLM endpoint must be loopback (got %q) — air-gap policy", host)
	}
	if model == "" {
		model = "deepseek-coder-v2:16b"
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &OllamaProvider{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Model:   model,
		Client:  &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
	}, nil
}

func (p *OllamaProvider) Name() string { return "ollama" }

// Health probes the Ollama server. Returns nil if reachable.
func (p *OllamaProvider) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", p.BaseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("llm endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("llm endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// ollamaGenerateRequest matches Ollama /api/generate body schema.
type ollamaGenerateRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	Stream  bool                   `json:"stream"`
	Format  string                 `json:"format,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

type ollamaGenerateResponse struct {
	Model    string `json:"model"`
	Response string `json:"response"`
	Done     bool   `json:"done"`
	EvalCount int   `json:"eval_count"`
}

// GenerateFix calls Ollama /api/generate, parses the JSON response, and
// validates against FixResponse schema. Errors fall back to caller's "manual
// review" path — never surface raw model output.
func (p *OllamaProvider) GenerateFix(ctx context.Context, req FixRequest) (FixResponse, error) {
	start := time.Now()
	prompt := BuildFixPrompt(req)

	body := ollamaGenerateRequest{
		Model:  p.Model,
		Prompt: prompt,
		Stream: false,
		Format: "json", // Ollama JSON mode
		Options: map[string]interface{}{
			"temperature": 0.1,
			"top_p":       0.9,
			"num_predict": 1024,
		},
	}
	data, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.BaseURL+"/api/generate", bytes.NewReader(data))
	if err != nil {
		return FixResponse{}, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(httpReq)
	if err != nil {
		return FixResponse{}, fmt.Errorf("llm call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return FixResponse{}, fmt.Errorf("llm returned status %d", resp.StatusCode)
	}

	var oResp ollamaGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&oResp); err != nil {
		return FixResponse{}, fmt.Errorf("decode ollama response: %w", err)
	}

	// Strip code fences if model wrapped output (some models do despite format=json)
	cleaned := stripCodeFences(oResp.Response)

	var fix FixResponse
	if err := json.Unmarshal([]byte(cleaned), &fix); err != nil {
		return FixResponse{}, fmt.Errorf("parse fix json: %w (raw len=%d)", err, len(cleaned))
	}

	if err := ValidateResponse(fix); err != nil {
		return FixResponse{}, fmt.Errorf("invalid fix response: %w", err)
	}

	fix.Provider = "ollama"
	fix.Model = p.Model
	fix.LatencyMs = time.Since(start).Milliseconds()
	fix.TokensUsed = oResp.EvalCount
	return fix, nil
}

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove first line (e.g. "```json")
		if idx := strings.Index(s, "\n"); idx > 0 {
			s = s[idx+1:]
		}
	}
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
