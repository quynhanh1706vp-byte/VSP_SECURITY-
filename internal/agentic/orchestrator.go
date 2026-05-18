// =====================================================================
// H3.T Agentic Autofix — Orchestrator (ReAct loop)
// File: internal/agentic/orchestrator.go
// =====================================================================
//
// Multi-turn LLM reasoning loop:
//   turn 0: system prompt + finding context
//   turn N: LLM emits {thought, tool_call} OR {thought, final_answer}
//   we run the tool, append observation, increment turn
//   stop on final_answer OR turn == max_turns
//
// Every turn is persisted to agentic_trace (CMMC AU-2/AU-3).
// LLM transport: ollama HTTP /api/generate (deepseek-coder-v2:16b).
//
// Telemetry hooks (H3.W):
//   - increments agentic_turn_total{role,tool}
//   - observes agentic_turn_duration_seconds
//   - emits OTLP span per session

package agentic

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultMaxTurns  = 5
	hardMaxTurns     = 10 // matches DB CHECK constraint
	llmTimeout       = 300 * time.Second
	tokenSoftBudget  = 8000 // total prompt + reply tokens per session
	traceOutputCapKB = 4
)

// Telemetry — minimal interface so orchestrator doesn't import H3.W package
// (avoids circular deps). Real impl provided by metrics.go.
type Telemetry interface {
	CounterInc(name string, labels map[string]string)
	HistogramObserve(name string, seconds float64, labels map[string]string)
	StartSpan(ctx context.Context, op string, attrs map[string]any) (context.Context, func(status int, err error))
}

// noopTelemetry — used when H3.W is disabled
type noopTelemetry struct{}

func (noopTelemetry) CounterInc(string, map[string]string)                {}
func (noopTelemetry) HistogramObserve(string, float64, map[string]string) {}
func (noopTelemetry) StartSpan(ctx context.Context, op string, _ map[string]any) (context.Context, func(int, error)) {
	return ctx, func(int, error) {}
}

// =====================================================================
// Orchestrator
// =====================================================================

type Orchestrator struct {
	DB        *sql.DB
	Tools     *ToolBox
	OllamaURL string // e.g. http://127.0.0.1:11434
	Model     string // e.g. deepseek-coder-v2:16b
	MaxTurns  int
	Telem     Telemetry
}

func NewOrchestrator(db *sql.DB, tools *ToolBox) *Orchestrator {
	o := &Orchestrator{
		DB:        db,
		Tools:     tools,
		OllamaURL: getEnv("OLLAMA_URL", "http://127.0.0.1:11434"),
		Model:     getEnv("OLLAMA_MODEL", "deepseek-coder-v2:16b"),
		MaxTurns:  defaultMaxTurns,
		Telem:     noopTelemetry{},
	}
	if mt := os.Getenv("AGENTIC_MAX_TURNS"); mt != "" {
		if n, _ := fmt.Sscanf(mt, "%d", &o.MaxTurns); n == 1 && o.MaxTurns > 0 && o.MaxTurns <= hardMaxTurns {
			// ok
		} else {
			o.MaxTurns = defaultMaxTurns
		}
	}
	return o
}

// RunRequest — input from POST /agentic/run
type RunRequest struct {
	CacheKey   string `json:"cache_key"`
	FindingID  string `json:"finding_id"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Tool       string `json:"tool"` // sast/sca/secrets/iac
	Message    string `json:"message"`
	FilePath   string `json:"file_path,omitempty"`
	LineNumber int    `json:"line_number,omitempty"`
	RepoRoot   string `json:"repo_root,omitempty"` // override default
}

// RunResult — what /agentic/run returns
type RunResult struct {
	SessionID   string  `json:"session_id"`
	Turns       int     `json:"turns"`
	Converged   bool    `json:"converged"`
	FinalAnswer string  `json:"final_answer"`
	TotalTokens int     `json:"total_tokens"`
	DurationMS  int64   `json:"duration_ms"`
	Confidence  float64 `json:"confidence,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// =====================================================================
// Run — main entry point
// =====================================================================

func (o *Orchestrator) Run(ctx context.Context, req RunRequest) (*RunResult, error) {
	if req.FindingID == "" || req.CacheKey == "" {
		return nil, errors.New("cache_key and finding_id required")
	}

	sessionID := uuid.NewString()
	startWall := time.Now()

	ctx, endSpan := o.Telem.StartSpan(ctx, "agentic.session", map[string]any{
		"session_id": sessionID,
		"finding_id": req.FindingID,
		"rule_id":    req.RuleID,
		"severity":   req.Severity,
		"max_turns":  o.MaxTurns,
	})
	defer func() { endSpan(0, nil) }()

	result := &RunResult{SessionID: sessionID}

	// turn 0 — system prompt
	systemPrompt := o.buildSystemPrompt(req)
	o.persistTrace(ctx, sessionID, req, 0, "system", "", nil, nil, systemPrompt, 0, 0, false, "")

	// conversation buffer fed back to ollama every turn
	convo := []map[string]string{
		{"role": "system", "content": systemPrompt},
		{"role": "user", "content": o.buildUserPrompt(req)},
	}

	totalTokens := 0
	var converged bool
	var finalAnswer string

	for turn := 1; turn <= o.MaxTurns; turn++ {
		turnStart := time.Now()

		// 1) Ask LLM
		llmReply, tokens, err := o.callLLM(ctx, convo)
		totalTokens += tokens
		if err != nil {
			o.persistTrace(ctx, sessionID, req, turn, "llm", "", nil, nil, "",
				tokens, msSince(turnStart), false, "llm error: "+err.Error())
			result.Error = "llm: " + err.Error()
			break
		}

		// 2) Parse LLM intent
		intent := parseLLMReply(llmReply)
		o.persistTrace(ctx, sessionID, req, turn, "llm", "", nil, nil,
			intent.Thought, tokens, msSince(turnStart), false, "")
		o.Telem.CounterInc("agentic_turn_total", map[string]string{
			"role": "llm", "model": o.Model,
		})

		// 3) Convergence?
		if intent.FinalAnswer != "" {
			converged = true
			finalAnswer = intent.FinalAnswer
			o.persistTrace(ctx, sessionID, req, turn, "final", "", nil,
				map[string]any{"answer": finalAnswer}, intent.Thought,
				0, msSince(turnStart), true, "")
			break
		}

		// 4) Tool call
		if intent.ToolName == "" {
			// LLM gave no tool and no answer — feedback nudge
			convo = append(convo,
				map[string]string{"role": "assistant", "content": llmReply},
				map[string]string{"role": "user", "content": "You must either call a tool (JSON: {\"tool\":\"name\",\"input\":{...}}) or give a final answer (JSON: {\"final_answer\":\"...\"}). Try again."},
			)
			continue
		}

		toolStart := time.Now()
		toolRes := o.Tools.Run(ctx, intent.ToolName, intent.ToolInput)
		toolDur := msSince(toolStart)
		o.Telem.CounterInc("agentic_tool_total", map[string]string{
			"tool":  intent.ToolName,
			"error": boolStr(toolRes.Error != ""),
		})
		o.Telem.HistogramObserve("agentic_tool_duration_seconds",
			float64(toolDur)/1000.0, map[string]string{"tool": intent.ToolName})

		o.persistTrace(ctx, sessionID, req, turn, "tool", intent.ToolName,
			intent.ToolInput, toolResultToJSON(toolRes), intent.Thought,
			0, toolDur, false, toolRes.Error)

		// 5) Feed observation back into convo
		obsMsg := fmt.Sprintf("Tool %s output:\n%s", intent.ToolName, toolRes.Output)
		if toolRes.Error != "" {
			obsMsg = fmt.Sprintf("Tool %s error: %s", intent.ToolName, toolRes.Error)
		}
		convo = append(convo,
			map[string]string{"role": "assistant", "content": llmReply},
			map[string]string{"role": "user", "content": obsMsg},
		)

		// 6) Token budget guard
		if totalTokens > tokenSoftBudget {
			result.Error = "token budget exceeded"
			break
		}
	}

	result.Turns = o.countTurns(ctx, sessionID)
	result.Converged = converged
	result.FinalAnswer = finalAnswer
	result.TotalTokens = totalTokens
	result.DurationMS = time.Since(startWall).Milliseconds()
	if converged {
		result.Confidence = 0.85 // heuristic — could derive from logprobs later
	}

	o.Telem.HistogramObserve("agentic_session_duration_seconds",
		float64(result.DurationMS)/1000.0, map[string]string{
			"converged": boolStr(converged),
		})
	return result, nil
}

// =====================================================================
// Prompt construction
// =====================================================================

func (o *Orchestrator) buildSystemPrompt(req RunRequest) string {
	// Compact tool list (name + 1-line desc) to keep prompt under 1KB.
	var toolList strings.Builder
	for _, t := range o.Tools.tools {
		fmt.Fprintf(&toolList, "  - %s: %s\n", t.Name(), t.Description())
	}
	return fmt.Sprintf(`You are VSP Autofix Agent. Reply with ONE JSON object per turn:
  {"thought":"...","tool":"<name>","input":{...}}   // to call a tool
  {"thought":"...","final_answer":"..."}             // when done
NEVER prose outside JSON.

Tools:
%sInput keys (use exactly these):
  read_file:     {"path":"<rel>","start":1,"end":200}
  grep:          {"pattern":"<regex>","path":"."}
  list_files:    {"path":"."}
  ast_parse:     {"path":"<rel.go>"}
  check_imports: {"import_path":"<pkg>"}

Max %d turns. final_answer must include: root cause, fix steps, verification cmd.
`, toolList.String(), o.MaxTurns)
}

func (o *Orchestrator) buildUserPrompt(req RunRequest) string {
	loc := ""
	if req.FilePath != "" {
		loc = fmt.Sprintf("\nLocation: %s", req.FilePath)
		if req.LineNumber > 0 {
			loc += fmt.Sprintf(":%d", req.LineNumber)
		}
	}
	return fmt.Sprintf(`Investigate this finding and propose a fix:

Tool: %s
Rule: %s
Severity: %s
Message: %s%s

Begin by exploring the code with tools (read_file, grep, ast_parse, list_files,
check_imports). When you have enough context, emit a final_answer.`,
		req.Tool, req.RuleID, req.Severity, req.Message, loc)
}

// =====================================================================
// LLM transport (ollama)
// =====================================================================

type ollamaReq struct {
	Model    string              `json:"model"`
	Messages []map[string]string `json:"messages"`
	Stream   bool                `json:"stream"`
	Options  map[string]any      `json:"options,omitempty"`
}

type ollamaResp struct {
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	Done            bool `json:"done"`
	PromptEvalCount int  `json:"prompt_eval_count"`
	EvalCount       int  `json:"eval_count"`
}

func (o *Orchestrator) callLLM(ctx context.Context, msgs []map[string]string) (string, int, error) {
	body := ollamaReq{
		Model:    o.Model,
		Messages: msgs,
		Stream:   false,
		Options: map[string]any{
			"temperature": 0.2,
			"num_predict": 384,
			"num_ctx":     4096,
		},
	}
	buf, _ := json.Marshal(body)

	subCtx, cancel := context.WithTimeout(ctx, llmTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(subCtx, "POST",
		o.OllamaURL+"/api/chat", bytes.NewReader(buf))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("ollama %d: %s", resp.StatusCode, truncStr(string(b), 200))
	}
	var or ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&or); err != nil {
		return "", 0, err
	}
	tokens := or.PromptEvalCount + or.EvalCount
	return or.Message.Content, tokens, nil
}

// =====================================================================
// LLM reply parsing
// =====================================================================

type llmIntent struct {
	Thought     string
	ToolName    string
	ToolInput   map[string]any
	FinalAnswer string
}

func parseLLMReply(s string) llmIntent {
	out := llmIntent{}
	// Strip code fences if present
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	// Extract first {...} block (LLMs sometimes prepend prose despite instructions)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := lastIndexBalanced(s, '{', '}', i); j > i {
			s = s[i : j+1]
		}
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		out.Thought = "(unparseable LLM reply)"
		return out
	}
	if t, ok := raw["thought"].(string); ok {
		out.Thought = t
	}
	if fa, ok := raw["final_answer"].(string); ok && fa != "" {
		out.FinalAnswer = fa
		return out
	}
	if tn, ok := raw["tool"].(string); ok {
		out.ToolName = tn
	}
	if ti, ok := raw["input"].(map[string]any); ok {
		out.ToolInput = ti
	} else {
		out.ToolInput = map[string]any{}
	}
	return out
}

// lastIndexBalanced — find matching close brace starting from `from`
func lastIndexBalanced(s string, open, close byte, from int) int {
	depth := 0
	inStr := false
	esc := false
	for i := from; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if c == open {
			depth++
		} else if c == close {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// =====================================================================
// Persistence
// =====================================================================

func (o *Orchestrator) persistTrace(
	ctx context.Context,
	sessionID string, req RunRequest,
	turn int, role, toolName string,
	toolIn map[string]any, toolOut map[string]any,
	thought string, tokens int, durMS int64,
	converged bool, errMsg string,
) {
	// Truncate thought to keep DB rows sane
	if len(thought) > 4000 {
		thought = thought[:4000] + "...[truncated]"
	}

	var toolInJS, toolOutJS []byte
	if toolIn != nil {
		toolInJS, _ = json.Marshal(toolIn)
	}
	if toolOut != nil {
		toolOutJS, _ = json.Marshal(toolOut)
	}
	var toolNameNullable any = nil
	if toolName != "" {
		toolNameNullable = toolName
	}
	var errNullable any = nil
	if errMsg != "" {
		errNullable = errMsg
	}

	// Use independent timeout — parent ctx may already be expired if LLM hit timeout
	dbCtx, dbCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dbCancel()
	_, err := o.DB.ExecContext(dbCtx, `
		INSERT INTO agentic_trace
			(cache_key, finding_id, session_id, turn_number, role,
			 tool_name, tool_input, tool_output, llm_thought,
			 tokens_used, duration_ms, converged, error_msg)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, req.CacheKey, req.FindingID, sessionID, turn, role,
		toolNameNullable, nullJSON(toolInJS), nullJSON(toolOutJS),
		thought, tokens, durMS, converged, errNullable)
	if err != nil {
		// Don't fail the run on telemetry errors — just log to stderr
		fmt.Fprintf(os.Stderr, "[agentic] persist trace failed: %v\n", err)
	}
}

func (o *Orchestrator) countTurns(ctx context.Context, sessionID string) int {
	var n int
	_ = o.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agentic_trace WHERE session_id = $1 AND role IN ('llm','tool')`,
		sessionID).Scan(&n)
	return n
}

// =====================================================================
// Helpers
// =====================================================================

func toolResultToJSON(r ToolResult) map[string]any {
	out := map[string]any{
		"output":    truncStr(r.Output, traceOutputCapKB*1024),
		"truncated": r.Truncated,
	}
	if r.Error != "" {
		out["error"] = r.Error
	}
	if r.Metadata != nil {
		out["metadata"] = r.Metadata
	}
	return out
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func msSince(t time.Time) int64 {
	return time.Since(t).Milliseconds()
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
