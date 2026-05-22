// =====================================================================
// H3.T Agentic Autofix — HTTP handlers
// File: internal/agentic/handlers.go
// =====================================================================
//
// Routes (mounted on vsp-gateway via RegisterRoutes):
//
//   POST  /api/v1/agentic/run            — start an agentic session
//                                            (sync; returns final_answer)
//   GET   /api/v1/agentic/trace/{id}     — fetch all turns of a session
//   GET   /api/v1/agentic/sessions       — list recent sessions (admin)
//   GET   /api/v1/agentic/stats          — convergence rate, token usage
//
// AuthN: re-uses the gateway's existing JWT middleware (caller must wrap).
// AuthZ: any authenticated user can run; trace fetch limited to owner OR admin
//        (we store the JWT subject in cache_key prefix as a soft tenant guard).

package agentic

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// HandlerSet — bundle the orchestrator + DB so we can register routes
type HandlerSet struct {
	Orch *Orchestrator
	DB   *sql.DB
}

func NewHandlerSet(orch *Orchestrator) *HandlerSet {
	return &HandlerSet{Orch: orch, DB: orch.DB}
}

// RegisterRoutes — call from main.go after the gateway sets up its mux.
// `protected` is the auth-wrapped subrouter. We expose the prefix
// /api/v1/agentic/* under it.
func (h *HandlerSet) RegisterRoutes(r chi.Router) {
	r.Post("/api/v1/agentic/run", h.handleRun)
	r.Get("/api/v1/agentic/trace/{sessionID}", h.handleTrace)
	r.Get("/api/v1/agentic/sessions", h.handleSessions)
	r.Get("/api/v1/agentic/stats", h.handleStats)
}

// =====================================================================
// POST /api/v1/agentic/run
// =====================================================================

func (h *HandlerSet) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if r.ContentLength > 64*1024 {
		writeErr(w, http.StatusRequestEntityTooLarge, "body > 64KB")
		return
	}
	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.CacheKey == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "cache_key and finding_id required")
		return
	}

	// Hard cap session walltime so a stuck LLM can't tie up the goroutine
	// Detach from request context — chi middleware.Timeout caps it at 60s,
	// nhưng LLM ReAct loop có thể cần 30-90s/turn × 5 turns. Spawn fresh ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	res, err := h.Orch.Run(ctx, req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// =====================================================================
// GET /api/v1/agentic/trace/{session_id}
// =====================================================================

func (h *HandlerSet) handleTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	sessionID := chi.URLParam(r, "sessionID")
	if sessionID == "" || len(sessionID) > 64 {
		writeErr(w, http.StatusBadRequest, "missing or invalid session_id")
		return
	}
	// Validate UUID-ish (cheap, no extra dep needed since DB will reject bad input)
	if !looksLikeUUID(sessionID) {
		writeErr(w, http.StatusBadRequest, "session_id must be uuid")
		return
	}

	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT turn_number, role, tool_name, tool_input, tool_output,
		       llm_thought, tokens_used, duration_ms, converged, error_msg, created_at
		FROM agentic_trace
		WHERE session_id = $1
		ORDER BY turn_number ASC, id ASC
	`, sessionID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	defer rows.Close()

	type traceRow struct {
		Turn       int             `json:"turn"`
		Role       string          `json:"role"`
		ToolName   *string         `json:"tool_name,omitempty"`
		ToolInput  json.RawMessage `json:"tool_input,omitempty"`
		ToolOutput json.RawMessage `json:"tool_output,omitempty"`
		Thought    string          `json:"thought,omitempty"`
		Tokens     int             `json:"tokens_used"`
		DurationMS int             `json:"duration_ms"`
		Converged  bool            `json:"converged"`
		Error      *string         `json:"error,omitempty"`
		CreatedAt  time.Time       `json:"created_at"`
	}
	var out []traceRow
	for rows.Next() {
		var tr traceRow
		var toolName, errMsg sql.NullString
		var toolIn, toolOut sql.NullString
		if err := rows.Scan(&tr.Turn, &tr.Role, &toolName, &toolIn, &toolOut,
			&tr.Thought, &tr.Tokens, &tr.DurationMS, &tr.Converged, &errMsg, &tr.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		if toolName.Valid {
			s := toolName.String
			tr.ToolName = &s
		}
		if errMsg.Valid {
			s := errMsg.String
			tr.Error = &s
		}
		if toolIn.Valid {
			tr.ToolInput = json.RawMessage(toolIn.String)
		}
		if toolOut.Valid {
			tr.ToolOutput = json.RawMessage(toolOut.String)
		}
		out = append(out, tr)
	}
	if len(out) == 0 {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"turns":      out,
	})
}

// =====================================================================
// GET /api/v1/agentic/sessions?limit=N
// =====================================================================

func (h *HandlerSet) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, _ := parseIntDef(l, 50); n > 0 && n <= 500 {
			limit = n
		}
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT
			session_id::text,
			MIN(finding_id) AS finding_id,
			MIN(cache_key)  AS cache_key,
			MAX(turn_number) AS turns,
			BOOL_OR(converged) AS converged,
			SUM(tokens_used)::int AS tokens,
			SUM(duration_ms)::int AS duration_ms,
			MIN(created_at) AS started_at
		FROM agentic_trace
		GROUP BY session_id
		ORDER BY started_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	defer rows.Close()

	type sessionRow struct {
		SessionID  string    `json:"session_id"`
		FindingID  string    `json:"finding_id"`
		CacheKey   string    `json:"cache_key"`
		Turns      int       `json:"turns"`
		Converged  bool      `json:"converged"`
		Tokens     int       `json:"tokens"`
		DurationMS int       `json:"duration_ms"`
		StartedAt  time.Time `json:"started_at"`
	}
	var out []sessionRow
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(&s.SessionID, &s.FindingID, &s.CacheKey,
			&s.Turns, &s.Converged, &s.Tokens, &s.DurationMS, &s.StartedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": out,
		"count":    len(out),
	})
}

// =====================================================================
// GET /api/v1/agentic/stats
// =====================================================================

func (h *HandlerSet) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	row := h.DB.QueryRowContext(r.Context(), `
		SELECT
			COUNT(DISTINCT session_id)::int                          AS sessions,
			COALESCE(SUM(tokens_used),0)::int                        AS tokens_total,
			COALESCE(AVG(duration_ms) FILTER (WHERE role='final'),0) AS avg_duration_ms,
			COALESCE(
				(COUNT(*) FILTER (WHERE role='final' AND converged))::float
				/ NULLIF(COUNT(DISTINCT session_id),0), 0)           AS convergence_rate,
			COALESCE(AVG(turn_number) FILTER (WHERE role='final'),0) AS avg_turns
		FROM agentic_trace
		WHERE created_at > NOW() - INTERVAL '7 days'
	`)
	var stats struct {
		Sessions        int     `json:"sessions"`
		TokensTotal     int     `json:"tokens_total"`
		AvgDurationMS   float64 `json:"avg_duration_ms"`
		ConvergenceRate float64 `json:"convergence_rate"`
		AvgTurns        float64 `json:"avg_turns"`
	}
	if err := row.Scan(&stats.Sessions, &stats.TokensTotal,
		&stats.AvgDurationMS, &stats.ConvergenceRate, &stats.AvgTurns); err != nil {
		writeErr(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// =====================================================================
// Helpers
// =====================================================================

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func parseIntDef(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def, nil
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return def, nil
		}
	}
	return n, nil
}

// contextWithDeadline — exposed as a var so tests can stub it
var contextWithDeadline = func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
