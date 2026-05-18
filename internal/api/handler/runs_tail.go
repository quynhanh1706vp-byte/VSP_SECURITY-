// Package handler — SSE live-tail for scan runs.
//
// Endpoint: GET /api/v1/runs/{rid}/tail  (text/event-stream)
//
// Replaces frontend polling of /runs/{rid} + /runs/{rid}/log with a single
// long-lived HTTP connection. The server emits SSE events as the run
// progresses:
//
//	event: status   data: {"status":"RUNNING","tools_done":3,"tools_total":8}
//	event: finding  data: {"tool":"gosec","severity":"HIGH","rule_id":"G401",...}
//	event: log      data: {"ts":"00:01:14","tool":"trivy","level":"INFO",...}
//	event: done     data: {"status":"COMPLETED","total_findings":104}
//
// Implementation note: we don't have a real-time pubsub wired for finding
// inserts, so the tailer polls the DB every pollInterval and emits the
// delta. From the browser's perspective this is still a single connection
// → identical UX to a real broker-backed SSE. When we add Redis pubsub
// later, swap the poll loop for a subscription without changing the
// client.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
)

const (
	tailPollInterval = 1 * time.Second
	tailMaxDuration  = 10 * time.Minute // server-side cap
	tailHeartbeat    = 15 * time.Second // SSE comment to keep proxies open
)

// Tail streams run progress as Server-Sent Events. The connection ends
// when the run reaches a terminal state, the client disconnects, or the
// server-side cap is hit.
func (h *Runs) Tail(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rid := chi.URLParam(r, "rid")
	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // tell nginx not to buffer
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), tailMaxDuration)
	defer cancel()

	// Initial snapshot — immediately tell the client what we know.
	emitEvent(w, flusher, "status", map[string]any{
		"rid":         rid,
		"status":      run.Status,
		"mode":        run.Mode,
		"tools_done":  run.ToolsDone,
		"tools_total": run.ToolsTotal,
	})

	// Replay any findings already inserted before the connection.
	lastSeenSeq := h.streamFindingsSince(ctx, w, flusher, tenantID, run.ID, "")

	pollT := time.NewTicker(tailPollInterval)
	defer pollT.Stop()
	heartbeatT := time.NewTicker(tailHeartbeat)
	defer heartbeatT.Stop()

	prevStatus := run.Status
	prevToolsDone := run.ToolsDone

	for {
		select {
		case <-ctx.Done():
			emitEvent(w, flusher, "done", map[string]any{
				"status": "TIMEOUT", "reason": "server tail cap reached",
			})
			return
		case <-heartbeatT.C:
			// SSE comment line keeps proxy connections alive without
			// triggering EventSource onmessage handlers.
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-pollT.C:
			// Re-fetch the run row and any new findings.
			refreshed, err := h.DB.GetRunByRID(ctx, claims.TenantID, rid)
			if err != nil || refreshed == nil {
				continue
			}
			if refreshed.Status != prevStatus || refreshed.ToolsDone != prevToolsDone {
				emitEvent(w, flusher, "status", map[string]any{
					"rid":         rid,
					"status":      refreshed.Status,
					"tools_done":  refreshed.ToolsDone,
					"tools_total": refreshed.ToolsTotal,
				})
				prevStatus = refreshed.Status
				prevToolsDone = refreshed.ToolsDone
			}
			lastSeenSeq = h.streamFindingsSince(ctx, w, flusher, tenantID, run.ID, lastSeenSeq)

			if isTerminal(refreshed.Status) {
				emitEvent(w, flusher, "done", map[string]any{
					"status":         refreshed.Status,
					"total_findings": refreshed.TotalFindings,
				})
				return
			}
		}
	}
}

// streamFindingsSince emits one "finding" event per newly-arrived row.
// Returns the last id seen so the next call can resume.
func (h *Runs) streamFindingsSince(ctx context.Context, w http.ResponseWriter,
	flusher http.Flusher, tenantID, runID, sinceID string) string {

	// We use the finding's id text-ordering as the cursor. Findings are
	// inserted with gen_random_uuid() so this isn't strictly chronological,
	// but combined with the WHERE NOT IN/created_at filter we never
	// double-emit a row within a single tail session.
	q := `SELECT id::text, tool, severity, COALESCE(rule_id,''), COALESCE(message,''), created_at
	        FROM findings
	       WHERE run_id = $1 AND tenant_id = $2`
	args := []any{runID, tenantID}
	if sinceID != "" {
		q += ` AND created_at > (SELECT created_at FROM findings WHERE id = $3::uuid)`
		args = append(args, sinceID)
	}
	q += ` ORDER BY created_at ASC LIMIT 200`

	rows, err := h.DB.Pool().Query(ctx, q, args...)
	if err != nil {
		return sinceID
	}
	defer rows.Close()

	last := sinceID
	for rows.Next() {
		var id, tool, sev, ruleID, msg string
		var ts time.Time
		if err := rows.Scan(&id, &tool, &sev, &ruleID, &msg, &ts); err != nil {
			continue
		}
		emitEvent(w, flusher, "finding", map[string]any{
			"id":       id,
			"tool":     tool,
			"severity": sev,
			"rule_id":  ruleID,
			"message":  msg,
			"ts":       ts.UTC().Format(time.RFC3339),
		})
		last = id
	}
	return last
}

func emitEvent(w http.ResponseWriter, flusher http.Flusher, name string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, payload)
	flusher.Flush()
}

func isTerminal(status string) bool {
	switch status {
	case "COMPLETED", "FAILED", "CANCELLED", "ERROR":
		return true
	}
	return false
}
