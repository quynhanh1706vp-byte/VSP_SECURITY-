package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// PrecomputeStatusHandler returns GET /api/v1/autofix/precompute/status
// UI polls this to render H3.O progress bar widget.
func PrecomputeStatusHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		ctx := r.Context()

		row := db.QueryRowContext(ctx, `
			SELECT j.id::text, j.run_id::text, j.status, j.total, j.completed,
			       j.failed, j.skipped, COALESCE(j.avg_latency_ms, 0),
			       j.started_at, j.finished_at, j.created_at,
			       COALESCE(r.rid, ''), COALESCE(r.profile, '')
			FROM autofix_precompute_jobs j
			LEFT JOIN runs r ON r.id = j.run_id
			WHERE j.created_at > NOW() - INTERVAL '24 hours'
			ORDER BY j.created_at DESC
			LIMIT 1
		`)

		var jobID, runID, status, runRID, runProfile string
		var total, completed, failed, skipped, avgLatency int
		var startedAt, finishedAt, createdAt sql.NullTime

		err := row.Scan(&jobID, &runID, &status, &total, &completed, &failed, &skipped,
			&avgLatency, &startedAt, &finishedAt, &createdAt, &runRID, &runProfile)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "idle",
				"message": "No pre-compute jobs in the last 24 hours",
			})
			return
		}

		var totalCached int
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM autofix_cache WHERE expires_at > NOW()`).Scan(&totalCached)

		resp := map[string]interface{}{
			"job_id":         jobID,
			"run_id":         runID,
			"run_label":      runRID,
			"run_profile":    runProfile,
			"status":         status,
			"total":          total,
			"completed":      completed,
			"failed":         failed,
			"skipped":        skipped,
			"avg_latency_ms": avgLatency,
			"total_cached":   totalCached,
		}
		if startedAt.Valid {
			resp["started_at"] = startedAt.Time
		}
		if finishedAt.Valid {
			resp["finished_at"] = finishedAt.Time
		}
		if createdAt.Valid {
			resp["created_at"] = createdAt.Time
		}

		processed := completed + failed + skipped
		if total > 0 {
			resp["progress_pct"] = int(float64(processed) / float64(total) * 100)
		} else {
			resp["progress_pct"] = 0
		}

		if status == "running" && completed > 0 && avgLatency > 0 && processed < total {
			remaining := total - processed
			etaMs := int64(remaining) * int64(avgLatency)
			resp["eta_seconds"] = etaMs / 1000
		}

		_ = json.NewEncoder(w).Encode(resp)

		// Suppress unused import lint
		_ = time.Now
	}
}

// PrecomputeHistoryHandler returns GET /api/v1/autofix/precompute/history
// Last 20 jobs for admin debugging.
func PrecomputeHistoryHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		rows, err := db.QueryContext(r.Context(), `
			SELECT j.id::text, j.run_id::text, j.status, j.total, j.completed,
			       j.failed, j.skipped, COALESCE(j.avg_latency_ms, 0),
			       j.started_at, j.finished_at, j.created_at,
			       COALESCE(r.rid, '')
			FROM autofix_precompute_jobs j
			LEFT JOIN runs r ON r.id = j.run_id
			ORDER BY j.created_at DESC
			LIMIT 20
		`)
		if err != nil {
			http.Error(w, `{"error":"db query failed"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		out := make([]map[string]interface{}, 0)
		for rows.Next() {
			var jobID, runID, status, runRID string
			var total, completed, failed, skipped, avgLatency int
			var startedAt, finishedAt, createdAt sql.NullTime
			if err := rows.Scan(&jobID, &runID, &status, &total, &completed,
				&failed, &skipped, &avgLatency, &startedAt, &finishedAt,
				&createdAt, &runRID); err != nil {
				continue
			}
			entry := map[string]interface{}{
				"job_id":         jobID,
				"run_id":         runID,
				"run_label":      runRID,
				"status":         status,
				"total":          total,
				"completed":      completed,
				"failed":         failed,
				"skipped":        skipped,
				"avg_latency_ms": avgLatency,
			}
			if startedAt.Valid {
				entry["started_at"] = startedAt.Time
			}
			if finishedAt.Valid {
				entry["finished_at"] = finishedAt.Time
			}
			if createdAt.Valid {
				entry["created_at"] = createdAt.Time
			}
			out = append(out, entry)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jobs":  out,
			"count": len(out),
		})
	}
}
