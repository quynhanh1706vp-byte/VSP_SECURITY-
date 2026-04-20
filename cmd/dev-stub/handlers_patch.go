//go:build devstub
// +build devstub

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Override HandleRunLatest — ưu tiên run có findings cao nhất
// thay vì chỉ lấy run DONE gần nhất
func HandleRunLatestV2(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type RunResp struct {
			ID            string          `json:"id"`
			RID           string          `json:"rid"`
			Mode          string          `json:"mode"`
			Profile       string          `json:"profile"`
			Status        string          `json:"status"`
			Gate          string          `json:"gate"`
			Score         int             `json:"score"`
			Posture       string          `json:"posture"`
			TotalFindings int             `json:"total_findings"`
			StartedAt     *time.Time      `json:"started_at"`
			FinishedAt    *time.Time      `json:"finished_at"`
			Summary       json.RawMessage `json:"summary"`
			RunID         string          `json:"run_id"`
		}

		// Ưu tiên: run DONE có findings > 0, lấy gần nhất
		// Fallback: run DONE gần nhất bất kỳ
		query := `
			SELECT id::text, rid, mode, COALESCE(profile,'STANDARD'), status,
			       COALESCE(gate,''), COALESCE((summary->>'SCORE')::int,0),
			       COALESCE(total_findings,0),
			       started_at, finished_at,
			       COALESCE(summary,'{}')
			FROM runs
			WHERE status IN ('DONE','done')
			ORDER BY
			  CASE WHEN total_findings > 0 THEN 0 ELSE 1 END,
			  started_at DESC
			LIMIT 1`

		row := db.QueryRowContext(r.Context(), query)
		var run RunResp
		var summaryBytes []byte
		err := row.Scan(&run.ID, &run.RID, &run.Mode, &run.Profile,
			&run.Status, &run.Gate, &run.Score, &run.TotalFindings,
			&run.StartedAt, &run.FinishedAt, &summaryBytes)
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"","rid":"","status":"none","gate":"","score":0,"total_findings":0,"summary":{}}`))
			return
		}
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}

		var summ map[string]interface{}
		json.Unmarshal(summaryBytes, &summ)
		if summ == nil {
			summ = map[string]interface{}{}
		}

		// Tính lại severity từ findings thật
		sevRow := db.QueryRowContext(r.Context(), `
			SELECT
			  COUNT(*) FILTER (WHERE severity='CRITICAL'),
			  COUNT(*) FILTER (WHERE severity='HIGH'),
			  COUNT(*) FILTER (WHERE severity='MEDIUM'),
			  COUNT(*) FILTER (WHERE severity='LOW'),
			  COUNT(*)
			FROM findings WHERE run_id=$1::uuid`, run.ID)
		var crit, high, med, low, total int
		sevRow.Scan(&crit, &high, &med, &low, &total)
		if total > 0 {
			summ["CRITICAL"] = crit
			summ["HIGH"] = high
			summ["MEDIUM"] = med
			summ["LOW"] = low
			run.TotalFindings = total
		}

		// Score từ summary
		if sc, ok := summ["SCORE"]; ok {
			if v, ok := sc.(float64); ok {
				run.Score = int(v)
			}
		}

		// Tính posture/grade từ score
		score := run.Score
		switch {
		case score >= 90:
			run.Posture = "A+"
		case score >= 80:
			run.Posture = "A"
		case score >= 70:
			run.Posture = "B"
		case score >= 60:
			run.Posture = "C"
		case score >= 40:
			run.Posture = "D"
		default:
			run.Posture = "F"
		}

		summBytes, _ := json.Marshal(summ)
		run.Summary = summBytes
		run.RunID = run.ID

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(run)
	}
}

// Đảm bảo không conflict với HandleRunLatest trong handlers.go
var _ = fmt.Sprintf

// HandleRunsIndexV2 — ưu tiên DONE runs lên trước QUEUED
func HandleRunsIndexV2(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 200
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}

		rows, err := db.QueryContext(r.Context(), `
			SELECT id::text, rid, mode, COALESCE(profile,'STANDARD') as profile, status,
			       COALESCE(gate,''), COALESCE((summary->>'SCORE')::int,0),
			       COALESCE(total_findings,0),
			       started_at, finished_at,
			       COALESCE(summary,'{}')
			FROM runs
			WHERE status IN ('DONE','done')
			ORDER BY started_at DESC NULLS LAST
			LIMIT $1`, limit)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		type RunRow struct {
			ID            string          `json:"id"`
			RID           string          `json:"rid"`
			Mode          string          `json:"mode"`
			Profile       string          `json:"profile"`
			Status        string          `json:"status"`
			Gate          string          `json:"gate"`
			Score         int             `json:"score"`
			TotalFindings int             `json:"total_findings"`
			StartedAt     *time.Time      `json:"started_at"`
			CreatedAt     *time.Time      `json:"created_at"`
			FinishedAt    *time.Time      `json:"finished_at"`
			Summary       json.RawMessage `json:"summary"`
		}

		var runs []RunRow
		for rows.Next() {
			var run RunRow
			var summBytes []byte
			if err := rows.Scan(&run.ID, &run.RID, &run.Mode, &run.Profile,
				&run.Status, &run.Gate, &run.Score, &run.TotalFindings,
				&run.StartedAt, &run.FinishedAt, &summBytes); err != nil {
				continue
			}
			if len(summBytes) == 0 {
				summBytes = []byte("{}")
			}
			run.CreatedAt = run.StartedAt // alias cho analytics
			run.Summary = summBytes
			runs = append(runs, run)
		}
		if runs == nil {
			runs = []RunRow{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"runs":  runs,
			"total": len(runs),
		})
	}
}
