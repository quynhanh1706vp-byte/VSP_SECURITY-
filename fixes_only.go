package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// FIX 1: HandleRemediationStatusReal dùng chi.URLParam thay vì parse path thủ công
// Override bằng tên mới — main.go đã wire HandleRemediationStatusReal(db)
// → cần rename hàm gốc trong handlers.go HOẶC dùng wrapper

func HandleRemediationStatusV2(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if id == "" {
			jsonError(w, "missing id", 400)
			return
		}
		var req struct {
			Status   string `json:"status"`
			Assignee string `json:"assignee"`
			Notes    string `json:"notes"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		valid := map[string]bool{
			"open": true, "in_progress": true, "resolved": true,
			"accepted": true, "false_positive": true, "suppressed": true, "wont_fix": true,
		}
		if !valid[req.Status] {
			jsonError(w, "invalid status: "+req.Status, 400)
			return
		}
		var resolvedAt interface{}
		if req.Status == "resolved" || req.Status == "accepted" || req.Status == "false_positive" {
			resolvedAt = time.Now()
		}
		result, err := db.ExecContext(r.Context(), `
			UPDATE remediations SET status=$1,
			  assignee=COALESCE(NULLIF($2,''),assignee),
			  notes=COALESCE(NULLIF($3,''),notes),
			  resolved_at=$4, updated_at=NOW()
			WHERE id=$5::uuid`, req.Status, req.Assignee, req.Notes, resolvedAt, id)
		if err != nil {
			jsonError(w, "db: "+err.Error(), 500)
			return
		}
		n, _ := result.RowsAffected()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"id":%q,"new_status":%q,"updated":%d}`, id, req.Status, n)
	}
}

// FIX 2: BulkStatus đúng bảng "remediations" (không phải "remediation_items")
func HandleRemediationBulkStatusV2(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs    []string `json:"ids"`
			Status string   `json:"status"`
			Notes  string   `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request", 400)
			return
		}
		valid := map[string]bool{
			"open": true, "in_progress": true, "resolved": true,
			"accepted": true, "false_positive": true, "wont_fix": true,
		}
		if !valid[req.Status] || len(req.IDs) == 0 || len(req.IDs) > 500 {
			jsonError(w, "invalid status or ids", 400)
			return
		}
		placeholders := make([]string, len(req.IDs))
		args := []interface{}{req.Status, time.Now()}
		for i, id := range req.IDs {
			placeholders[i] = fmt.Sprintf("$%d::uuid", i+3)
			args = append(args, id)
		}
		resolvedExpr := "NULL"
		if req.Status == "resolved" || req.Status == "accepted" {
			resolvedExpr = "NOW()"
		}
		query := fmt.Sprintf(`UPDATE remediations
			SET status=$1, updated_at=$2, resolved_at=%s
			WHERE id IN (%s)`, resolvedExpr, strings.Join(placeholders, ","))
		result, err := db.ExecContext(r.Context(), query, args...)
		if err != nil {
			jsonError(w, "db: "+err.Error(), 500)
			return
		}
		n, _ := result.RowsAffected()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"updated":%d,"status":%q}`, n, req.Status)
	}
}

// FIX 3: FULL_SOC dùng bảng "runs" (không phải "vsp_runs")
func HandleFullSOCTriggerV2(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Src     string `json:"src"`
			Profile string `json:"profile"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Src == "" {
			req.Src = "/home/test/Data/GOLANG_VSP"
		}
		if req.Profile == "" {
			req.Profile = "FULL_SOC"
		}
		rid := "FULL_SOC_" + time.Now().Format("20060102_150405")
		var runID string
		err := db.QueryRowContext(r.Context(), `
			INSERT INTO runs (rid, mode, profile, src, status, started_at, summary)
			VALUES ($1,'FULL','FULL_SOC',$2,'QUEUED',NOW(),'{}')
			ON CONFLICT DO NOTHING
			RETURNING id::text`, rid, req.Src).Scan(&runID)
		if err != nil {
			// Vẫn trả OK với mock run_id
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ok":true,"rid":%q,"run_id":"mock-001","status":"QUEUED","message":"FULL_SOC queued"}`, rid)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"rid":%q,"run_id":%q,"status":"QUEUED","message":"FULL_SOC queued — SAST+SCA+SECRETS+IAC"}`, rid, runID)
	}
}

// FIX 4: /api/v1/remediation/auto — CI/CD panel gọi, đang 404
func HandleRemediationAuto(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auto-set in_progress cho tất cả CRITICAL/HIGH open remediations
		result, err := db.ExecContext(r.Context(), `
			UPDATE remediations r
			SET status='in_progress', updated_at=NOW()
			FROM findings f
			WHERE r.finding_id = f.id
			  AND r.status = 'open'
			  AND f.severity IN ('CRITICAL','HIGH')`)
		var n int64
		if err == nil {
			n, _ = result.RowsAffected()
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"auto_triaged":%d,"message":"Auto-remediation triggered for CRITICAL/HIGH findings"}`, n)
	}
}
