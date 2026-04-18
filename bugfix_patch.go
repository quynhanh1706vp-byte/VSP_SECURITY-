package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ─── Minimal stdlib Context (no gin dependency in this file) ──
// Nếu project dùng gin, xem GinCSRF() và RegisterGinRoutes() ở cuối file.

// ═══════════════════════════════════════════════════════════════
// BUG 1 — SW Risk agent CSRF bypass
// Fix: exempt /api/v1/software-inventory/report khỏi CSRF check
// ═══════════════════════════════════════════════════════════════

var csrfExemptRoutes = []string{
	"/api/v1/software-inventory/report",
	"/api/v1/auth/login",
	"/api/v1/auth/refresh",
}

func isCSRFExempt(path string) bool {
	for _, exempt := range csrfExemptRoutes {
		if strings.HasPrefix(path, exempt) {
			return true
		}
	}
	return false
}

// CSRFMiddleware — stdlib http.Handler wrapper.
// Dùng trực tiếp: mux.Handle("/", CSRFMiddleware(yourRouter))
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet ||
			r.Method == http.MethodHead ||
			r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if isCSRFExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		headerToken := r.Header.Get("X-CSRF-Token")
		ck, err := r.Cookie("csrf_token")
		if err != nil || headerToken == "" || headerToken != ck.Value {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"CSRF token invalid or missing"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GinCSRF — gin.HandlerFunc wrapper, dùng nếu project dùng gin:
//   r.Use(GinCSRF())
//
// func GinCSRF() gin.HandlerFunc {
//     return func(c *gin.Context) {
//         if c.Request.Method == "GET" || c.Request.Method == "HEAD" ||
//             c.Request.Method == "OPTIONS" || isCSRFExempt(c.Request.URL.Path) {
//             c.Next(); return
//         }
//         headerToken := c.GetHeader("X-CSRF-Token")
//         ck, err := c.Cookie("csrf_token")
//         if err != nil || headerToken == "" || headerToken != ck {
//             c.AbortWithStatusJSON(403, gin.H{"error": "CSRF token invalid"})
//             return
//         }
//         c.Next()
//     }
// }

// ═══════════════════════════════════════════════════════════════
// BUG 2 — FULL_SOC scan chưa có runs
// Thêm: POST /api/v1/vsp/run/full-soc
//       GET  /api/v1/vsp/runs/full-soc
// ═══════════════════════════════════════════════════════════════

type FullSOCRequest struct {
	Src           string `json:"src"`
	NotifyWebhook string `json:"notify_webhook"`
}

func HandleFullSOCTrigger(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req FullSOCRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Src == "" {
			req.Src = "/home/test/Data/GOLANG_VSP"
		}
		rid := "FULL_SOC_" + time.Now().Format("20060102_150405")
		_, err := db.Exec(`
			INSERT INTO vsp_runs (rid, mode, profile, src, status, started_at)
			VALUES ($1,'FULL_SOC','FULL_SOC',$2,'running',NOW())
			ON CONFLICT (rid) DO NOTHING`, rid, req.Src)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
			return
		}
		go runFullSOCAsync(rid, req.Src, req.NotifyWebhook, db)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"rid":%q,"mode":"FULL_SOC","profile":"FULL_SOC",`+
			`"message":"FULL_SOC queued — SAST+SCA+SECRETS+IAC+DAST+NETWORK"}`, rid)
	}
}

func HandleFullSOCList(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
			SELECT rid, status, started_at,
			       COALESCE(total_findings,0),
			       COALESCE(gate,'pending'),
			       COALESCE(score,0)
			FROM vsp_runs WHERE mode='FULL_SOC'
			ORDER BY started_at DESC LIMIT 20`)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
			return
		}
		defer rows.Close()
		type Row struct {
			RID           string    `json:"rid"`
			Status        string    `json:"status"`
			StartedAt     time.Time `json:"started_at"`
			TotalFindings int       `json:"total_findings"`
			Gate          string    `json:"gate"`
			Score         int       `json:"score"`
		}
		var runs []Row
		for rows.Next() {
			var row Row
			if err := rows.Scan(&row.RID, &row.Status, &row.StartedAt,
				&row.TotalFindings, &row.Gate, &row.Score); err != nil {
				continue
			}
			runs = append(runs, row)
		}
		if runs == nil {
			runs = []Row{}
		}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(map[string]interface{}{"runs": runs, "total": len(runs)})
		_, _ = w.Write(b)
	}
}

func runFullSOCAsync(rid, src, webhook string, db *sql.DB) {
	modes := []string{"SAST", "SCA", "SECRETS", "IAC", "DAST", "NETWORK"}
	total := 0
	for _, m := range modes {
		total += runScanMode(m, src)
	}
	gate := "PASS"
	if total > 50 {
		gate = "FAIL"
	} else if total > 10 {
		gate = "WARN"
	}
	db.Exec(`UPDATE vsp_runs SET status='done',finished_at=NOW(),
		total_findings=$1,gate=$2 WHERE rid=$3`, total, gate, rid)
	if webhook != "" {
		notifyWebhook(webhook, rid, gate, total)
	}
}

// ── Stubs: map vào scan engine thực tế ───────────────────────
// Tìm keyword runScanMode và thay bằng call thực tế của project
func runScanMode(_ string, _ string) int                { return 0 }
func notifyWebhook(_ string, _ string, _ string, _ int) {}

// ═══════════════════════════════════════════════════════════════
// BUG 3 — Remediation workflow: 0 resolved
// Thêm: PATCH /api/v1/remediation/:id/status
//       POST  /api/v1/remediation/bulk-status
//       GET   /api/v1/remediation/stats
// ═══════════════════════════════════════════════════════════════

var validStatuses = map[string]bool{
	"open": true, "in_progress": true, "resolved": true,
	"accepted": true, "false_positive": true, "suppressed": true,
}

type StatusUpdateReq struct {
	Status     string `json:"status"`
	Comment    string `json:"comment"`
	Assignee   string `json:"assignee"`
	ResolvedBy string `json:"resolved_by"`
}

// HandleRemediationStatus — PATCH /api/v1/remediation/{id}/status
func HandleRemediationStatus(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id := ""
		for i, p := range parts {
			if p == "remediation" && i+2 < len(parts) {
				id = parts[i+1]
				break
			}
		}
		if id == "" {
			http.Error(w, `{"error":"missing id"}`, 400)
			return
		}
		var req StatusUpdateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validStatuses[req.Status] {
			http.Error(w, `{"error":"invalid request"}`, 400)
			return
		}
		var resolvedAt interface{}
		if req.Status == "resolved" || req.Status == "accepted" || req.Status == "false_positive" {
			resolvedAt = time.Now()
		}
		result, err := db.Exec(`
			UPDATE remediation_items
			SET status=$1,
			    comment=COALESCE(NULLIF($2,''),comment),
			    assignee=COALESCE(NULLIF($3,''),assignee),
			    resolved_by=$4, resolved_at=$5, updated_at=NOW()
			WHERE id=$6`,
			req.Status, req.Comment, req.Assignee, req.ResolvedBy, resolvedAt, id)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
			return
		}
		if n, _ := result.RowsAffected(); n == 0 {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"id":%q,"new_status":%q}`, id, req.Status)
	}
}

type BulkStatusReq struct {
	IDs     []string `json:"ids"`
	Status  string   `json:"status"`
	Comment string   `json:"comment"`
}

// HandleRemediationBulkStatus — POST /api/v1/remediation/bulk-status
func HandleRemediationBulkStatus(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req BulkStatusReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad request"}`, 400)
			return
		}
		if !validStatuses[req.Status] || len(req.IDs) == 0 || len(req.IDs) > 500 {
			http.Error(w, `{"error":"invalid status or ids count"}`, 400)
			return
		}
		placeholders := make([]string, len(req.IDs))
		args := make([]interface{}, 0, len(req.IDs)+2)
		args = append(args, req.Status, req.Comment)
		for i, id := range req.IDs {
			placeholders[i] = fmt.Sprintf("$%d", i+3)
			args = append(args, id)
		}
		resolvedExpr := "NULL"
		if req.Status == "resolved" || req.Status == "accepted" {
			resolvedExpr = "NOW()"
		}
		query := fmt.Sprintf(`UPDATE remediation_items
			SET status=$1, comment=COALESCE(NULLIF($2,''),comment),
			    updated_at=NOW(), resolved_at=%s
			WHERE id IN (%s)`, resolvedExpr, strings.Join(placeholders, ","))
		result, err := db.Exec(query, args...)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
			return
		}
		affected, _ := result.RowsAffected()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"updated":%d,"status":%q}`, affected, req.Status)
	}
}

// HandleRemediationStats — GET /api/v1/remediation/stats
func HandleRemediationStats(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		row := db.QueryRow(`SELECT
			COUNT(*) FILTER (WHERE status='open'),
			COUNT(*) FILTER (WHERE status='in_progress'),
			COUNT(*) FILTER (WHERE status='resolved'),
			COUNT(*) FILTER (WHERE status='accepted'),
			COUNT(*) FILTER (WHERE status='false_positive'),
			COUNT(*) FILTER (WHERE status='suppressed'),
			COUNT(*) FROM remediation_items`)
		var open, inProg, resolved, accepted, fp, suppressed, total int
		if err := row.Scan(&open, &inProg, &resolved, &accepted,
			&fp, &suppressed, &total); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
			return
		}
		rate := 0.0
		if total > 0 {
			rate = float64(resolved+accepted) / float64(total) * 100
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"open":%d,"in_progress":%d,"resolved":%d,"accepted":%d,`+
				`"false_positive":%d,"suppressed":%d,"total":%d,"remediation_rate":%.2f}`,
			open, inProg, resolved, accepted, fp, suppressed, total, rate)
	}
}
