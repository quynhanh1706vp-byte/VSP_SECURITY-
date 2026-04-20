//go:build devstub
// +build devstub

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// GET /api/v1/vsp/run/latest
// Trả run DONE gần nhất kèm summary severity breakdown
// ═══════════════════════════════════════════════════════════════
func HandleRunLatest(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type RunResp struct {
			ID            string          `json:"id"`
			RID           string          `json:"rid"`
			Mode          string          `json:"mode"`
			Profile       string          `json:"profile"`
			Status        string          `json:"status"`
			Gate          string          `json:"gate"`
			Score         int             `json:"score"`
			TotalFindings int             `json:"total_findings"`
			StartedAt     *time.Time      `json:"started_at"`
			FinishedAt    *time.Time      `json:"finished_at"`
			Summary       json.RawMessage `json:"summary"`
			RunID         string          `json:"run_id"` // alias cho frontend
		}

		// Lấy run DONE gần nhất
		row := db.QueryRowContext(r.Context(), `
			SELECT id::text, rid, mode, profile, status,
			       COALESCE(gate,''), COALESCE((summary->>'SCORE')::int,0),
			       COALESCE(total_findings,0),
			       started_at, finished_at,
			       COALESCE(summary,'{}')
			FROM runs
			WHERE status IN ('DONE','done')
			ORDER BY started_at DESC
			LIMIT 1`)

		var run RunResp
		var summaryBytes []byte
		err := row.Scan(&run.ID, &run.RID, &run.Mode, &run.Profile,
			&run.Status, &run.Gate, &run.Score, &run.TotalFindings,
			&run.StartedAt, &run.FinishedAt, &summaryBytes)
		if err == sql.ErrNoRows {
			// Không có run nào — trả empty nhưng hợp lệ
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"","rid":"","status":"none","gate":"","score":0,"total_findings":0,"summary":{}}`))
			return
		}
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}

		// Parse summary JSONB, inject severity counts từ findings thật
		var summ map[string]interface{}
		json.Unmarshal(summaryBytes, &summ)
		if summ == nil {
			summ = map[string]interface{}{}
		}

		// Luôn tính lại severity từ findings để đảm bảo chính xác
		sevRow := db.QueryRowContext(r.Context(), `
			SELECT
			  COUNT(*) FILTER (WHERE severity='CRITICAL'),
			  COUNT(*) FILTER (WHERE severity='HIGH'),
			  COUNT(*) FILTER (WHERE severity='MEDIUM'),
			  COUNT(*) FILTER (WHERE severity='LOW'),
			  COUNT(*)
			FROM findings WHERE rid=$1`, run.RID)
		var crit, high, med, low, total int
		sevRow.Scan(&crit, &high, &med, &low, &total)

		// Nếu findings table có data, override summary
		if total > 0 {
			summ["CRITICAL"] = crit
			summ["HIGH"] = high
			summ["MEDIUM"] = med
			summ["LOW"] = low
			run.TotalFindings = total
		}

		// Score: lấy từ summary nếu có, fallback tính đơn giản
		if sc, ok := summ["SCORE"]; ok {
			switch v := sc.(type) {
			case float64:
				run.Score = int(v)
			}
		}

		summBytes, _ := json.Marshal(summ)
		run.Summary = summBytes
		run.RunID = run.ID // alias

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(run)
	}
}

// ═══════════════════════════════════════════════════════════════
// GET /api/v1/vsp/runs/index?limit=50
// Danh sách runs cho sparkline và analytics
// ═══════════════════════════════════════════════════════════════
func HandleRunsIndex(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 50
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
			ORDER BY started_at DESC
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
			run.Summary = summBytes
			runs = append(runs, run)
		}
		if runs == nil {
			runs = []RunRow{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"runs":  runs,
			"total": len(runs),
		})
	}
}

// ═══════════════════════════════════════════════════════════════
// GET /api/v1/vsp/findings/summary?scope=all|run_id=xxx
// Dùng cho chartSeverity và KPI cards
// ═══════════════════════════════════════════════════════════════
func HandleFindingsSummary(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		runID := r.URL.Query().Get("run_id")
		rid := r.URL.Query().Get("rid")

		var query string
		var args []interface{}

		if scope == "all" || (runID == "" && rid == "") {
			// All-time summary
			query = `SELECT
				COUNT(*) FILTER (WHERE severity='CRITICAL'),
				COUNT(*) FILTER (WHERE severity='HIGH'),
				COUNT(*) FILTER (WHERE severity='MEDIUM'),
				COUNT(*) FILTER (WHERE severity='LOW'),
				COUNT(*) FILTER (WHERE severity='INFO'),
				COUNT(*)
			FROM findings`
		} else if rid != "" {
			query = `SELECT
				COUNT(*) FILTER (WHERE severity='CRITICAL'),
				COUNT(*) FILTER (WHERE severity='HIGH'),
				COUNT(*) FILTER (WHERE severity='MEDIUM'),
				COUNT(*) FILTER (WHERE severity='LOW'),
				COUNT(*) FILTER (WHERE severity='INFO'),
				COUNT(*)
			FROM findings WHERE rid=$1`
			args = append(args, rid)
		} else {
			// run_id = UUID
			query = `SELECT
				COUNT(*) FILTER (WHERE severity='CRITICAL'),
				COUNT(*) FILTER (WHERE severity='HIGH'),
				COUNT(*) FILTER (WHERE severity='MEDIUM'),
				COUNT(*) FILTER (WHERE severity='LOW'),
				COUNT(*) FILTER (WHERE severity='INFO'),
				COUNT(*)
			FROM findings WHERE run_id=$1::uuid`
			args = append(args, runID)
		}

		var crit, high, med, low, info, total int
		err := db.QueryRowContext(r.Context(), query, args...).
			Scan(&crit, &high, &med, &low, &info, &total)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"critical":%d,"high":%d,"medium":%d,"low":%d,"info":%d,"total":%d}`,
			crit, high, med, low, info, total)
	}
}

// ═══════════════════════════════════════════════════════════════
// GET /api/v1/vsp/findings?severity=&tool=&limit=&offset=
// ═══════════════════════════════════════════════════════════════
func HandleFindingsList(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		severity := q.Get("severity")
		tool := q.Get("tool")
		status := q.Get("status")
		rid := q.Get("rid")
		limit := 50
		offset := 0
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 500 {
			limit = l
		}
		if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
			offset = o
		}

		where := "WHERE 1=1"
		args := []interface{}{}
		i := 1
		if severity != "" {
			where += fmt.Sprintf(" AND severity=$%d", i)
			args = append(args, severity)
			i++
		}
		if tool != "" {
			where += fmt.Sprintf(" AND tool=$%d", i)
			args = append(args, tool)
			i++
		}
		if status != "" {
			where += fmt.Sprintf(" AND status=$%d", i)
			args = append(args, status)
			i++
		}
		if rid != "" {
			where += fmt.Sprintf(" AND rid=$%d", i)
			args = append(args, rid)
			i++
		}

		// Count
		var total int
		db.QueryRowContext(r.Context(),
			"SELECT COUNT(*) FROM findings "+where, args...).Scan(&total)

		// Data
		args = append(args, limit, offset)
		rows, err := db.QueryContext(r.Context(), fmt.Sprintf(`
			SELECT id::text, COALESCE(rid,''), tool, severity,
			       COALESCE(rule_id,''), COALESCE(message,''),
			       COALESCE(path,''), COALESCE(line_num,0),
			       COALESCE(cwe,''), status, created_at
			FROM findings %s
			ORDER BY
			  CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
			    WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
			  created_at DESC
			LIMIT $%d OFFSET $%d`, where, i, i+1), args...)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		type Finding struct {
			ID        string    `json:"id"`
			RID       string    `json:"rid"`
			Tool      string    `json:"tool"`
			Severity  string    `json:"severity"`
			RuleID    string    `json:"rule_id"`
			Message   string    `json:"message"`
			Path      string    `json:"path"`
			LineNum   int       `json:"line_num"`
			CWE       string    `json:"cwe"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		}

		var findings []Finding
		for rows.Next() {
			var f Finding
			if err := rows.Scan(&f.ID, &f.RID, &f.Tool, &f.Severity,
				&f.RuleID, &f.Message, &f.Path, &f.LineNum,
				&f.CWE, &f.Status, &f.CreatedAt); err != nil {
				continue
			}
			findings = append(findings, f)
		}
		if findings == nil {
			findings = []Finding{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"findings": findings,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		})
	}
}

// ── helper ────────────────────────────────────────────────────
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func HandleRemediationStatsReal(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		row := db.QueryRowContext(r.Context(), `
			SELECT
			  COUNT(*) FILTER (WHERE status='open'),
			  COUNT(*) FILTER (WHERE status='in_progress'),
			  COUNT(*) FILTER (WHERE status='resolved'),
			  COUNT(*) FILTER (WHERE status='accepted'),
			  COUNT(*) FILTER (WHERE status='false_positive'),
			  COUNT(*) FILTER (WHERE status='suppressed'),
			  COUNT(*) FROM remediations`)
		var open, inProg, resolved, accepted, fp, suppressed, total int
		if err := row.Scan(&open, &inProg, &resolved, &accepted, &fp, &suppressed, &total); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		rate := 0.0
		if total > 0 {
			rate = float64(resolved+accepted) / float64(total) * 100
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"open":%d,"in_progress":%d,"resolved":%d,"accepted":%d,"false_positive":%d,"suppressed":%d,"total":%d,"remediation_rate":%.2f}`,
			open, inProg, resolved, accepted, fp, suppressed, total, rate)
	}
}

func HandleRemediationStatusReal(db *sql.DB) http.HandlerFunc {
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
			jsonError(w, "missing id", 400)
			return
		}
		var req struct {
			Status   string `json:"status"`
			Assignee string `json:"assignee"`
			Notes    string `json:"notes"`
			Priority string `json:"priority"`
			Ticket   string `json:"ticket_url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		valid := map[string]bool{"open": true, "in_progress": true, "resolved": true, "accepted": true, "false_positive": true, "suppressed": true}
		if !valid[req.Status] {
			jsonError(w, "invalid status", 400)
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
			jsonError(w, err.Error(), 500)
			return
		}
		if n, _ := result.RowsAffected(); n == 0 {
			db.ExecContext(r.Context(), `UPDATE remediations SET status=$1,resolved_at=$2,updated_at=NOW() WHERE finding_id=$3::uuid`, req.Status, resolvedAt, id)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"id":%q,"new_status":%q}`, id, req.Status)
	}
}

func HandleFindingsListReal(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		severity, tool, status := q.Get("severity"), q.Get("tool"), q.Get("status")
		runID, rid := q.Get("run_id"), q.Get("rid")
		limit, offset := 50, 0
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 500 {
			limit = l
		}
		if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
			offset = o
		}
		if rid != "" && runID == "" {
			db.QueryRowContext(r.Context(), `SELECT id::text FROM runs WHERE rid=$1 LIMIT 1`, rid).Scan(&runID)
		}
		where, args, i := "WHERE 1=1", []interface{}{}, 1
		if runID != "" {
			where += fmt.Sprintf(" AND f.run_id=$%d::uuid", i)
			args = append(args, runID)
			i++
		}
		if severity != "" {
			where += fmt.Sprintf(" AND f.severity=$%d", i)
			args = append(args, severity)
			i++
		}
		if tool != "" {
			where += fmt.Sprintf(" AND f.tool=$%d", i)
			args = append(args, tool)
			i++
		}
		if status != "" {
			where += fmt.Sprintf(" AND COALESCE(rem.status,'open')=$%d", i)
			args = append(args, status)
			i++
		}
		var total int
		db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM findings f LEFT JOIN remediations rem ON rem.finding_id=f.id "+where, args...).Scan(&total)
		args = append(args, limit, offset)
		rows, err := db.QueryContext(r.Context(), fmt.Sprintf(`
			SELECT f.id::text, f.run_id::text, f.tool, f.severity,
			       COALESCE(f.rule_id,''), COALESCE(f.message,''),
			       COALESCE(f.path,''), COALESCE(f.line_num,0),
			       COALESCE(f.cwe,''), COALESCE(f.cvss,0),
			       COALESCE(rem.status,'open'), f.created_at
			FROM findings f
			LEFT JOIN remediations rem ON rem.finding_id=f.id
			%s ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
			LIMIT $%d OFFSET $%d`, where, i, i+1), args...)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		type Finding struct {
			ID        string    `json:"id"`
			RunID     string    `json:"run_id"`
			Tool      string    `json:"tool"`
			Severity  string    `json:"severity"`
			RuleID    string    `json:"rule_id"`
			Message   string    `json:"message"`
			Path      string    `json:"path"`
			LineNum   int       `json:"line_num"`
			CWE       string    `json:"cwe"`
			CVSS      float64   `json:"cvss"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		}
		var findings []Finding
		for rows.Next() {
			var f Finding
			if err := rows.Scan(&f.ID, &f.RunID, &f.Tool, &f.Severity, &f.RuleID, &f.Message,
				&f.Path, &f.LineNum, &f.CWE, &f.CVSS, &f.Status, &f.CreatedAt); err != nil {
				continue
			}
			findings = append(findings, f)
		}
		if findings == nil {
			findings = []Finding{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"findings": findings, "total": total, "limit": limit, "offset": offset})
	}
}

func HandleFindingsByTool(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		runID, rid := r.URL.Query().Get("run_id"), r.URL.Query().Get("rid")
		if rid != "" && runID == "" {
			db.QueryRowContext(r.Context(), `SELECT id::text FROM runs WHERE rid=$1 LIMIT 1`, rid).Scan(&runID)
		}
		if runID == "" {
			jsonError(w, "run_id or rid required", 400)
			return
		}
		rows, err := db.QueryContext(r.Context(), `
			SELECT tool, COUNT(*), COUNT(*) FILTER (WHERE severity='CRITICAL'),
			       COUNT(*) FILTER (WHERE severity='HIGH'), COUNT(*) FILTER (WHERE severity='MEDIUM'),
			       COUNT(*) FILTER (WHERE severity='LOW')
			FROM findings WHERE run_id=$1::uuid GROUP BY tool ORDER BY COUNT(*) DESC`, runID)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		type T struct {
			Tool                               string `json:"tool"`
			Total, Critical, High, Medium, Low int
		}
		var tools []T
		for rows.Next() {
			var t T
			_ = rows.Scan(&t.Tool, &t.Total, &t.Critical, &t.High, &t.Medium, &t.Low)
			tools = append(tools, t)
		}
		if tools == nil {
			tools = []T{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"tools": tools})
	}
}

func HandleRunLog(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		rid := ""
		for i, p := range parts {
			if p == "run" && i+2 < len(parts) && parts[i+2] == "log" {
				rid = parts[i+1]
				break
			}
		}
		if rid == "" {
			jsonError(w, "missing rid", 400)
			return
		}
		var runUUID, mode, status, gate string
		var totalFindings int
		var startedAt time.Time
		var finishedAt *time.Time
		var summBytes []byte
		err := db.QueryRowContext(r.Context(), `
			SELECT id::text, mode, status, COALESCE(gate,''),
			       COALESCE(total_findings,0), started_at, finished_at, COALESCE(summary,'{}')
			FROM runs WHERE rid=$1 LIMIT 1`, rid).
			Scan(&runUUID, &mode, &status, &gate, &totalFindings, &startedAt, &finishedAt, &summBytes)
		if err == sql.ErrNoRows {
			jsonError(w, "not found", 404)
			return
		}
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		var summ map[string]interface{}
		json.Unmarshal(summBytes, &summ)
		score := 0
		if sc, ok := summ["SCORE"]; ok {
			if v, ok := sc.(float64); ok {
				score = int(v)
			}
		}
		rows, err := db.QueryContext(r.Context(), `
			SELECT tool, COUNT(*), COUNT(*) FILTER (WHERE severity='CRITICAL'),
			       COUNT(*) FILTER (WHERE severity='HIGH'), COUNT(*) FILTER (WHERE severity='MEDIUM'),
			       COUNT(*) FILTER (WHERE severity='LOW')
			FROM findings WHERE run_id=$1::uuid GROUP BY tool ORDER BY COUNT(*) DESC`, runUUID)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		type TR struct {
			Tool                        string
			Total, Crit, High, Med, Low int
		}
		var toolRows []TR
		for rows.Next() {
			var t TR
			rows.Scan(&t.Tool, &t.Total, &t.Crit, &t.High, &t.Med, &t.Low)
			toolRows = append(toolRows, t)
		}
		type L struct{ TS, Tool, Level, Msg string }
		var lines []L
		ts := 0
		f := func(s int) string { return fmt.Sprintf("%02d:%02d:%02d", s/3600, (s%3600)/60, s%60) }
		lines = append(lines, L{f(ts), "scanner", "INFO", fmt.Sprintf("Run started: %s", rid)})
		ts++
		lines = append(lines, L{f(ts), "scanner", "INFO", fmt.Sprintf("Mode: %s · Total: %d findings", mode, totalFindings)})
		ts++
		for _, t := range toolRows {
			lines = append(lines, L{f(ts), t.Tool, "INFO", "Starting scan…"})
			ts++
			if t.Crit > 0 {
				lines = append(lines, L{f(ts), t.Tool, "ERROR", fmt.Sprintf("Found %d CRITICAL findings", t.Crit)})
				ts++
			}
			if t.High > 0 {
				lines = append(lines, L{f(ts), t.Tool, "WARN", fmt.Sprintf("Found %d HIGH findings", t.High)})
				ts++
			}
			if t.Med > 0 {
				lines = append(lines, L{f(ts), t.Tool, "WARN", fmt.Sprintf("Found %d MEDIUM findings", t.Med)})
				ts++
			}
			lines = append(lines, L{f(ts), t.Tool, "DONE", fmt.Sprintf("Completed · %d findings", t.Total)})
			ts++
		}
		gl := "INFO"
		if gate == "FAIL" {
			gl = "ERROR"
		} else if gate == "WARN" {
			gl = "WARN"
		}
		lines = append(lines, L{f(ts), "gate", gl, fmt.Sprintf("Gate: %s · %d findings · Score: %d/100", gate, totalFindings, score)})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rid": rid, "mode": mode, "status": status, "gate": gate, "score": score,
			"total_findings": totalFindings, "lines": lines, "line_count": len(lines),
		})
	}
}

func HandleRunByRID(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		rid := parts[len(parts)-1]
		if rid == "" {
			jsonError(w, "missing rid", 400)
			return
		}
		var id, mode, status, gate string
		var score, totalFindings int
		var startedAt *time.Time
		var finishedAt *time.Time
		var summBytes []byte
		err := db.QueryRowContext(r.Context(), `
			SELECT id::text, mode, status, COALESCE(gate,''),
			       COALESCE((summary->>'SCORE')::int,0), COALESCE(total_findings,0),
			       started_at, finished_at, COALESCE(summary,'{}')
			FROM runs WHERE rid=$1 LIMIT 1`, rid).
			Scan(&id, &mode, &status, &gate, &score, &totalFindings,
				&startedAt, &finishedAt, &summBytes)
		if err == sql.ErrNoRows {
			jsonError(w, "not found", 404)
			return
		}
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		var summ map[string]interface{}
		json.Unmarshal(summBytes, &summ)
		if summ == nil {
			summ = map[string]interface{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": id, "rid": rid, "mode": mode, "status": status,
			"gate": gate, "score": score, "total_findings": totalFindings,
			"started_at": startedAt, "finished_at": finishedAt, "summary": summ,
		})
	}
}
