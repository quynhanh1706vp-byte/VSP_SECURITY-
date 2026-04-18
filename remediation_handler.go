package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func HandleRemediationListReal(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		status := q.Get("status")
		limit, offset := 50, 0
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 500 {
			limit = l
		}
		if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
			offset = o
		}

		where, args, i := "WHERE 1=1", []interface{}{}, 1
		if status != "" && status != "all" {
			where += fmt.Sprintf(" AND r.status=$%d", i)
			args = append(args, status)
			i++
		}

		var total int
		db.QueryRowContext(r.Context(),
			"SELECT COUNT(*) FROM remediations r "+where, args...).Scan(&total)

		args = append(args, limit, offset)
		rows, err := db.QueryContext(r.Context(), fmt.Sprintf(`
			SELECT r.id::text,
			       r.finding_id::text,
			       COALESCE(f.severity,'MEDIUM'),
			       COALESCE(f.tool,''),
			       COALESCE(f.rule_id,''),
			       COALESCE(f.message,''),
			       r.status,
			       COALESCE(r.assignee,''),
			       COALESCE(r.priority,'P3'),
			       COALESCE(r.notes,''),
			       r.created_at,
			       r.updated_at
			FROM remediations r
			LEFT JOIN findings f ON f.id = r.finding_id
			%s
			ORDER BY
			  CASE COALESCE(f.severity,'LOW')
			    WHEN 'CRITICAL' THEN 1
			    WHEN 'HIGH' THEN 2
			    WHEN 'MEDIUM' THEN 3
			    ELSE 4
			  END,
			  r.created_at DESC
			LIMIT $%d OFFSET $%d`, where, i, i+1), args...)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		type Item struct {
			ID        string    `json:"id"`
			FindingID string    `json:"finding_id"`
			Severity  string    `json:"severity"`
			Tool      string    `json:"tool"`
			RuleID    string    `json:"rule_id"`
			Message   string    `json:"message"`
			Status    string    `json:"status"`
			Assignee  string    `json:"assignee"`
			Priority  string    `json:"priority"`
			Notes     string    `json:"notes"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		}

		var items []Item
		for rows.Next() {
			var it Item
			if err := rows.Scan(&it.ID, &it.FindingID, &it.Severity, &it.Tool,
				&it.RuleID, &it.Message, &it.Status, &it.Assignee,
				&it.Priority, &it.Notes, &it.CreatedAt, &it.UpdatedAt); err != nil {
				continue
			}
			items = append(items, it)
		}
		if items == nil {
			items = []Item{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"remediations": items,
			"total":        total,
			"limit":        limit,
			"offset":       offset,
		})
	}
}
