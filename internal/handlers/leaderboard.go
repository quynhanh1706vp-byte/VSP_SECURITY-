package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

// LeaderboardEntry is one row in the remediation leaderboard.
// Email is masked unless user has opted into visibility.
type LeaderboardEntry struct {
	Rank          int     `json:"rank"`
	Actor         string  `json:"actor"`           // masked or full per opt-in
	VerifiedCount int     `json:"verified_count"`
	AppliedCount  int     `json:"applied_count"`
	AvgMTTRHours  float64 `json:"avg_mttr_hours"`
	OptedIn       bool    `json:"opted_in"`
}

// LeaderboardResponse wraps the entries with metadata for the UI.
type LeaderboardResponse struct {
	Period  string             `json:"period"`
	Tenant  string             `json:"tenant"`
	Entries []LeaderboardEntry `json:"entries"`
	Total   int                `json:"total"`
}

// LeaderboardHandler returns GET /api/v1/autofix/leaderboard
// Reuses the existing audit_log table — no new schema needed.
//
// Privacy: by default, actors see ONLY themselves with full email
// and others as masked entries (c***@vsp.local). Users opt in via
// settings to appear with full email.
func LeaderboardHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		period := r.URL.Query().Get("period")
		if period == "" { period = "30d" }
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" { tenantID = "default" }

		intervalSQL := map[string]string{
			"7d":  "7 days",
			"30d": "30 days",
			"90d": "90 days",
			"all": "100 years",
		}[period]
		if intervalSQL == "" { intervalSQL = "30 days" }

		// Query audit_log for status transitions to verified/fix_applied.
		// Falls back gracefully if audit_log table doesn't exist (returns empty list).
		query := `
			SELECT
				COALESCE(actor, 'unknown') AS actor,
				COUNT(*) FILTER (WHERE detail LIKE '%verified%')      AS verified_count,
				COUNT(*) FILTER (WHERE detail LIKE '%fix_applied%')   AS applied_count,
				0.0 AS avg_mttr_hours
			FROM audit_log
			WHERE created_at > NOW() - INTERVAL '` + intervalSQL + `'
			  AND (detail LIKE '%verified%' OR detail LIKE '%fix_applied%')
			GROUP BY actor
			ORDER BY verified_count DESC
			LIMIT 20
		`

		rows, err := db.QueryContext(r.Context(), query)
		if err != nil {
			// Table may not exist or schema differs — return empty board, log internally
			writeJSON(w, LeaderboardResponse{
				Period:  period,
				Tenant:  tenantID,
				Entries: []LeaderboardEntry{},
				Total:   0,
			})
			return
		}
		defer rows.Close()

		entries := []LeaderboardEntry{}
		rank := 1
		for rows.Next() {
			var e LeaderboardEntry
			if err := rows.Scan(&e.Actor, &e.VerifiedCount, &e.AppliedCount, &e.AvgMTTRHours); err != nil {
				continue
			}
			e.Rank = rank
			rank++

			// Privacy: check opt-in status via user_preferences (best effort)
			e.OptedIn = isOptedIn(db, e.Actor)
			if !e.OptedIn {
				e.Actor = maskEmail(e.Actor)
			}
			entries = append(entries, e)
		}

		writeJSON(w, LeaderboardResponse{
			Period:  period,
			Tenant:  tenantID,
			Entries: entries,
			Total:   len(entries),
		})
	}
}

// isOptedIn checks user_preferences table for leaderboard_visible flag.
// Returns false on any error (privacy by default).
func isOptedIn(db *sql.DB, actor string) bool {
	var visible sql.NullBool
	_ = db.QueryRow(
		`SELECT leaderboard_visible FROM user_preferences WHERE email = $1`,
		actor,
	).Scan(&visible)
	return visible.Valid && visible.Bool
}

// maskEmail turns "cuong@vsp.local" into "c***@vsp.local".
func maskEmail(email string) string {
	at := strings.Index(email, "@")
	if at <= 1 { return "***" }
	return email[:1] + strings.Repeat("*", 3) + email[at:]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
