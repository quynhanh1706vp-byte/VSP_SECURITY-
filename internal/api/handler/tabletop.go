// Package handler — tabletop exercise registry.
//
//   GET    /api/v1/tabletop/exercises    — list, filter by scenario_kind
//   POST   /api/v1/tabletop/exercises    — record a completed exercise
//   GET    /api/v1/tabletop/cadence      — last-run-per-scenario summary
//
// The cadence endpoint is what an auditor actually wants — "when did
// you last practise ransomware? data breach? insider threat?" — so the
// dashboard can flag scenarios whose last run is older than the
// agreed cadence (e.g. >180 days).
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Tabletop struct {
	DB *store.DB
}

func NewTabletop(db *store.DB) *Tabletop { return &Tabletop{DB: db} }

var validScenarios = map[string]bool{
	"ransomware": true, "data_breach": true, "insider_threat": true,
	"ddos": true, "supply_chain": true, "phishing": true,
	"cloud_account_takeover": true, "third_party_outage": true,
	"generic": true,
}

func (h *Tabletop) Record(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || (claims.Role != "admin" && claims.Role != "analyst") {
		jsonError(w, "forbidden — admin or analyst role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var body struct {
		ScenarioKind string                   `json:"scenario_kind"`
		Title        string                   `json:"title"`
		ScenarioText string                   `json:"scenario_text"`
		ConductedAt  time.Time                `json:"conducted_at"`
		DurationMin  int                      `json:"duration_min"`
		Participants string                   `json:"participants"`
		Facilitator  string                   `json:"facilitator"`
		Observations string                   `json:"observations"`
		ActionItems  []map[string]any         `json:"action_items"`
		Rating       string                   `json:"rating"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	body.ScenarioKind = strings.ToLower(strings.TrimSpace(body.ScenarioKind))
	if !validScenarios[body.ScenarioKind] {
		jsonError(w, "scenario_kind must be one of: ransomware, data_breach, insider_threat, ddos, supply_chain, phishing, cloud_account_takeover, third_party_outage, generic",
			http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.Title) == "" {
		jsonError(w, "title required", http.StatusBadRequest)
		return
	}
	if body.ConductedAt.IsZero() {
		body.ConductedAt = time.Now().UTC()
	}
	if body.Rating == "" {
		body.Rating = "not_rated"
	}
	if body.ActionItems == nil {
		body.ActionItems = []map[string]any{}
	}
	itemsJSON, _ := json.Marshal(body.ActionItems)

	var id string
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO tabletop_exercises
		   (tenant_id, scenario_kind, title, scenario_text, conducted_at,
		    duration_min, participants, facilitator, observations,
		    action_items, rating)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
		 RETURNING id`,
		tenantID, body.ScenarioKind, body.Title, body.ScenarioText,
		body.ConductedAt, body.DurationMin, body.Participants, body.Facilitator,
		body.Observations, itemsJSON, body.Rating,
	).Scan(&id)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit(r, h.DB, "TABLETOP_RECORDED",
		"tabletop_exercises/"+id+":"+body.ScenarioKind)
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id})
}

func (h *Tabletop) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	scenario := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scenario_kind")))
	q := `SELECT id::text, scenario_kind, title, scenario_text, conducted_at,
	             duration_min, COALESCE(participants,''), COALESCE(facilitator,''),
	             COALESCE(observations,''), action_items, rating
	        FROM tabletop_exercises WHERE tenant_id = $1`
	args := []any{tenantID}
	if scenario != "" && validScenarios[scenario] {
		q += " AND scenario_kind = $2"
		args = append(args, scenario)
	}
	q += " ORDER BY conducted_at DESC LIMIT 200"

	rows, err := h.DB.Pool().Query(r.Context(), q, args...)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type item struct {
		ID           string          `json:"id"`
		Scenario     string          `json:"scenario_kind"`
		Title        string          `json:"title"`
		ScenarioText string          `json:"scenario_text,omitempty"`
		ConductedAt  time.Time       `json:"conducted_at"`
		DurationMin  int             `json:"duration_min"`
		Participants string          `json:"participants,omitempty"`
		Facilitator  string          `json:"facilitator,omitempty"`
		Observations string          `json:"observations,omitempty"`
		ActionItems  json.RawMessage `json:"action_items"`
		Rating       string          `json:"rating"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		_ = rows.Scan(&it.ID, &it.Scenario, &it.Title, &it.ScenarioText,
			&it.ConductedAt, &it.DurationMin, &it.Participants, &it.Facilitator,
			&it.Observations, &it.ActionItems, &it.Rating)
		out = append(out, it)
	}
	jsonOK(w, map[string]any{"exercises": out, "total": len(out)})
}

// Cadence: for each canonical scenario, return the last-conducted
// timestamp + days since. Auditor's go-to query.
func (h *Tabletop) Cadence(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT scenario_kind, MAX(conducted_at) AS last_run, COUNT(*) AS total
		   FROM tabletop_exercises
		  WHERE tenant_id = $1
		  GROUP BY scenario_kind`,
		tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	last := map[string]struct {
		ts    time.Time
		total int
	}{}
	for rows.Next() {
		var k string
		var t time.Time
		var n int
		if err := rows.Scan(&k, &t, &n); err == nil {
			last[k] = struct {
				ts    time.Time
				total int
			}{t, n}
		}
	}
	type cadenceRow struct {
		Scenario  string `json:"scenario_kind"`
		LastRun   string `json:"last_run,omitempty"`
		DaysSince int    `json:"days_since"` // -1 = never
		TotalRuns int    `json:"total_runs"`
		Status    string `json:"status"` // ok | due | overdue | never
	}
	out := []cadenceRow{}
	now := time.Now().UTC()
	for k := range validScenarios {
		row := cadenceRow{Scenario: k, DaysSince: -1, Status: "never"}
		if v, ok := last[k]; ok {
			row.LastRun = v.ts.Format(time.RFC3339)
			row.TotalRuns = v.total
			row.DaysSince = int(now.Sub(v.ts).Hours() / 24)
			switch {
			case row.DaysSince <= 90:
				row.Status = "ok"
			case row.DaysSince <= 180:
				row.Status = "due"
			default:
				row.Status = "overdue"
			}
		}
		out = append(out, row)
	}
	jsonOK(w, map[string]any{"cadence": out})
}
