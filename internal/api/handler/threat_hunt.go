package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// ThreatHunt — saved + scheduled hunt queries (migration 027).
// The actual log search is delegated to /api/v1/logs/hunt; this handler
// owns the persistence layer (queries + results) so analysts can save
// useful expressions and review run history.
type ThreatHunt struct {
	DB *store.DB
}

func NewThreatHunt(db *store.DB) *ThreatHunt { return &ThreatHunt{DB: db} }

// resolveTenantUUID accepts either a UUID directly (production login flow)
// or a slug like "default" (dev mint_jwt_local.sh scripts) and returns the
// canonical UUID. Returns "" if the tenant doesn't exist.
//
// All Threat Hunt tables FK to tenants.id (UUID), so an INSERT with a slug
// would fail with `invalid input syntax for type uuid` — this helper bridges
// both formats so dev tokens work alongside real session tokens.
func (h *ThreatHunt) resolveTenantUUID(r *http.Request, raw string) string {
	if raw == "" {
		return ""
	}
	// Already UUID? Use as-is.
	if len(raw) == 36 && raw[8] == '-' && raw[13] == '-' && raw[18] == '-' && raw[23] == '-' {
		return raw
	}
	var id string
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text FROM tenants WHERE slug = $1 LIMIT 1`, raw).Scan(&id)
	return id
}

var validHuntSeverity = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
}

// ── Queries ──────────────────────────────────────────────────────────────────

type huntQuery struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Query            string     `json:"query"`
	LookbackHours    *int       `json:"lookback_hours,omitempty"`
	ScheduleCron     string     `json:"schedule_cron,omitempty"`
	MITRETechniques  []string   `json:"mitre_techniques"`
	MinMatchSeverity string     `json:"min_match_severity"`
	Enabled          bool       `json:"enabled"`
	CreatedBy        string     `json:"created_by"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// GET /api/v1/threat-hunt/queries
func (h *ThreatHunt) ListQueries(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, name, description, query, lookback_hours,
		        COALESCE(schedule_cron,''), mitre_techniques, min_match_severity,
		        enabled, created_by, last_run_at, created_at, updated_at
		   FROM hunt_queries
		  WHERE tenant_id = $1
		  ORDER BY enabled DESC, updated_at DESC`,
		tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []huntQuery{}
	for rows.Next() {
		var q huntQuery
		var techs string
		if err := rows.Scan(&q.ID, &q.Name, &q.Description, &q.Query, &q.LookbackHours,
			&q.ScheduleCron, &techs, &q.MinMatchSeverity, &q.Enabled, &q.CreatedBy,
			&q.LastRunAt, &q.CreatedAt, &q.UpdatedAt); err != nil {
			continue
		}
		q.MITRETechniques = splitCSV(techs)
		out = append(out, q)
	}
	// SQL has no LIMIT — out is the complete hunt_queries set for the tenant.
	jsonOK(w, map[string]any{"queries": out, "total": len(out)}) // safe-len: unlimited query
}

// POST /api/v1/threat-hunt/queries
func (h *ThreatHunt) CreateQuery(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var req struct {
		Name             string   `json:"name"`
		Description      string   `json:"description"`
		Query            string   `json:"query"`
		LookbackHours    *int     `json:"lookback_hours,omitempty"`
		ScheduleCron     string   `json:"schedule_cron,omitempty"`
		MITRETechniques  []string `json:"mitre_techniques"`
		MinMatchSeverity string   `json:"min_match_severity"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Query = strings.TrimSpace(req.Query)
	if len(req.Name) == 0 || len(req.Name) > 200 {
		jsonError(w, "name 1–200 chars", http.StatusBadRequest)
		return
	}
	if len(req.Query) == 0 || len(req.Query) > 4000 {
		jsonError(w, "query 1–4000 chars", http.StatusBadRequest)
		return
	}
	if req.LookbackHours != nil && (*req.LookbackHours < 1 || *req.LookbackHours > 720) {
		jsonError(w, "lookback_hours must be 1–720", http.StatusBadRequest)
		return
	}
	sev := strings.ToLower(strings.TrimSpace(req.MinMatchSeverity))
	if sev == "" {
		sev = "medium"
	}
	if !validHuntSeverity[sev] {
		jsonError(w, "min_match_severity must be critical|high|medium|low", http.StatusBadRequest)
		return
	}
	techCSV := strings.ToUpper(strings.Join(req.MITRETechniques, ","))
	if len(techCSV) > 500 {
		jsonError(w, "too many MITRE techniques (max 500 chars CSV)", http.StatusBadRequest)
		return
	}
	cron := strings.TrimSpace(req.ScheduleCron)
	if cron != "" && len(strings.Fields(cron)) != 5 {
		jsonError(w, "schedule_cron must be 5 fields or empty", http.StatusBadRequest)
		return
	}

	var id string
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO hunt_queries(tenant_id, name, description, query,
		                          lookback_hours, schedule_cron, mitre_techniques,
		                          min_match_severity, created_by)
		 VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9)
		 ON CONFLICT(tenant_id, name) DO NOTHING
		 RETURNING id`,
		tenantID, req.Name, req.Description, req.Query,
		req.LookbackHours, cron, techCSV, sev, claims.UserID,
	).Scan(&id)
	if err != nil || id == "" {
		jsonError(w, "name already exists or db error", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "name": req.Name})
}

// DELETE /api/v1/threat-hunt/queries/{id}
func (h *ThreatHunt) DeleteQuery(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid query id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM hunt_queries WHERE id=$1 AND tenant_id=$2`,
		id, tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/threat-hunt/queries/{id}/run
// Synthetic implementation: counts events in `findings` over the lookback
// window that match the query's text (substring search across rule_id /
// description / file). Real prod would forward to the SIEM warehouse via
// /api/v1/logs/hunt. This is enough to demonstrate the panel's behaviour
// — the panel just needs a result row to display.
func (h *ThreatHunt) RunQuery(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid query id", http.StatusBadRequest)
		return
	}

	var (
		queryText     string
		lookbackHours *int
	)
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT query, lookback_hours FROM hunt_queries
		  WHERE id=$1 AND tenant_id=$2 AND enabled=TRUE`,
		id, tenantID).Scan(&queryText, &lookbackHours)
	if err != nil {
		jsonError(w, "query not found or disabled", http.StatusNotFound)
		return
	}

	lookback := 24
	if lookbackHours != nil && *lookbackHours > 0 {
		lookback = *lookbackHours
	}
	cutoff := time.Now().Add(-time.Duration(lookback) * time.Hour)

	// Substring match across findings table — a real implementation would
	// parse the Lucene-ish query and dispatch to the log warehouse.
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, severity, COALESCE(rule_id,''), COALESCE(message,''), COALESCE(path,''), created_at
		   FROM findings
		  WHERE tenant_id=$1
		    AND created_at >= $2
		    AND (rule_id ILIKE $3 OR message ILIKE $3 OR path ILIKE $3 OR tool ILIKE $3)
		  ORDER BY created_at DESC
		  LIMIT 25`,
		tenantID, cutoff, "%"+queryText+"%")
	startTime := time.Now()
	if err != nil {
		_, _ = h.DB.Pool().Exec(r.Context(),
			`INSERT INTO hunt_results(query_id, tenant_id, error, triggered_by)
			 VALUES($1, $2, $3, 'manual')`, id, tenantID, err.Error())
		jsonInternalError(w, r, "hunt failed", err)
		return
	}
	defer rows.Close()

	type sample struct {
		ID         string    `json:"id"`
		Severity   string    `json:"severity"`
		RuleID     string    `json:"rule_id"`
		Desc       string    `json:"description"`
		File       string    `json:"file,omitempty"`
		DetectedAt time.Time `json:"detected_at"`
	}
	var samples []sample
	for rows.Next() {
		var s sample
		if err := rows.Scan(&s.ID, &s.Severity, &s.RuleID, &s.Desc, &s.File, &s.DetectedAt); err != nil {
			continue
		}
		samples = append(samples, s)
	}
	if samples == nil {
		samples = []sample{}
	}
	durationMs := int(time.Since(startTime).Milliseconds())
	samplesJSON, _ := json.Marshal(samples)

	var resultID int64
	_ = h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO hunt_results(query_id, tenant_id, duration_ms, match_count, samples, triggered_by)
		 VALUES($1, $2, $3, $4, $5::jsonb, 'manual')
		 RETURNING id`,
		id, tenantID, durationMs, len(samples), string(samplesJSON),
	).Scan(&resultID)

	_, _ = h.DB.Pool().Exec(r.Context(),
		`UPDATE hunt_queries SET last_run_at = NOW(), updated_at = NOW()
		  WHERE id = $1 AND tenant_id = $2`,
		id, tenantID)

	jsonOK(w, map[string]any{
		"result_id":   resultID,
		"match_count": len(samples),
		"duration_ms": durationMs,
		"samples":     samples,
	})
}

// GET /api/v1/threat-hunt/results?query_id=<id>&limit=<n>
func (h *ThreatHunt) ListResults(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := h.resolveTenantUUID(r, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	limit := queryInt(r, "limit", 50)
	if limit < 1 || limit > 500 {
		limit = 50
	}
	// Optional query_id filter handled via nullable bind so the SQL
	// stays a single literal (no `+where+` concat → no taint-tracking
	// false positive). Empty $2 == ANY, otherwise exact-match.
	var qidFilter any
	if qid := q.Get("query_id"); qid != "" {
		if !validateUUID(qid) {
			jsonError(w, "invalid query_id", http.StatusBadRequest)
			return
		}
		qidFilter = qid
	}

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, query_id, ran_at, duration_ms, match_count,
		        COALESCE(error,''), triggered_by
		   FROM hunt_results
		  WHERE tenant_id = $1
		    AND ($2::uuid IS NULL OR query_id = $2::uuid)
		  ORDER BY ran_at DESC
		  LIMIT $3`,
		tenantID, qidFilter, limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type entry struct {
		ID          int64     `json:"id"`
		QueryID     string    `json:"query_id"`
		RanAt       time.Time `json:"ran_at"`
		DurationMs  int       `json:"duration_ms"`
		MatchCount  int       `json:"match_count"`
		Error       string    `json:"error,omitempty"`
		TriggeredBy string    `json:"triggered_by"`
	}
	var out []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.ID, &e.QueryID, &e.RanAt, &e.DurationMs,
			&e.MatchCount, &e.Error, &e.TriggeredBy); err != nil {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []entry{}
	}
	var totalCount int
	_ = h.DB.Pool().QueryRow(r.Context(),
		`SELECT COUNT(*) FROM hunt_results
		   WHERE tenant_id = $1
		     AND ($2::uuid IS NULL OR query_id = $2::uuid)`,
		tenantID, qidFilter).Scan(&totalCount)
	if totalCount == 0 {
		totalCount = len(out)
	}
	jsonOK(w, map[string]any{"results": out, "total": totalCount, "page_size": len(out)})
}
