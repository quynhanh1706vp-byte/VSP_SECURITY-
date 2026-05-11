package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// CSPM serves the Cloud Security Posture Management endpoints (PRO feature).
// Tables: cspm_accounts, cspm_findings, cspm_config (migration 020).
type CSPM struct {
	DB *store.DB
}

func NewCSPM(db *store.DB) *CSPM { return &CSPM{DB: db} }

var validProviders = map[string]bool{
	"aws": true, "gcp": true, "azure": true, "kubernetes": true, "other": true,
}
var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}
var validFindingStatus = map[string]bool{
	"open": true, "suppressed": true, "resolved": true,
}

// ── Accounts ──────────────────────────────────────────────────────────────────

type cspmAccountRow struct {
	ID         string     `json:"id"`
	Provider   string     `json:"provider"`
	Name       string     `json:"name"`
	ExternalID string     `json:"external_id"`
	Status     string     `json:"status"`
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// GET /api/v1/cspm/accounts — list cloud accounts for the calling tenant.
func (h *CSPM) ListAccounts(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id, provider, name, external_id, status, last_sync_at, created_at
		   FROM cspm_accounts
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC`,
		claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []cspmAccountRow{}
	for rows.Next() {
		var a cspmAccountRow
		if err := rows.Scan(&a.ID, &a.Provider, &a.Name, &a.ExternalID, &a.Status, &a.LastSyncAt, &a.CreatedAt); err != nil {
			continue
		}
		out = append(out, a)
	}
	jsonOK(w, map[string]any{"accounts": out, "total": len(out)})
}

// POST /api/v1/cspm/accounts — register a new cloud account.
func (h *CSPM) CreateAccount(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Provider   string `json:"provider"`
		Name       string `json:"name"`
		ExternalID string `json:"external_id"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.Name = sanitizeString(strings.TrimSpace(req.Name), 200)
	req.ExternalID = sanitizeString(strings.TrimSpace(req.ExternalID), 200)
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be one of aws/gcp/azure/kubernetes/other", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.ExternalID == "" {
		jsonError(w, "name and external_id required", http.StatusBadRequest)
		return
	}

	var id string
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO cspm_accounts(tenant_id, provider, name, external_id)
		 VALUES($1,$2,$3,$4)
		 ON CONFLICT(tenant_id, provider, external_id) DO NOTHING
		 RETURNING id`,
		claims.TenantID, req.Provider, req.Name, req.ExternalID,
	).Scan(&id)
	if err != nil || id == "" {
		jsonError(w, "account already exists or db error", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{
		"id": id, "provider": req.Provider, "name": req.Name,
		"external_id": req.ExternalID, "status": "pending",
	})
}

// DELETE /api/v1/cspm/accounts/{id} — remove an account (cascades findings).
func (h *CSPM) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid account id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM cspm_accounts WHERE id=$1 AND tenant_id=$2`,
		id, claims.TenantID)
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

// POST /api/v1/cspm/accounts/{id}/sync — mark account for resync (placeholder
// for connector worker that runs the actual scan). Returns 202 Accepted.
func (h *CSPM) SyncAccount(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid account id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE cspm_accounts SET status='pending' WHERE id=$1 AND tenant_id=$2`,
		id, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{"id": id, "status": "queued"})
}

// ── Findings ──────────────────────────────────────────────────────────────────

type cspmFindingRow struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"account_id"`
	Provider   string     `json:"provider"`
	Severity   string     `json:"severity"`
	Resource   string     `json:"resource"`
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name,omitempty"`
	Message    string     `json:"message"`
	File       string     `json:"file,omitempty"`
	Status     string     `json:"status"`
	DetectedAt time.Time  `json:"detected_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// GET /api/v1/cspm/findings?account=<id>&severity=<s>&status=<s>&limit=<n>&offset=<n>
func (h *CSPM) ListFindings(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	args := []any{claims.TenantID}
	where := "tenant_id = $1"

	if v := q.Get("account"); v != "" {
		if !validateUUID(v) {
			jsonError(w, "invalid account id", http.StatusBadRequest)
			return
		}
		args = append(args, v)
		where += " AND account_id = $2"
	}
	if v := strings.ToLower(q.Get("severity")); v != "" {
		if !validSeverities[v] {
			jsonError(w, "invalid severity", http.StatusBadRequest)
			return
		}
		args = append(args, v)
		where += " AND severity = $" + itoa(len(args))
	}
	if v := strings.ToLower(q.Get("status")); v != "" {
		if !validFindingStatus[v] {
			jsonError(w, "invalid status", http.StatusBadRequest)
			return
		}
		args = append(args, v)
		where += " AND status = $" + itoa(len(args))
	}

	limit := queryInt(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}
	if limit < 1 {
		limit = 100
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	args = append(args, limit, offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	// where + LIMIT/OFFSET are literal SQL with $N placeholders; user input via args.
	sql := `SELECT id, account_id, provider, severity, resource, rule_id,
	               COALESCE(rule_name,''), message, COALESCE(file,''),
	               status, detected_at, resolved_at
	          FROM cspm_findings
	         WHERE ` + where +
		` ORDER BY detected_at DESC
	         LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))

	rows, err := h.DB.Pool().Query(r.Context(), sql, args...)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []cspmFindingRow{}
	for rows.Next() {
		var f cspmFindingRow
		if err := rows.Scan(&f.ID, &f.AccountID, &f.Provider, &f.Severity, &f.Resource,
			&f.RuleID, &f.RuleName, &f.Message, &f.File, &f.Status, &f.DetectedAt, &f.ResolvedAt); err != nil {
			continue
		}
		out = append(out, f)
	}
	jsonOK(w, map[string]any{"findings": out, "total": len(out), "limit": limit, "offset": offset})
}

// GET /api/v1/cspm/findings/{id}
func (h *CSPM) GetFinding(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	var f cspmFindingRow
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT id, account_id, provider, severity, resource, rule_id,
		        COALESCE(rule_name,''), message, COALESCE(file,''),
		        status, detected_at, resolved_at
		   FROM cspm_findings
		  WHERE id=$1 AND tenant_id=$2`,
		id, claims.TenantID,
	).Scan(&f.ID, &f.AccountID, &f.Provider, &f.Severity, &f.Resource, &f.RuleID,
		&f.RuleName, &f.Message, &f.File, &f.Status, &f.DetectedAt, &f.ResolvedAt)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	jsonOK(w, f)
}

// POST /api/v1/cspm/findings/{id}/status — body {"status":"open|suppressed|resolved"}
func (h *CSPM) UpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid finding id", http.StatusBadRequest)
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	if !validFindingStatus[req.Status] {
		jsonError(w, "status must be open|suppressed|resolved", http.StatusBadRequest)
		return
	}

	resolvedClause := ", resolved_at = NULL"
	if req.Status == "resolved" {
		resolvedClause = ", resolved_at = NOW()"
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE cspm_findings SET status=$1`+resolvedClause+
			` WHERE id=$2 AND tenant_id=$3`,
		req.Status, id, claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]any{"id": id, "status": req.Status})
}

// ── Posture (aggregated score per provider) ───────────────────────────────────

type posturePerProvider struct {
	Provider     string  `json:"provider"`
	Accounts     int     `json:"accounts"`
	Critical     int     `json:"critical"`
	High         int     `json:"high"`
	Medium       int     `json:"medium"`
	Low          int     `json:"low"`
	Info         int     `json:"info"`
	OpenFindings int     `json:"open_findings"`
	Score        float64 `json:"score"` // 0-100
}

// GET /api/v1/cspm/posture — aggregated per-provider posture for the tenant.
func (h *CSPM) Posture(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT provider, severity, COUNT(*)
		   FROM cspm_findings
		  WHERE tenant_id=$1 AND status='open'
		  GROUP BY provider, severity`,
		claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	byProv := map[string]*posturePerProvider{}
	for rows.Next() {
		var prov, sev string
		var count int
		if err := rows.Scan(&prov, &sev, &count); err != nil {
			continue
		}
		p, ok := byProv[prov]
		if !ok {
			p = &posturePerProvider{Provider: prov}
			byProv[prov] = p
		}
		p.OpenFindings += count
		switch sev {
		case "critical":
			p.Critical = count
		case "high":
			p.High = count
		case "medium":
			p.Medium = count
		case "low":
			p.Low = count
		case "info":
			p.Info = count
		}
	}

	// Overlay account counts per provider.
	accRows, err := h.DB.Pool().Query(r.Context(),
		`SELECT provider, COUNT(*) FROM cspm_accounts WHERE tenant_id=$1 GROUP BY provider`,
		claims.TenantID)
	if err == nil {
		defer accRows.Close()
		for accRows.Next() {
			var prov string
			var n int
			if err := accRows.Scan(&prov, &n); err != nil {
				continue
			}
			if p, ok := byProv[prov]; ok {
				p.Accounts = n
			} else {
				byProv[prov] = &posturePerProvider{Provider: prov, Accounts: n, Score: 100}
			}
		}
	}

	out := make([]posturePerProvider, 0, len(byProv))
	for _, p := range byProv {
		// Weighted score: critical=10, high=5, medium=2, low=1, info=0.5
		penalty := float64(p.Critical*10 + p.High*5 + p.Medium*2 + p.Low)
		penalty += float64(p.Info) * 0.5
		base := penalty + 100 // simple normalization: more findings → lower score
		if base > 0 {
			p.Score = (100.0 / base) * 100.0
		} else {
			p.Score = 100.0
		}
		if p.Score > 100 {
			p.Score = 100
		}
		out = append(out, *p)
	}
	jsonOK(w, map[string]any{"posture": out, "total_providers": len(out)})
}

// ── Per-tenant feature config (PRO "view details" panel) ─────────────────────

type cspmConfig struct {
	SyncIntervalMin  int       `json:"sync_interval_min"`
	RetentionDays    int       `json:"retention_days"`
	AutoFixEnabled   bool      `json:"auto_fix_enabled"`
	NotifySeverities []string  `json:"notify_severities"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// GET /api/v1/cspm/config — return per-tenant CSPM config (creates default row on first read).
func (h *CSPM) GetConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var (
		cfg cspmConfig
		sev string
	)
	err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO cspm_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING sync_interval_min, retention_days, auto_fix_enabled,
		           notify_severities, updated_at`,
		claims.TenantID,
	).Scan(&cfg.SyncIntervalMin, &cfg.RetentionDays, &cfg.AutoFixEnabled, &sev, &cfg.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	cfg.NotifySeverities = splitCSV(sev)
	jsonOK(w, cfg)
}

// PUT /api/v1/cspm/config — update per-tenant CSPM config.
func (h *CSPM) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SyncIntervalMin  int      `json:"sync_interval_min"`
		RetentionDays    int      `json:"retention_days"`
		AutoFixEnabled   bool     `json:"auto_fix_enabled"`
		NotifySeverities []string `json:"notify_severities"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.SyncIntervalMin < 5 || req.SyncIntervalMin > 1440 {
		jsonError(w, "sync_interval_min must be 5..1440", http.StatusBadRequest)
		return
	}
	if req.RetentionDays < 7 || req.RetentionDays > 730 {
		jsonError(w, "retention_days must be 7..730", http.StatusBadRequest)
		return
	}
	for _, s := range req.NotifySeverities {
		if !validSeverities[strings.ToLower(s)] {
			jsonError(w, "notify_severities contains invalid severity", http.StatusBadRequest)
			return
		}
	}
	sevCSV := strings.ToLower(strings.Join(req.NotifySeverities, ","))
	if sevCSV == "" {
		sevCSV = "critical,high"
	}

	_, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO cspm_config(tenant_id, sync_interval_min, retention_days,
		                          auto_fix_enabled, notify_severities, updated_at)
		 VALUES($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   sync_interval_min = EXCLUDED.sync_interval_min,
		   retention_days    = EXCLUDED.retention_days,
		   auto_fix_enabled  = EXCLUDED.auto_fix_enabled,
		   notify_severities = EXCLUDED.notify_severities,
		   updated_at        = NOW()`,
		claims.TenantID, req.SyncIntervalMin, req.RetentionDays,
		req.AutoFixEnabled, sevCSV)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	jsonOK(w, map[string]any{"ok": true})
}

// ── small local helpers (avoid pulling strconv just for itoa) ─────────────────

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func splitCSV(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
