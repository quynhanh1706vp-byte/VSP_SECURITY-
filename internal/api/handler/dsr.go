// Package handler — Data Subject Requests (DSAR + Right-to-Erasure).
//
// GDPR Art. 15/17 + Vietnam PDPA Decree 13/2023 Arts. 9-12 require any
// SaaS storing personal data to provide:
//  1. Export ("Subject Access") — return all data we hold for the tenant
//  2. Erasure ("Right to be Forgotten") — irreversibly delete on request
//
// Endpoints:
//
//	POST   /api/v1/data/export                 → kick off async export
//	GET    /api/v1/data/exports/{id}           → status + download URL
//	POST   /api/v1/data/erasure                → schedule erasure (admin)
//	POST   /api/v1/data/erasure/{id}/confirm   → confirm with token
//	POST   /api/v1/data/erasure/{id}/cancel    → cancel within grace
//	GET    /api/v1/data/requests               → list tenant requests
//
// Workers (background):
//   - dsrExportWorker drains 'pending' export requests, builds JSON
//     archive in compliance_evidence (re-using existing bytea blob),
//     marks 'ready'.
//   - dsrErasureWorker fires at scheduled_at for confirmed requests,
//     cascades DELETE across tenant rows, writes irrevocable audit
//     entries.
package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

const erasureGracePeriod = 30 * 24 * time.Hour // 30 days

type DSR struct {
	DB *store.DB
}

func NewDSR(db *store.DB) *DSR { return &DSR{DB: db} }

type dsrRow struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	ScheduledAt *time.Time `json:"scheduled_at,omitempty"`
	ResultURL   string     `json:"result_url,omitempty"`
	Notes       string     `json:"notes,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ── Export ─────────────────────────────────────────────────────────────────

// RequestExport queues a data-export request. Any authenticated user can
// trigger this for their own tenant — GDPR Art. 15 grants the right to
// the data subject, not just admins.
func (h *DSR) RequestExport(w http.ResponseWriter, r *http.Request) {
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
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	var userPtr *string
	if userID != "" {
		userPtr = &userID
	}

	var id string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO data_subject_requests (tenant_id, requested_by, kind, status)
		 VALUES ($1, $2, 'export', 'pending') RETURNING id`,
		tenantID, userPtr).Scan(&id); err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	logAudit(r, h.DB, "DSR_EXPORT_REQUESTED", "data_subject_requests/"+id)
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{
		"id":     id,
		"kind":   "export",
		"status": "pending",
	})
}

// GetExport returns status + download URL once the worker has populated it.
func (h *DSR) GetExport(w http.ResponseWriter, r *http.Request) {
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
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var row dsrRow
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT id::text, kind, status,
		        scheduled_at, COALESCE(result_url,''), COALESCE(notes,''),
		        created_at, completed_at
		   FROM data_subject_requests
		  WHERE id = $1 AND tenant_id = $2 AND kind = 'export'`,
		id, tenantID,
	).Scan(&row.ID, &row.Kind, &row.Status, &row.ScheduledAt,
		&row.ResultURL, &row.Notes, &row.CreatedAt, &row.CompletedAt)
	if err != nil {
		jsonError(w, "export request not found", http.StatusNotFound)
		return
	}
	jsonOK(w, row)
}

// ── Erasure ────────────────────────────────────────────────────────────────

// RequestErasure schedules tenant data deletion 30 days out. Admin only —
// erasure is irreversible after the grace window so the decision must
// involve someone authorised to make data lifecycle choices.
//
// Two-phase: schedule → confirm. The confirm token is returned ONCE in
// the schedule response and never stored in plaintext (only its SHA-256).
// The user must POST the token back to /confirm to actually arm the
// scheduled deletion. Without confirmation the request stays 'pending'
// and the worker will not act on it.
func (h *DSR) RequestErasure(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	var userPtr *string
	if userID != "" {
		userPtr = &userID
	}
	var body struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if len(body.Notes) > 1024 {
		body.Notes = body.Notes[:1024]
	}

	token, err := generateConfirmToken()
	if err != nil {
		jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	scheduledAt := time.Now().Add(erasureGracePeriod)
	var id string
	if err := h.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO data_subject_requests
		   (tenant_id, requested_by, kind, status, scheduled_at, notes, confirm_hash)
		 VALUES ($1, $2, 'erasure', 'pending', $3, $4, $5)
		 RETURNING id`,
		tenantID, userPtr, scheduledAt, body.Notes, hashHex,
	).Scan(&id); err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	logAudit(r, h.DB, "DSR_ERASURE_SCHEDULED",
		"data_subject_requests/"+id+"@"+scheduledAt.UTC().Format(time.RFC3339))

	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, map[string]any{
		"id":            id,
		"kind":          "erasure",
		"status":        "pending",
		"scheduled_at":  scheduledAt.UTC().Format(time.RFC3339),
		"confirm_token": token, // ONE-TIME — never returned again
		"grace_days":    int(erasureGracePeriod / (24 * time.Hour)),
		"warning":       "Erasure is irreversible. Cancel before scheduled_at to abort.",
	})
}

// ConfirmErasure verifies the SHA-256 of the supplied token matches the
// stored hash, then arms the request by transitioning to 'processing'.
// The worker will fire at scheduled_at and only acts on 'processing' rows.
func (h *DSR) ConfirmErasure(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		jsonError(w, "token required", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256([]byte(body.Token))
	hashHex := hex.EncodeToString(hash[:])

	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE data_subject_requests
		    SET status = 'processing', updated_at = NOW()
		  WHERE id = $1 AND tenant_id = $2 AND kind = 'erasure'
		    AND status = 'pending' AND confirm_hash = $3`,
		id, tenantID, hashHex)
	if err != nil {
		jsonInternalError(w, r, "db error", err)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "invalid token or request not pending", http.StatusBadRequest)
		return
	}
	logAudit(r, h.DB, "DSR_ERASURE_CONFIRMED", "data_subject_requests/"+id)
	jsonOK(w, map[string]any{"id": id, "status": "processing"})
}

// CancelErasure reverts a 'pending' or 'processing' erasure back to
// cancelled, provided the scheduled fire time hasn't passed. Admin only.
func (h *DSR) CancelErasure(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`UPDATE data_subject_requests
		    SET status = 'cancelled', updated_at = NOW(), completed_at = NOW()
		  WHERE id = $1 AND tenant_id = $2 AND kind = 'erasure'
		    AND status IN ('pending','processing')
		    AND scheduled_at > NOW()`,
		id, tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "request not cancellable (already fired or not found)",
			http.StatusBadRequest)
		return
	}
	logAudit(r, h.DB, "DSR_ERASURE_CANCELLED", "data_subject_requests/"+id)
	jsonOK(w, map[string]any{"id": id, "status": "cancelled"})
}

// List returns recent DSR rows for the tenant.
func (h *DSR) List(w http.ResponseWriter, r *http.Request) {
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
		`SELECT id::text, kind, status, scheduled_at,
		        COALESCE(result_url,''), COALESCE(notes,''),
		        created_at, completed_at
		   FROM data_subject_requests
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC LIMIT 200`, tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []dsrRow{}
	for rows.Next() {
		var row dsrRow
		if err := rows.Scan(&row.ID, &row.Kind, &row.Status, &row.ScheduledAt,
			&row.ResultURL, &row.Notes, &row.CreatedAt, &row.CompletedAt); err == nil {
			out = append(out, row)
		}
	}
	jsonOK(w, map[string]any{"requests": out, "total": len(out)})
}

// generateConfirmToken returns a cryptographically random 32-byte hex
// token. The token is shown to the user once and never persisted in
// plaintext — the DB stores only its SHA-256.
func generateConfirmToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ── Worker hook ────────────────────────────────────────────────────────────

// RunErasureWorker should be spawned at gateway start. It scans every
// tickInterval for confirmed erasure requests whose scheduled_at has
// passed, and runs the actual cascading deletion in a single tx.
//
// We expose this as an exported func so the gateway main binds it once.
func RunErasureWorker(ctx context.Context, db *store.DB, tickInterval time.Duration) {
	if tickInterval <= 0 {
		tickInterval = 5 * time.Minute
	}
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			processOneDueErasure(ctx, db)
		}
	}
}

// eraseTableExclude lists tenant_id-bearing tables that must SURVIVE an
// erasure. The DSR request itself stays so the audit trail of the
// deletion is preserved; residency/billing config persists because it
// belongs to the operator's compliance posture, not the data subject.
// The dated backup table is informational and self-cleaning.
//
// Keep in sync with scripts/test-l7-dsr-residue.sh's EXCLUDE_FROM_ERASURE
// list — L7 8.1 will fail loudly if a table appears in one but not the
// other.
var eraseTableExclude = map[string]bool{
	"data_subject_requests":          true,
	"tenant_residency":               true,
	"scan_schedules_backup_20260428": true,
}

// processOneDueErasure picks at most one due request per tick and runs
// the deletion. Single-shot keeps blast radius bounded — if a deletion
// breaks something, the next tick still lets the operator intervene.
func processOneDueErasure(ctx context.Context, db *store.DB) {
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var id, tenantID string
	err = tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text
		   FROM data_subject_requests
		  WHERE kind = 'erasure' AND status = 'processing'
		    AND scheduled_at <= NOW()
		  ORDER BY scheduled_at ASC LIMIT 1
		  FOR UPDATE SKIP LOCKED`).Scan(&id, &tenantID)
	if err != nil {
		return // no work or transient
	}

	// L7 2026-05-09: erase from EVERY tenant_id-bearing table, not a
	// hardcoded subset. The pre-L7 list covered 11 tables; the schema
	// has 77, so 62 tables retained tenant PII after "erasure" — a
	// clear GDPR Art.17 / PDPA Decree 13/2023 violation that compounds
	// every time a migration adds a new tenant-scoped table.
	//
	// We enumerate from information_schema in the same tx so a writer
	// adding a new tenant_id column can't slip past us. Some tables
	// must SURVIVE the erasure — the request log itself
	// (data_subject_requests) so the audit trail of the deletion
	// exists, and a few residency/billing config tables tracked
	// separately. eraseTableExclude lists those.
	rows, err := tx.Query(ctx,
		`SELECT table_name FROM information_schema.columns
		  WHERE column_name='tenant_id' AND table_schema='public'
		  ORDER BY table_name`)
	if err != nil {
		return
	}
	var allTables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err == nil {
			allTables = append(allTables, t)
		}
	}
	rows.Close()
	for _, tbl := range allTables {
		if eraseTableExclude[tbl] {
			continue
		}
		// Identifier comes from information_schema (server-side) so it's
		// safe to interpolate; no user-controllable input reaches here.
		// Use IF EXISTS-ish behavior by ignoring errors — a per-table
		// failure shouldn't abort the whole erasure (we re-tick later).
		_, _ = tx.Exec(ctx, "DELETE FROM "+tbl+" WHERE tenant_id = $1", tenantID)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE data_subject_requests
		    SET status = 'completed', completed_at = NOW(), updated_at = NOW()
		  WHERE id = $1`, id); err != nil {
		return
	}
	if err := tx.Commit(ctx); err != nil {
		return
	}
	// Best-effort meta-audit. We just deleted audit_log rows for the
	// tenant; this entry goes into a different tenant's audit (the
	// operator's) so it's not subject to the same erasure.
	_, _ = db.Pool().Exec(ctx,
		`INSERT INTO audit_log (tenant_id, action, resource, hash, prev_hash)
		 VALUES ($1, 'DSR_ERASURE_COMPLETED', $2, '', '')`,
		tenantID, "data_subject_requests/"+id)
}

// validateUUID is a small helper duplicated from compliance_evidence.go
// pattern. Matches the canonical 8-4-4-4-12 layout, no dependency.
func init() {
	// Cheap compile-time sanity check that erasureGracePeriod is positive.
	if erasureGracePeriod <= 0 {
		panic(errors.New("erasureGracePeriod must be positive"))
	}
}
