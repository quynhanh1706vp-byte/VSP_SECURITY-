package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Audit struct {
	DB *store.DB
}

// GET /api/v1/audit/log
func (h *Audit) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)
	actionFilter := r.URL.Query().Get("action")

	// Sprint 12.7: resolve tenant slug → UUID. Pre-12.7 dev JWTs
	// carrying tenant_id="default" caused SQLSTATE 22P02. Same root
	// cause as Sprint 12.6 audit/verify; pinning here too keeps the
	// pattern consistent across all audit endpoints.
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}

	entries, total, err := h.DB.ListAuditPaged(r.Context(),
		tenantID, actionFilter, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	jsonOK(w, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// POST /api/v1/audit/verify
func (h *Audit) Verify(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	// Sprint 12.6: resolve tenant slug → UUID before passing to the
	// audit chain walker. Pre-12.6 dev JWTs carrying tenant_id="default"
	// (slug, not UUID) caused SQLSTATE 22P02 (invalid uuid syntax) and
	// the verify reported ok=false with a parse error instead of an
	// honest chain-integrity result.
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	result := audit.Verify(r.Context(), &auditStoreAdapter{db: h.DB}, tenantID)
	// Always return 200: the request itself succeeded — `ok:false` in body
	// expresses the negative result. Returning 4xx for "valid request with
	// negative outcome" makes generic FE fetch wrappers swallow the body and
	// surface a misleading "request failed" UX. Convention matches
	// /api/v1/health and /api/v1/compliance/* which use ok-in-body.
	if !result.OK {
		AuditChainBreaks.Inc()
		errMsg := ""
		if result.Err != nil {
			errMsg = result.Err.Error()
		}
		jsonOK(w, map[string]any{
			"ok":            false,
			"checked":       result.Checked,
			"broken_at_seq": result.BrokenAtSeq,
			"error":         errMsg,
		})
		return
	}
	// L8 fix: who-verified-when is itself a compliance-relevant
	// event. SOC 2 CC4.1 expects an audit trail of integrity checks,
	// not just integrity-check failures. Logging on the OK path
	// matches that expectation.
	logAudit(r, h.DB, "CHAIN_VERIFY_OK",
		"audit_log/checked="+itoa(result.Checked))
	jsonOK(w, map[string]any{
		"ok":      true,
		"checked": result.Checked,
		"message": "audit chain intact",
	})
}

// auditStoreAdapter adapts store.DB to audit.Store interface
type auditStoreAdapter struct{ db *store.DB }

func (a *auditStoreAdapter) ListAuditByTenant(ctx context.Context, tenantID string) ([]audit.Entry, error) {
	dbEntries, err := a.db.ListAuditByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	entries := make([]audit.Entry, 0, len(dbEntries))
	for _, e := range dbEntries {
		uid := ""
		if e.UserID != nil {
			uid = *e.UserID
		}
		entries = append(entries, audit.Entry{
			Seq:        e.Seq,
			TenantID:   e.TenantID,
			UserID:     uid,
			Action:     e.Action,
			Resource:   e.Resource,
			IP:         e.IP,
			PrevHash:   e.PrevHash,
			StoredHash: e.Hash,
		})
	}
	return entries, nil
}

func (a *auditStoreAdapter) WriteAudit(ctx context.Context, e audit.Entry) (int64, error) {
	uid := (*string)(nil)
	if e.UserID != "" {
		uid = &e.UserID
	}
	seq, _, err := a.db.InsertAudit(ctx, store.AuditWriteParams{
		TenantID: e.TenantID, UserID: uid,
		Action: e.Action, Resource: e.Resource,
		IP: e.IP, PrevHash: e.PrevHash,
	})
	return seq, err
}

// UpdateAuditHashes implements audit.Repairer — bridges to store.DB.
func (a *auditStoreAdapter) UpdateAuditHashes(ctx context.Context, tenantID string, entries []audit.Entry) error {
	return a.db.UpdateAuditHashes(ctx, tenantID, entries)
}

// POST /api/v1/audit/repair — admin-only chain rebuild after tamper detection.
//
// Body: {"confirm": true}  (required to commit; otherwise dry-run preview)
//
// Response: {ok, broken_at_seq, entries_scanned, entries_fixed, new_tip_hash, dry_run}
//
// Compliance: writes a CHAIN_REPAIRED audit entry recording who initiated.
func (h *Audit) Repair(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required for chain repair", http.StatusForbidden)
		return
	}
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = decodeJSON(w, r, &req)
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	adapter := &auditStoreAdapter{db: h.DB}
	result, err := audit.RepairChain(r.Context(), adapter, tenantID, !req.Confirm)
	if err != nil {
		jsonError(w, "repair failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// If we actually wrote changes, log a meta-audit entry recording the act.
	// Done after commit so the new entry's prev_hash chains off the rebuilt tip.
	if !result.DryRun && result.EntriesFixed > 0 {
		logAudit(r, h.DB, "CHAIN_REPAIRED",
			fmt.Sprintf("audit_log:broken_at=%d:fixed=%d", result.BrokenAtSeq, result.EntriesFixed))
	}
	jsonOK(w, map[string]any{
		"ok":              true,
		"broken_at_seq":   result.BrokenAtSeq,
		"entries_scanned": result.EntriesScanned,
		"entries_fixed":   result.EntriesFixed,
		"new_tip_hash":    result.NewTipHash,
		"dry_run":         result.DryRun,
	})
}
