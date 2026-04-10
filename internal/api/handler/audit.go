package handler

import (
	"context"
	"encoding/json"
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

	entries, total, err := h.DB.ListAuditPaged(r.Context(),
		claims.TenantID, actionFilter, limit, offset)
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
	result := audit.Verify(r.Context(), &auditStoreAdapter{db: h.DB}, claims.TenantID)
	if !result.OK {
		errMsg := ""
		if result.Err != nil {
			errMsg = result.Err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":            false,
			"checked":       result.Checked,
			"broken_at_seq": result.BrokenAtSeq,
			"error":         errMsg,
		})
		return
	}
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
