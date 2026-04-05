package handler

import (
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// logAudit ghi audit log cho một action.
// Best-effort — không fail request nếu audit fail.
func logAudit(r *http.Request, db *store.DB, action, resource string) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return
	}
	go func() {
		prevHash, err := db.GetLastAuditHash(r.Context(), claims.TenantID)
		if err != nil {
			log.Warn().Err(err).Msg("audit: get last hash failed")
			return
		}
		e := audit.Entry{
			TenantID: claims.TenantID,
			UserID:   claims.UserID,
			Action:   action,
			Resource: resource,
			IP:       r.RemoteAddr,
			PrevHash: prevHash,
		}
		e.StoredHash = audit.Hash(e)
		_, _, err2 := db.InsertAudit(r.Context(), store.AuditWriteParams{
			TenantID: claims.TenantID, UserID: &claims.UserID,
			Action: action, Resource: resource,
			IP: r.RemoteAddr, PrevHash: prevHash,
		})
		if err2 != nil {
			log.Warn().Err(err2).Str("action", action).Msg("audit: insert failed")
		}
	}()
}
