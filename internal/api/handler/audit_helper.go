package handler

import (
	"context"
	"net/http"
	"time"

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
	// Capture values before goroutine — r may be gone by the time goroutine runs
	tenantID := claims.TenantID
	userID := claims.UserID
	remoteIP := r.RemoteAddr
	go func() { //#nosec G118 -- intentional: audit goroutine outlives request
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) //nolint:gosec // G118: intentional — request ctx cancelled after response
		defer cancel()
		prevHash, err := db.GetLastAuditHash(ctx, tenantID)
		if err != nil {
			log.Warn().Err(err).Msg("audit: get last hash failed")
			return
		}
		e := audit.Entry{
			TenantID: tenantID,
			UserID:   userID,
			Action:   action,
			Resource: resource,
			IP:       remoteIP,
			PrevHash: prevHash,
		}
		e.StoredHash = audit.Hash(e)
		_, _, err2 := db.InsertAudit(ctx, store.AuditWriteParams{
			TenantID: tenantID, UserID: &userID,
			Action: action, Resource: resource,
			IP: remoteIP, PrevHash: prevHash,
		})
		if err2 != nil {
			log.Warn().Err(err2).Str("action", action).Msg("audit: insert failed")
		}
	}()
}
