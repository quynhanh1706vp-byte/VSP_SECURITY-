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

// looksLikeUUID returns true for strings that match the canonical 8-4-4-4-12
// UUID layout. Used to guard audit_log inserts since user_id and tenant_id
// columns are UUID-typed and dev JWTs may carry email/slug instead.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

// resolveUserUUID accepts a UUID directly or an email, returns canonical UUID
// or empty string if not found. Mirrors the pattern feature_config.go uses
// for tenant resolution (slug → UUID).
func resolveUserUUID(ctx context.Context, db *store.DB, raw string) string {
	if raw == "" || db == nil {
		return ""
	}
	if looksLikeUUID(raw) {
		return raw
	}
	var id string
	_ = db.Pool().QueryRow(ctx,
		`SELECT id::text FROM users WHERE email = $1 LIMIT 1`, raw).Scan(&id)
	return id
}

// resolveTenantUUID accepts a UUID or slug, returns canonical UUID.
func resolveTenantUUID(ctx context.Context, db *store.DB, raw string) string {
	if raw == "" || db == nil {
		return ""
	}
	if looksLikeUUID(raw) {
		return raw
	}
	var id string
	_ = db.Pool().QueryRow(ctx,
		`SELECT id::text FROM tenants WHERE slug = $1 LIMIT 1`, raw).Scan(&id)
	return id
}

// logAudit ghi audit log cho một action.
// Best-effort — không fail request nếu audit fail.
func logAudit(r *http.Request, db *store.DB, action, resource string) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return
	}
	// Capture values before goroutine — r may be gone by the time goroutine runs
	rawTenant := claims.TenantID
	rawUser := claims.UserID
	remoteIP := r.RemoteAddr
	go func() { //#nosec G118 -- intentional: audit goroutine outlives request
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) //nolint:gosec // G118: intentional — request ctx cancelled after response
		defer cancel()
		// Both columns are UUID-typed. Dev JWTs (mint_jwt_local.sh) embed the
		// tenant slug + user email instead of UUIDs; resolve before insert,
		// otherwise SQLSTATE 22P02 fires and the audit row is lost.
		tenantID := resolveTenantUUID(ctx, db, rawTenant)
		if tenantID == "" {
			log.Warn().Str("raw", rawTenant).Msg("audit: tenant resolve failed")
			return
		}
		userID := resolveUserUUID(ctx, db, rawUser)
		var userIDPtr *string
		if userID != "" {
			userIDPtr = &userID
		}
		prevHash, err := db.GetLastAuditHash(ctx, tenantID)
		if err != nil {
			log.Warn().Err(err).Msg("audit: get last hash failed")
			return
		}
		uid := ""
		if userIDPtr != nil {
			uid = *userIDPtr
		}
		e := audit.Entry{
			TenantID: tenantID,
			UserID:   uid,
			Action:   action,
			Resource: resource,
			IP:       remoteIP,
			PrevHash: prevHash,
		}
		e.StoredHash = audit.Hash(e)
		_, _, err2 := db.InsertAudit(ctx, store.AuditWriteParams{
			TenantID: tenantID, UserID: userIDPtr,
			Action: action, Resource: resource,
			IP: remoteIP, PrevHash: prevHash,
		})
		if err2 != nil {
			log.Warn().Err(err2).Str("action", action).Msg("audit: insert failed")
			return
		}
		// L27 2026-05-09: instrument the success path so operators see
		// audit-write rate per action in Prometheus.
		AuditInserts.WithLabelValues(action).Inc()
	}()
}
