package main

// tenant_resolve.go — small helpers used by the RLS middleware wiring in
// main.go. Mirrors the implementation in internal/api/handler/audit_helper.go
// (looksLikeUUID + resolveTenantUUID) but lives in package main so the
// middleware closure doesn't need to import the handler package.

import (
	"context"

	"github.com/vsp/platform/internal/store"
)

func looksLikeUUIDLocal(s string) bool {
	if len(s) != 36 {
		return false
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

func resolveTenantUUIDLocal(ctx context.Context, db *store.DB, raw string) string {
	if raw == "" {
		return ""
	}
	if looksLikeUUIDLocal(raw) {
		return raw
	}
	var id string
	_ = db.Pool().QueryRow(ctx,
		`SELECT id::text FROM tenants WHERE slug = $1 LIMIT 1`, raw).Scan(&id)
	return id
}
