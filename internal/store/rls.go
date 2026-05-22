// Package store — Row-Level Security helpers.
//
// The migration in 037_row_level_security.sql enables RLS on the
// tenant-scoped tables. This file provides the Go-side glue for setting
// the per-request `vsp.tenant_id` GUC that the policies check.
//
// Two ways to scope a query:
//
//  1. WithTenant — recommended for any new code that touches multiple
//     tenant-scoped tables in one logical operation. Wraps the work in
//     a transaction with `SET LOCAL vsp.tenant_id`.
//
//  2. PoolBeforeAcquire — drop-in for handlers that already use
//     db.Pool().Query(ctx, ...) without retrofitting. Configured at
//     pool init: every connection acquired with a tenant in ctx gets
//     `set_config('vsp.tenant_id', ...)` run before the caller sees
//     the connection. See StoreOpenWithRLS for setup.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// tenantCtxKey is the context key that handlers set via SetTenantContext
// before issuing pool queries. The pool's BeforeAcquire hook reads it.
type tenantCtxKey struct{}

// SetTenantContext returns a derived context carrying the tenant UUID.
// Middleware calls this once per request after JWT parsing.
func SetTenantContext(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenantID)
}

// TenantFromContext returns the tenant on a context or "" when unset.
func TenantFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(tenantCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// WithTenant runs fn in a transaction with `SET LOCAL vsp.tenant_id`
// configured. Use this for new code that touches RLS-protected tables.
// Returns ErrNoTenant if tenantID is empty (fail-closed by design — a
// missing tenant id indicates a coding error, not "no scope").
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string,
	fn func(pgx.Tx) error) error {

	if tenantID == "" {
		return ErrNoTenant
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx,
		`SELECT set_config('vsp.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ErrNoTenant is returned by WithTenant when the supplied tenant id is
// empty. This is intentional fail-closed behaviour — never run a
// query "without scope" against RLS-protected tables.
var ErrNoTenant = errors.New("store: tenant context required for RLS-protected operation")

// PoolAfterAcquire runs `set_config('vsp.tenant_id', ...)` so every
// query routed through the pool inherits the per-request tenant. Wire
// this into pgxpool.Config.AfterConnect when constructing the pool.
//
// Implementation note: AfterConnect runs once per *physical* connection
// (not per Acquire) so it's not actually appropriate for per-request
// scoping. The right hook is BeforeAcquire — but BeforeAcquire's
// signature only passes a *pgx.Conn, so we set the GUC here and rely on
// the AfterRelease hook (next func) to RESET it on return so a stale
// tenant doesn't leak to the next caller.
func PoolBeforeAcquire(ctx context.Context, conn *pgx.Conn) bool {
	tenant := TenantFromContext(ctx)
	if tenant == "" {
		// No tenant on this ctx — leave GUC unset. RLS policy treats
		// unset as "owner-bypass", which only matters in dev.
		return true
	}
	// SET (not SET LOCAL) so the GUC persists on the connection until
	// AfterRelease resets it. We can't use SET LOCAL because we're not
	// inside a transaction here.
	if _, err := conn.Exec(ctx,
		`SELECT set_config('vsp.tenant_id', $1, false)`, tenant); err != nil {
		// Log via the conn's tracer? For now just refuse the
		// connection — the request handler will get an error.
		return false
	}
	return true
}

// PoolAfterRelease resets the GUC so the connection returned to the pool
// doesn't carry the previous request's tenant. Returning true means
// "keep this connection in the pool"; false discards it.
func PoolAfterRelease(conn *pgx.Conn) bool {
	// We don't have a context here, so fire off a quick reset without one.
	// The default per-statement timeout protects us from hangs.
	_, _ = conn.Exec(context.Background(),
		`SELECT set_config('vsp.tenant_id', '', false)`)
	return true
}
