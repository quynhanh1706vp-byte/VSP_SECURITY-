// Package middleware — data-residency enforcement.
//
// Vietnam Decree 53/2022, GDPR + Schrems II, DPDP Act 2023 — same
// shape: personal data must be processed in a declared jurisdiction
// (or in a pre-approved list of additional jurisdictions). This
// middleware compares the tenant's declared region to the gateway's
// configured region and rejects requests that would process data
// outside the legal envelope.
//
// Wiring:
//  1. Operator sets VSP_REGION at deployment (e.g. "vn-1" for
//     Vietnam-mainland deployment, "eu-1" for Frankfurt, "us-1" for
//     Virginia). Default empty = no enforcement (development).
//  2. Tenants register their primary_region + optional egress list
//     via /api/v1/residency/config (admin only).
//  3. Every authenticated request hits this middleware. Mismatch →
//     451 Unavailable For Legal Reasons + residency_violations row.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vsp/platform/internal/auth"
)

// Residency config snapshot. Tenant configs are cached for 5 min to
// keep the per-request overhead at "single map lookup" rather than a
// DB query on every API call.
type residencyCache struct {
	mu      sync.RWMutex
	entries map[string]residencyEntry
}

type residencyEntry struct {
	primary  string
	allowed  map[string]struct{}
	cachedAt time.Time
}

const residencyTTL = 5 * time.Minute

func newResidencyCache() *residencyCache {
	return &residencyCache{entries: make(map[string]residencyEntry)}
}

// Residency returns the data-residency middleware. gatewayRegion is the
// physical region this binary is deployed to (set via VSP_REGION).
// When empty the middleware short-circuits — useful in dev / single-
// region deployments where residency isn't a concern.
func Residency(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	gatewayRegion := strings.ToLower(strings.TrimSpace(os.Getenv("VSP_REGION")))
	cache := newResidencyCache()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if gatewayRegion == "" {
				next.ServeHTTP(w, r)
				return
			}
			claims, ok := auth.FromContext(r.Context())
			if !ok || claims.TenantID == "" {
				// Unauthenticated paths skip residency — they don't
				// touch tenant data yet.
				next.ServeHTTP(w, r)
				return
			}
			entry, found := cache.lookup(r.Context(), pool, claims.TenantID)
			if !found {
				// No residency declared → tenant hasn't opted in.
				// Allow but tag a header so SOC dashboards can flag
				// tenants that should be configured.
				w.Header().Set("X-VSP-Residency", "unconfigured")
				next.ServeHTTP(w, r)
				return
			}
			if !entry.allows(gatewayRegion) {
				_, _ = pool.Exec(r.Context(),
					`INSERT INTO residency_violations
					   (tenant_id, gateway_region, expected_region,
					    request_path, request_ip)
					 SELECT $1, $2, $3, $4, $5`,
					claims.TenantID, gatewayRegion, entry.primary,
					r.URL.Path, r.RemoteAddr)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-VSP-Residency", "violated")
				w.WriteHeader(http.StatusUnavailableForLegalReasons)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":           "data residency policy violation",
					"tenant_region":   entry.primary,
					"gateway_region":  gatewayRegion,
					"allowed_regions": entry.allowedList(),
					"hint":            "route to the tenant's primary region",
				})
				return
			}
			w.Header().Set("X-VSP-Residency", "ok")
			next.ServeHTTP(w, r)
		})
	}
}

func (c *residencyCache) lookup(ctx context.Context, pool *pgxpool.Pool, tenantID string) (residencyEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[tenantID]
	c.mu.RUnlock()
	if ok && time.Since(e.cachedAt) < residencyTTL {
		return e, e.primary != ""
	}
	// Refresh — single query, no JOIN.
	var primary string
	var egress []string
	err := pool.QueryRow(ctx,
		`SELECT primary_region, allow_egress_regions
		   FROM tenant_residency
		  WHERE tenant_id::text = $1
		     OR tenant_id IN (SELECT id FROM tenants WHERE slug = $1)
		  LIMIT 1`,
		tenantID).Scan(&primary, &egress)
	if err != nil {
		// Cache the negative for a short while so repeated 404s don't
		// hit the DB; treat as "not configured".
		c.mu.Lock()
		c.entries[tenantID] = residencyEntry{cachedAt: time.Now()}
		c.mu.Unlock()
		return residencyEntry{}, false
	}
	allowed := map[string]struct{}{strings.ToLower(primary): {}}
	for _, eg := range egress {
		allowed[strings.ToLower(strings.TrimSpace(eg))] = struct{}{}
	}
	entry := residencyEntry{
		primary:  strings.ToLower(primary),
		allowed:  allowed,
		cachedAt: time.Now(),
	}
	c.mu.Lock()
	c.entries[tenantID] = entry
	c.mu.Unlock()
	return entry, true
}

func (e residencyEntry) allows(region string) bool {
	if e.primary == "" {
		return true
	}
	_, ok := e.allowed[strings.ToLower(region)]
	return ok
}

func (e residencyEntry) allowedList() []string {
	out := make([]string, 0, len(e.allowed))
	for k := range e.allowed {
		out = append(out, k)
	}
	return out
}
