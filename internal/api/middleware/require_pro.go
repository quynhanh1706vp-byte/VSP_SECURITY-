package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vsp/platform/internal/auth"
)

// Plan tiers, ordered low → high. A tenant on tier N satisfies any RequireTier ≤ N.
const (
	PlanFree       = "free"
	PlanStarter    = "starter"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

var planRank = map[string]int{
	PlanFree:       0,
	PlanStarter:    1,
	PlanPro:        2,
	PlanEnterprise: 3,
}

// PlanResolver returns the plan tier for a given tenant. Implementations must
// be safe for concurrent use. Return "" + nil error if the tenant is unknown —
// the middleware treats unknown tenants as starter.
type PlanResolver interface {
	Resolve(ctx context.Context, tenantID string) (string, error)
}

// RequirePro is shorthand for RequireTier(PlanPro).
func RequirePro(resolver PlanResolver) func(http.Handler) http.Handler {
	return RequireTier(resolver, PlanPro)
}

// RequireTier rejects requests whose tenant plan rank is below the given tier.
// On rejection it returns 402 Payment Required with a JSON body that the
// frontend uses to show the "Upgrade to PRO" overlay. Auth must run upstream
// so that auth.FromContext yields a tenant ID.
func RequireTier(resolver PlanResolver, minTier string) func(http.Handler) http.Handler {
	required, ok := planRank[minTier]
	if !ok {
		// Caller bug: fall back to PlanPro so we fail closed rather than open.
		required = planRank[PlanPro]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.FromContext(r.Context())
			if !ok || claims.TenantID == "" {
				writeUpgradeError(w, http.StatusUnauthorized, "auth required", minTier, "")
				return
			}
			plan, err := resolver.Resolve(r.Context(), claims.TenantID)
			if err != nil {
				// Don't leak DB errors; degrade to deny.
				writeUpgradeError(w, http.StatusServiceUnavailable, "plan check unavailable", minTier, "")
				return
			}
			plan = strings.ToLower(strings.TrimSpace(plan))
			if plan == "" {
				plan = PlanStarter
			}
			if planRank[plan] < required {
				writeUpgradeError(w, http.StatusPaymentRequired, "feature requires "+minTier+" plan", minTier, plan)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeUpgradeError(w http.ResponseWriter, status int, msg, required, current string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := `{"error":"` + msg + `","required_plan":"` + required + `"`
	if current != "" {
		body += `,"current_plan":"` + current + `"`
	}
	body += `}`
	_, _ = w.Write([]byte(body))
}

// ── DB-backed resolver with TTL cache ─────────────────────────────────────────

// DBPlanResolver reads tenants.plan with a small in-memory cache so the hot
// path (every PRO request) doesn't hit Postgres. Cache is per-process; that's
// fine because the only writers (admin tenant CRUD, billing webhook) are rare
// and a few minutes of staleness is acceptable for entitlement checks.
type DBPlanResolver struct {
	pool *pgxpool.Pool
	ttl  time.Duration

	mu    sync.RWMutex
	cache map[string]planCacheEntry
}

type planCacheEntry struct {
	plan      string
	expiresAt time.Time
}

func NewDBPlanResolver(pool *pgxpool.Pool, ttl time.Duration) *DBPlanResolver {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &DBPlanResolver{
		pool:  pool,
		ttl:   ttl,
		cache: make(map[string]planCacheEntry),
	}
}

// looksLikeUUID reports whether s has the canonical 36-char UUID shape.
// Used to decide whether to query tenants.id (UUID) vs tenants.slug (text)
// — JWTs minted by the dev script set tenant_id="default" (slug), while
// production login sets it to the row's UUID.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (r *DBPlanResolver) Resolve(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		return "", nil
	}
	now := time.Now()
	r.mu.RLock()
	entry, ok := r.cache[tenantID]
	r.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.plan, nil
	}

	// Look up by id (UUID) when the value matches; otherwise treat as slug.
	// Without this branch, slug-form tokens cause a Postgres "invalid input
	// syntax for type uuid" error and the plan check returns 503.
	var (
		plan string
		err  error
	)
	if looksLikeUUID(tenantID) {
		err = r.pool.QueryRow(ctx,
			`SELECT plan FROM tenants WHERE id = $1`, tenantID).Scan(&plan)
	} else {
		err = r.pool.QueryRow(ctx,
			`SELECT plan FROM tenants WHERE slug = $1`, tenantID).Scan(&plan)
	}
	if err != nil {
		if isNoRows(err) {
			plan = ""
		} else {
			return "", err
		}
	}

	r.mu.Lock()
	r.cache[tenantID] = planCacheEntry{plan: plan, expiresAt: now.Add(r.ttl)}
	r.mu.Unlock()
	return plan, nil
}

// Invalidate drops a tenant from the cache. Call after admin updates the plan
// (CreateTenant / billing webhook) so the next request sees the new tier.
func (r *DBPlanResolver) Invalidate(tenantID string) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}

func isNoRows(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no rows")
}

// ── Static resolver for tests / dev-stub ──────────────────────────────────────

// StaticPlanResolver serves a fixed map of tenant→plan. Useful for tests and
// for the dev-stub binary which has no Postgres.
type StaticPlanResolver struct {
	Plans   map[string]string
	Default string // returned when tenant is not in the map
}

func (s *StaticPlanResolver) Resolve(_ context.Context, tenantID string) (string, error) {
	if p, ok := s.Plans[tenantID]; ok {
		return p, nil
	}
	return s.Default, nil
}
