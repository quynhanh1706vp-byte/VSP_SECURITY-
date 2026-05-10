package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vsp/platform/internal/auth"
)

func injectClaims(r *http.Request, tenantID, role string) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, auth.CtxUserID, "u1")
	ctx = context.WithValue(ctx, auth.CtxTenantID, tenantID)
	ctx = context.WithValue(ctx, auth.CtxRole, role)
	return r.WithContext(ctx)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	})
}

func TestRequirePro_AllowsPro(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "pro"}}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequirePro_AllowsEnterprise(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "enterprise"}}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequirePro_DeniesStarter(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "starter"}}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"required_plan":"pro"`) {
		t.Errorf("body missing required_plan: %s", body)
	}
	if !strings.Contains(body, `"current_plan":"starter"`) {
		t.Errorf("body missing current_plan: %s", body)
	}
}

func TestRequirePro_DeniesFree(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "free"}}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", rec.Code)
	}
}

func TestRequirePro_NoAuthContext(t *testing.T) {
	resolver := &StaticPlanResolver{}
	h := RequirePro(resolver)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no auth, got %d", rec.Code)
	}
}

func TestRequirePro_UnknownTenantTreatedAsStarter(t *testing.T) {
	// Resolver returns "" (no row) → middleware treats as starter → deny.
	resolver := &StaticPlanResolver{Default: ""}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "ghost", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for unknown tenant, got %d", rec.Code)
	}
}

func TestRequireTier_HierarchyEnterpriseAllowedForProGate(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "enterprise"}}
	h := RequireTier(resolver, PlanPro)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("enterprise should pass pro gate, got %d", rec.Code)
	}
}

func TestRequireTier_ProRejectedForEnterpriseGate(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "pro"}}
	h := RequireTier(resolver, PlanEnterprise)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("pro should not satisfy enterprise gate, got %d", rec.Code)
	}
}

func TestRequirePro_ResolverErrorReturns503(t *testing.T) {
	resolver := &errorResolver{err: errors.New("db down")}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "db down") {
		t.Errorf("error body should not leak DB error: %s", rec.Body.String())
	}
}

func TestRequirePro_PlanCaseInsensitive(t *testing.T) {
	resolver := &StaticPlanResolver{Plans: map[string]string{"t1": "  PRO  "}}
	h := RequirePro(resolver)(okHandler())

	req := injectClaims(httptest.NewRequest(http.MethodGet, "/x", nil), "t1", "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("'  PRO  ' should be normalized to pro, got %d", rec.Code)
	}
}

// errorResolver is a test PlanResolver that always errors.
type errorResolver struct{ err error }

func (e *errorResolver) Resolve(_ context.Context, _ string) (string, error) {
	return "", e.err
}

// ── Resolver-cache behaviour ─────────────────────────────────────────────────

// countingResolver wraps a static map but counts how many times Resolve is called.
type countingResolver struct {
	plans map[string]string
	calls int32
	mu    sync.Mutex
}

func (c *countingResolver) Resolve(_ context.Context, tenantID string) (string, error) {
	atomic.AddInt32(&c.calls, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.plans[tenantID], nil
}

func TestStaticPlanResolverDefault(t *testing.T) {
	r := &StaticPlanResolver{Default: "pro"}
	got, _ := r.Resolve(context.Background(), "anything")
	if got != "pro" {
		t.Fatalf("expected default 'pro', got %q", got)
	}
}

// Compile-time check: ensure DBPlanResolver constructor returns non-nil even
// without a real pool — exercises ttl defaulting.
func TestNewDBPlanResolver_DefaultTTL(t *testing.T) {
	r := NewDBPlanResolver(nil, 0)
	if r == nil || r.ttl != 5*time.Minute {
		t.Fatalf("expected default 5m ttl, got %v", r)
	}
}
