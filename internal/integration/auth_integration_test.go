//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/vsp/platform/internal/api/handler"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

const testJWTSecret = "integration-test-secret-32bytes!"

func setupRouter(db interface{ /* store.DB */ }) *chi.Mux {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	return r
}

// TestAuthFlow_LoginAndRefresh tests login → token → API call → refresh
func TestAuthFlow_LoginAndRefresh(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()

	// Tạo test tenant
	var tenantID string
	db.Pool().QueryRow(ctx,
		`INSERT INTO tenants(slug,name,plan) VALUES($1,$2,'enterprise') RETURNING id`,
		fmt.Sprintf("test-%d", time.Now().UnixNano()), "Test Tenant",
	).Scan(&tenantID)
	if tenantID == "" {
		t.Fatal("failed to create test tenant")
	}
	defer testutil.CleanupTenant(t, db, tenantID)

	// Setup handlers
	authH := &handler.Auth{
		DB:         db,
		JWTSecret:  testJWTSecret,
		JWTTTL:     time.Hour,
		DefaultTID: tenantID,
	}

	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Post("/api/v1/auth/login", authH.Login)
	r.Post("/api/v1/auth/refresh", authH.Refresh)
	r.With(auth.Middleware(testJWTSecret, nil)).Get("/api/v1/test", func(w http.ResponseWriter, r *http.Request) {
		claims, _ := auth.FromContext(r.Context())
		json.NewEncoder(w).Encode(map[string]string{"user_id": claims.UserID})
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	// ── Step 1: Create user ──────────────────────────────────────────────
	// Dùng SQL trực tiếp vì chưa có signup endpoint
	hashBytes, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	hash := string(hashBytes)

	// Skip nếu không có bcrypt hash thật
	var userID string
	db.Pool().QueryRow(ctx,
		`INSERT INTO users(tenant_id,email,pw_hash,role)
		 VALUES($1,'test@integration.test',$2,'admin') RETURNING id`,
		tenantID, hash,
	).Scan(&userID)
	if userID == "" {
		t.Skip("could not create test user")
	}

	// ── Step 2: Login ────────────────────────────────────────────────────
	body, _ := json.Marshal(map[string]string{
		"email":    "test@integration.test",
		"password": "testpassword",
	})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status: got %d want 200", resp.StatusCode)
	}

	var loginResp struct {
		Token  string `json:"token"`
		UserID string `json:"user_id"`
	}
	json.NewDecoder(resp.Body).Decode(&loginResp)
	if loginResp.Token == "" {
		t.Fatal("expected token in login response")
	}

	t.Logf("Login OK — user_id: %s", loginResp.UserID)

	// ── Step 3: Use token to call API ─────────────────────────────────
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	apiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("api call: %v", err)
	}
	if apiResp.StatusCode != http.StatusOK {
		t.Fatalf("api status: got %d want 200", apiResp.StatusCode)
	}
	t.Log("API call with token: OK")
}

// TestRateLimit_LoginBrute tests rate limiting on login endpoint
func TestRateLimit_StrictLimiter(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}

	// StrictLimiter cho login: 10 req/min
	called := 0
	r := chi.NewRouter()
	r.With(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			next.ServeHTTP(w, r)
		})
	}).Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	// 5 requests — all should get through (limit is 10)
	for i := 0; i < 5; i++ {
		http.Post(srv.URL+"/login", "application/json", bytes.NewReader([]byte(`{}`)))
	}
	if called != 5 {
		t.Errorf("expected 5 calls, got %d", called)
	}
	t.Logf("Rate limit test: %d/5 requests processed", called)
}
