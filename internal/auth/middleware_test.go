package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddleware_NoAuth(t *testing.T) {
	mw := Middleware("secret", nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_ValidJWT(t *testing.T) {
	secret := "test-secret-32-bytes-long-enough!"
	claims := Claims{UserID: "u1", TenantID: "t1", Role: "admin", Email: "a@b.com"}
	token, err := IssueJWT(secret, claims, time.Hour)
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}

	mw := Middleware(secret, nil)
	var gotClaims Claims
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if gotClaims.UserID != "u1" {
		t.Errorf("UserID: got %q want %q", gotClaims.UserID, "u1")
	}
	if gotClaims.Role != "admin" {
		t.Errorf("Role: got %q want %q", gotClaims.Role, "admin")
	}
}

func TestMiddleware_InvalidJWT(t *testing.T) {
	mw := Middleware("secret", nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_ExpiredJWT(t *testing.T) {
	secret := "test-secret-32-bytes-long-enough!"
	claims := Claims{UserID: "u1", TenantID: "t1", Role: "analyst"}
	token, _ := IssueJWT(secret, claims, -time.Second)

	mw := Middleware(secret, nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", w.Code)
	}
}

func TestRequireRole_Allowed(t *testing.T) {
	mw := RequireRole("admin", "analyst")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := injectClaims(context.Background(), Claims{
		UserID: "u1", TenantID: "t1", Role: "admin",
	})
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireRole_Forbidden(t *testing.T) {
	mw := RequireRole("admin")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := injectClaims(context.Background(), Claims{
		UserID: "u1", TenantID: "t1", Role: "analyst",
	})
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestInjectAndFromContext(t *testing.T) {
	claims := Claims{UserID: "u1", TenantID: "t1", Role: "dev", Email: "dev@test.com"}
	ctx := injectClaims(context.Background(), claims)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext returned false")
	}
	if got.UserID != claims.UserID {
		t.Errorf("UserID: got %q want %q", got.UserID, claims.UserID)
	}
	if got.Email != claims.Email {
		t.Errorf("Email: got %q want %q", got.Email, claims.Email)
	}
}

func TestIssueJWT_UniqueJTI(t *testing.T) {
	secret := "test-secret-32-bytes-long-enough!"
	claims := Claims{UserID: "u1", TenantID: "t1"}

	token1, _ := IssueJWT(secret, claims, time.Hour)
	token2, _ := IssueJWT(secret, claims, time.Hour)

	if token1 == token2 {
		t.Error("expected unique tokens (different JTI), got identical tokens")
	}
}
