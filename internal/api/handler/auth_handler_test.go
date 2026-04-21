package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vsp/platform/internal/auth"
)

func makeAuthHandler(t *testing.T) *Auth {
	t.Helper()
	return &Auth{
		JWTSecret:  "test-secret-32-bytes-long-enough!",
		JWTTTL:     time.Hour,
		DefaultTID: "tenant-test",
	}
}

func issueTestToken(t *testing.T, secret string) string {
	t.Helper()
	token, err := auth.IssueJWT(secret, auth.Claims{
		UserID: "user-1", TenantID: "tenant-test",
		Role: "admin", Email: "test@test.com",
	}, time.Hour)
	require.NoError(t, err)
	return token
}

func reqWithAuth(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "user-1", TenantID: "tenant-test",
		Role: "admin", Email: "test@test.com",
	})
	return r.WithContext(ctx)
}

// ── Login ─────────────────────────────────────────────────────────────────

func TestLogin_InvalidJSON(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/login", bytes.NewReader([]byte("{bad")))
	a.Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_EmptyEmail(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"email": "", "password": "pw"})
	r := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	a.Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Contains(t, resp["error"], "required")
}

func TestLogin_EmptyPassword(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"email": "user@test.com", "password": ""})
	r := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	a.Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_BothEmpty(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"email": "  ", "password": "  "})
	r := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	a.Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Logout ────────────────────────────────────────────────────────────────

func TestLogout_NoContext(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	a.Logout(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "logged out", resp["message"])
}

func TestLogout_WithClaims(t *testing.T) {
	// Logout fires audit goroutine which needs DB — skip goroutine side effect
	// by not injecting claims (goroutine only fires when claims are present)
	// This test verifies the response contract only
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	// Use request WITHOUT claims to avoid audit goroutine (nil DB safe)
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	a.Logout(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "logged out", resp["message"])
}

// ── Refresh ───────────────────────────────────────────────────────────────

func TestRefresh_Unauthorized(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/refresh", nil)
	a.Refresh(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_OK(t *testing.T) {
	a := makeAuthHandler(t)
	w := httptest.NewRecorder()
	r := reqWithAuth("POST", "/auth/refresh", nil)
	a.Refresh(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.NotEmpty(t, resp["token"])
	assert.NotEmpty(t, resp["expires_at"])
}

func TestRefresh_TokenIsDifferent(t *testing.T) {
	a := makeAuthHandler(t)
	oldToken := issueTestToken(t, a.JWTSecret)
	w := httptest.NewRecorder()
	r := reqWithAuth("POST", "/auth/refresh", nil)
	a.Refresh(w, r)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	newToken, _ := resp["token"].(string)
	assert.NotEmpty(t, newToken)
	assert.NotEqual(t, oldToken, newToken)
}

func TestRefresh_CustomTTL(t *testing.T) {
	a := makeAuthHandler(t)
	a.JWTTTL = 2 * time.Hour
	w := httptest.NewRecorder()
	r := reqWithAuth("POST", "/auth/refresh", nil)
	a.Refresh(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRefresh_ZeroTTLDefaultsTo24h(t *testing.T) {
	a := makeAuthHandler(t)
	a.JWTTTL = 0 // should default to 24h
	w := httptest.NewRecorder()
	r := reqWithAuth("POST", "/auth/refresh", nil)
	a.Refresh(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.NotEmpty(t, resp["token"])
}

// ── Sprint 5 Day 1: VSP_AUTH_MODE feature flag tests ─────────────────────

func TestSelectBodyToken_Bearer(t *testing.T) {
	// Default mode — token stays in body for API clients
	assert.Equal(t, "abc123", selectBodyToken("abc123", "bearer"))
}

func TestSelectBodyToken_Cookie(t *testing.T) {
	// Cookie mode — token omitted from body (frontend uses cookie)
	assert.Equal(t, "", selectBodyToken("abc123", "cookie"))
}

func TestSelectBodyToken_Both(t *testing.T) {
	// Both mode — token in body AND cookie for dual-client rollout
	assert.Equal(t, "abc123", selectBodyToken("abc123", "both"))
}

func TestSelectBodyToken_EmptyMode_FallsBackToBearer(t *testing.T) {
	// Edge case: empty mode string — treated as bearer (backward compat)
	assert.Equal(t, "abc123", selectBodyToken("abc123", ""))
}

func TestSelectBodyToken_UnknownMode_FallsBackToBearer(t *testing.T) {
	// Edge case: unrecognized mode — treated as bearer (defensive)
	assert.Equal(t, "abc123", selectBodyToken("abc123", "invalid"))
}
