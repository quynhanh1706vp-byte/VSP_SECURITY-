package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsp/platform/internal/auth"
)

func TestRunsTrigger_InvalidBody(t *testing.T) {
	h := &Runs{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/vsp/run", bytes.NewReader([]byte("{bad")))
	r = r.WithContext(auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "u1", TenantID: "tid", Role: "admin",
	}))
	h.Trigger(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRunsTrigger_NoSrcOrURL(t *testing.T) {
	h := &Runs{}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"mode": "SAST"})
	r := httptest.NewRequest("POST", "/vsp/run", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "u1", TenantID: "tid", Role: "admin",
	}))
	h.Trigger(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Contains(t, resp["error"], "required")
}

func TestRunsTrigger_IllegalSrcChars(t *testing.T) {
	h := &Runs{}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"mode": "SAST",
		"src":  "/path/to/repo; rm -rf /",
	})
	r := httptest.NewRequest("POST", "/vsp/run", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "u1", TenantID: "tid", Role: "admin",
	}))
	h.Trigger(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Contains(t, resp["error"], "illegal")
}

func TestRunsTrigger_SrcTooLong(t *testing.T) {
	h := &Runs{}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"mode": "SAST",
		"src":  "/path/" + string(make([]byte, 500)),
	})
	r := httptest.NewRequest("POST", "/vsp/run", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "u1", TenantID: "tid", Role: "admin",
	}))
	h.Trigger(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRunsTrigger_InvalidURLScheme(t *testing.T) {
	h := &Runs{}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"mode": "DAST",
		"url":  "ftp://evil.com",
	})
	r := httptest.NewRequest("POST", "/vsp/run", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "u1", TenantID: "tid", Role: "admin",
	}))
	h.Trigger(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Contains(t, resp["error"], "scheme must be http or https")
}

func TestRunsTrigger_ValidHTTPSURL(t *testing.T) {
	// Trigger calls DB.CreateRun after validation — requires real DB
	// Validation is covered by TestRunsTrigger_InvalidURLScheme (returns 400)
	t.Skip("requires DB — covered by integration tests")
}

func TestRunsCancel_OK(t *testing.T) {
	// Cancel calls DB.UpdateRunStatus — requires real DB
	t.Skip("requires DB — covered by integration tests")
}
