package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/scanner"
)

func TestRunSummary_Nil(t *testing.T) {
	s := runSummary(nil)
	assert.Equal(t, scanner.Summary{}, s)
}

func TestRunSummary_InvalidJSON(t *testing.T) {
	s := runSummary(fakeRun([]byte("not-json")))
	assert.Equal(t, scanner.Summary{}, s)
}

func TestRunSummary_ValidCounts(t *testing.T) {
	run := fakeRun([]byte(`{"CRITICAL":2,"HIGH":5,"MEDIUM":10,"LOW":3,"INFO":1,"HAS_SECRETS":true}`))
	s := runSummary(run)
	assert.Equal(t, 2, s.Critical)
	assert.Equal(t, 5, s.High)
	assert.Equal(t, 10, s.Medium)
	assert.Equal(t, 3, s.Low)
	assert.Equal(t, 1, s.Info)
	assert.True(t, s.HasSecrets)
}

func TestRunSummary_ZeroCounts(t *testing.T) {
	run := fakeRun([]byte(`{}`))
	s := runSummary(run)
	assert.Equal(t, 0, s.Critical)
	assert.False(t, s.HasSecrets)
}

func TestRunSummary_FloatCounts(t *testing.T) {
	// JSON numbers unmarshal as float64
	run := fakeRun([]byte(`{"CRITICAL":1.0,"HIGH":3.0}`))
	s := runSummary(run)
	assert.Equal(t, 1, s.Critical)
	assert.Equal(t, 3, s.High)
}

// Gate handler tests with no DB (tests routing + validation only)

func TestGateEvaluate_InvalidBody(t *testing.T) {
	h := &Gate{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/policy/evaluate", bytes.NewReader([]byte("{bad")))
	r = r.WithContext(auth.InjectForTest(r.Context(), auth.Claims{
		UserID: "u1", TenantID: "tid", Role: "admin",
	}))
	h.Evaluate(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGateDeleteRule_InvalidUUID(t *testing.T) {
	// DeleteRule has defer logAudit (goroutine) which leaks with nil DB
	t.Skip("requires DB — logAudit goroutine leaks with nil DB")
}

func TestGateDeleteRule_ValidUUID(t *testing.T) {
	// DeleteRule calls logAudit via defer which requires DB
	// Full test requires integration test with real DB — skip here
	t.Skip("requires DB — covered by integration tests")
}

func TestGateCreateRule_InvalidBody(t *testing.T) {
	// CreateRule has defer logAudit which requires DB — skip
	t.Skip("requires DB — covered by integration tests")
}
