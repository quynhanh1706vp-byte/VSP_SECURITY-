//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vsp/platform/internal/api/handler"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"github.com/vsp/platform/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

type testEnv struct {
	db       *store.DB
	srv      *httptest.Server
	token    string
	tenantID string
	userID   string
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	db := testutil.TestDB(t)
	ctx := context.Background()

	var tenantID string
	err := db.Pool().QueryRow(ctx,
		`INSERT INTO tenants(slug,name,plan) VALUES($1,$2,'enterprise') RETURNING id`,
		fmt.Sprintf("itest-%d", time.Now().UnixNano()), "Integration Test",
	).Scan(&tenantID)
	require.NoError(t, err)
	require.NotEmpty(t, tenantID)
	t.Cleanup(func() { testutil.CleanupTenant(t, db, tenantID) })

	hash, _ := bcrypt.GenerateFromPassword([]byte("Test1234!"), bcrypt.MinCost)
	var userID string
	db.Pool().QueryRow(ctx,
		`INSERT INTO users(tenant_id,email,pw_hash,role) VALUES($1,$2,$3,'admin') RETURNING id`,
		tenantID, fmt.Sprintf("user-%d@test.com", time.Now().UnixNano()), string(hash),
	).Scan(&userID)
	require.NotEmpty(t, userID)

	token, err := auth.IssueJWT(testJWTSecret, auth.Claims{
		UserID: userID, TenantID: tenantID, Role: "admin", Email: "admin@test.com",
	}, time.Hour)
	require.NoError(t, err)

	authMw := auth.Middleware(testJWTSecret, nil)
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)

	authH := &handler.Auth{DB: db, JWTSecret: testJWTSecret, JWTTTL: time.Hour, DefaultTID: tenantID}
	r.Post("/api/v1/auth/login", authH.Login)
	r.With(authMw).Post("/api/v1/auth/refresh", authH.Refresh)
	r.With(authMw).Post("/api/v1/auth/logout", authH.Logout)

	findH := &handler.Findings{DB: db}
	r.With(authMw).Get("/api/v1/vsp/findings", findH.List)
	r.With(authMw).Get("/api/v1/vsp/findings/summary", findH.Summary)

	gateH := &handler.Gate{DB: db}
	r.With(authMw).Get("/api/v1/vsp/gate/latest", gateH.Latest)
	r.With(authMw).Get("/api/v1/vsp/posture/latest", gateH.PostureLatest)
	r.With(authMw).Post("/api/v1/policy/evaluate", gateH.Evaluate)
	r.With(authMw).Get("/api/v1/policy/rules", gateH.ListRules)
	r.With(authMw).Post("/api/v1/policy/rules", gateH.CreateRule)

	exportH := &handler.Export{DB: db}
	r.With(authMw).Get("/api/v1/export/sarif/{rid}", exportH.SARIF)
	r.With(authMw).Get("/api/v1/export/csv/{rid}", exportH.CSV)
	r.With(authMw).Get("/api/v1/export/json/{rid}", exportH.JSON)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &testEnv{db: db, srv: srv, token: token, tenantID: tenantID, userID: userID}
}

func (e *testEnv) get(path string) *http.Response {
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func (e *testEnv) post(path string, body any) *http.Response {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func createRun(t *testing.T, db *store.DB, tenantID string) (rid, runID string) {
	t.Helper()
	ctx := context.Background()
	rid = fmt.Sprintf("RID_IT_%d", time.Now().UnixNano())

	q := `INSERT INTO runs(rid,tenant_id,mode,profile,src,status,tools_total,tools_done,gate,posture,total_findings,summary)
	      VALUES($1,$2,'SAST','FAST','/src','DONE',3,3,'PASS','A',1,'{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"HAS_SECRETS":false}'::jsonb)
	      RETURNING id`
	err := db.Pool().QueryRow(ctx, q, rid, tenantID).Scan(&runID)
	require.NoError(t, err)
	return
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func TestIntegration_Login_OK(t *testing.T) {
	e := setupEnv(t)
	ctx := context.Background()
	email := fmt.Sprintf("login-%d@test.com", time.Now().UnixNano())
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.MinCost)
	e.db.Pool().Exec(ctx,
		`INSERT INTO users(tenant_id,email,pw_hash,role) VALUES($1,$2,$3,'viewer')`,
		e.tenantID, email, string(hash))
	body, _ := json.Marshal(map[string]string{"email": email, "password": "Password123!"})
	resp, err := http.Post(e.srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.NotEmpty(t, result["token"])
}

func TestIntegration_Login_WrongPassword(t *testing.T) {
	e := setupEnv(t)
	ctx := context.Background()
	email := fmt.Sprintf("badpw-%d@test.com", time.Now().UnixNano())
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	e.db.Pool().Exec(ctx,
		`INSERT INTO users(tenant_id,email,pw_hash,role) VALUES($1,$2,$3,'viewer')`,
		e.tenantID, email, string(hash))
	body, _ := json.Marshal(map[string]string{"email": email, "password": "wrong"})
	resp, _ := http.Post(e.srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_Login_UnknownUser(t *testing.T) {
	e := setupEnv(t)
	body, _ := json.Marshal(map[string]string{"email": "nobody@nowhere.com", "password": "x"})
	resp, _ := http.Post(e.srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_Refresh_OK(t *testing.T) {
	e := setupEnv(t)
	resp := e.post("/api/v1/auth/refresh", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.NotEmpty(t, result["token"])
}

func TestIntegration_NoToken_Returns401(t *testing.T) {
	e := setupEnv(t)
	for _, path := range []string{
		"/api/v1/vsp/findings",
		"/api/v1/vsp/gate/latest",
		"/api/v1/policy/rules",
	} {
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		resp, _ := http.DefaultClient.Do(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "path: %s", path)
	}
}

func TestIntegration_ExpiredToken_Returns401(t *testing.T) {
	e := setupEnv(t)
	expired, _ := auth.IssueJWT(testJWTSecret, auth.Claims{
		UserID: e.userID, TenantID: e.tenantID, Role: "admin",
	}, -time.Hour)
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/vsp/findings", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	resp, _ := http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ── Findings ──────────────────────────────────────────────────────────────────

func TestIntegration_Findings_Empty(t *testing.T) {
	e := setupEnv(t)
	resp := e.get("/api/v1/vsp/findings")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, float64(0), result["total"])
}

func TestIntegration_Findings_WithData(t *testing.T) {
	e := setupEnv(t)
	_, runID := createRun(t, e.db, e.tenantID)
	ctx := context.Background()
	for i, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
		_, err := e.db.Pool().Exec(ctx,
			`INSERT INTO findings(run_id,tenant_id,tool,severity,rule_id,message,path,line_num)
			 VALUES($1,$2,'semgrep',$3,'R1','test',$4,$5)`,
			runID, e.tenantID, sev, fmt.Sprintf("/src/main%d.go", i), i+1)
		require.NoError(t, err)
	}
	resp := e.get("/api/v1/vsp/findings?limit=10")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, float64(3), result["total"])
}

func TestIntegration_Findings_SeverityFilter(t *testing.T) {
	e := setupEnv(t)
	_, runID := createRun(t, e.db, e.tenantID)
	ctx := context.Background()
	for i, sev := range []string{"CRITICAL", "HIGH", "LOW"} {
		_, err := e.db.Pool().Exec(ctx,
			`INSERT INTO findings(run_id,tenant_id,tool,severity,rule_id,message,path,line_num)
			 VALUES($1,$2,'bandit',$3,'R1','msg',$4,$5)`,
			runID, e.tenantID, sev, fmt.Sprintf("/f%d.py", i), i+1)
		require.NoError(t, err)
	}
	resp := e.get("/api/v1/vsp/findings?severity=CRITICAL")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, float64(1), result["total"])
}

func TestIntegration_FindingsSummary(t *testing.T) {
	e := setupEnv(t)
	_, runID := createRun(t, e.db, e.tenantID)
	ctx := context.Background()
	e.db.Pool().Exec(ctx,
		`INSERT INTO findings(run_id,tenant_id,tool,severity,rule_id,message,path)
		 VALUES($1,$2,'trivy','HIGH','CVE-1','vuln','/go.mod')`,
		runID, e.tenantID)
	resp := e.get(fmt.Sprintf("/api/v1/vsp/findings/summary?run_id=%s", runID))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── Gate ──────────────────────────────────────────────────────────────────────

func TestIntegration_Gate_NoRuns(t *testing.T) {
	e := setupEnv(t)
	resp := e.get("/api/v1/vsp/gate/latest")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestIntegration_Gate_WithRun(t *testing.T) {
	e := setupEnv(t)
	_, _ = createRun(t, e.db, e.tenantID)
	resp := e.get("/api/v1/vsp/gate/latest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, "PASS", result["gate"])
}

func TestIntegration_Posture_WithRun(t *testing.T) {
	e := setupEnv(t)
	createRun(t, e.db, e.tenantID)
	resp := e.get("/api/v1/vsp/posture/latest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, "A", result["grade"])
}

func TestIntegration_PolicyRules_CRUD(t *testing.T) {
	e := setupEnv(t)
	resp := e.get("/api/v1/policy/rules")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var r1 map[string]any
	json.NewDecoder(resp.Body).Decode(&r1)
	assert.Equal(t, float64(0), r1["total"])

	resp = e.post("/api/v1/policy/rules", map[string]any{
		"name": "test-rule", "min_score": 80,
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	resp = e.get("/api/v1/policy/rules")
	var r2 map[string]any
	json.NewDecoder(resp.Body).Decode(&r2)
	assert.Equal(t, float64(1), r2["total"])
}

func TestIntegration_PolicyEvaluate(t *testing.T) {
	e := setupEnv(t)
	rid, _ := createRun(t, e.db, e.tenantID)
	resp := e.post("/api/v1/policy/evaluate", map[string]string{"rid": rid})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, "PASS", result["decision"])
}

// ── Export ────────────────────────────────────────────────────────────────────

func TestIntegration_Export_SARIF(t *testing.T) {
	e := setupEnv(t)
	rid, _ := createRun(t, e.db, e.tenantID)
	resp := e.get("/api/v1/export/sarif/" + rid)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/sarif+json", resp.Header.Get("Content-Type"))
}

func TestIntegration_Export_CSV(t *testing.T) {
	e := setupEnv(t)
	rid, _ := createRun(t, e.db, e.tenantID)
	resp := e.get("/api/v1/export/csv/" + rid)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/csv", resp.Header.Get("Content-Type"))
}

func TestIntegration_Export_JSON(t *testing.T) {
	e := setupEnv(t)
	rid, _ := createRun(t, e.db, e.tenantID)
	resp := e.get("/api/v1/export/json/" + rid)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_Export_NotFound(t *testing.T) {
	e := setupEnv(t)
	resp := e.get("/api/v1/export/sarif/RID_NONEXISTENT")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
