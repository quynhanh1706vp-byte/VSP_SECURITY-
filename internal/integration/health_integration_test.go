//go:build integration

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/vsp/platform/internal/testutil"
)

// TestHealthEndpoint_WithRealDB tests /health với real DB connection
func TestHealthEndpoint_WithRealDB(t *testing.T) {
	db := testutil.TestDB(t)

	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		checks := map[string]any{}
		overall := "ok"

		t0 := time.Now()
		if err := db.Pool().Ping(ctx); err != nil {
			checks["database"] = map[string]string{"status": "error", "error": err.Error()}
			overall = "error"
		} else {
			checks["database"] = map[string]string{
				"status":  "ok",
				"latency": time.Since(t0).String(),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if overall == "error" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status":  overall,
			"checks":  checks,
			"version": "test",
		})
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
	checks, _ := result["checks"].(map[string]any)
	if _, ok := checks["database"]; !ok {
		t.Error("expected database check in response")
	}
	t.Logf("Health check passed: %+v", result)
}

// TestMigrationVersion_IsLatest verifies migrations ran successfully
func TestMigrationVersion_IsLatest(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db := testutil.TestDB(t)

	var version int
	err := db.Pool().QueryRow(t.Context(),
		`SELECT MAX(version_id) FROM goose_db_version WHERE is_applied=true`,
	).Scan(&version)
	if err != nil {
		t.Fatalf("query migration version: %v", err)
	}
	if version < 5 {
		t.Errorf("expected migration version >= 5, got %d", version)
	}
	t.Logf("Migration version: %d", version)
}
