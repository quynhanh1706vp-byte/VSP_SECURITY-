// Package testutil cung cấp helpers cho integration tests.
// Chỉ compile khi có build tag "integration".
package testutil

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/store"
)

// TestDB tạo DB connection cho integration tests.
// Đọc từ env TEST_DATABASE_URL, skip nếu không có.
func TestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect với pgx pool
	db, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestServer tạo httptest.Server với router đã setup.
func TestServer(t *testing.T, r chi.Router) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// MustEnv lấy env var, fatal nếu không có.
func MustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set", key)
	}
	return v
}

// CleanupTenant xóa test data sau khi test xong.
func CleanupTenant(t *testing.T, db *store.DB, tenantID string) {
	t.Helper()
	ctx := context.Background()
	// Xóa theo thứ tự FK — bao gồm tất cả siem tables
	tables := []string{
		"remediation_comments",
		"remediations",
		"playbook_runs",
		"playbooks",
		"incidents",
		"correlation_rules",
		"log_sources",
		"siem_webhooks",
		"drift_events",
		"scan_schedules",
		"findings",
		"runs",
		"audit_log",
		"api_keys",
		"users",
	}
	for _, table := range tables {
		db.Pool().Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1", tenantID) //nolint:errcheck
	}
	db.Pool().Exec(ctx, "DELETE FROM tenants WHERE id=$1", tenantID) //nolint:errcheck
}
