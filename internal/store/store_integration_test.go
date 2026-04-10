//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vsp/platform/internal/store"
	"github.com/vsp/platform/internal/testutil"
)

var ctx = context.Background()

func setupTenant(t *testing.T, db *store.DB) string {
	t.Helper()
	var id string
	err := db.Pool().QueryRow(ctx,
		`INSERT INTO tenants(slug,name,plan) VALUES($1,$2,'enterprise') RETURNING id`,
		"test-"+t.Name(), "Test Tenant",
	).Scan(&id)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() { testutil.CleanupTenant(t, db, id) })
	return id
}

// ── InsertFindingsBatch ───────────────────────────────────────────────────────

func TestInsertFindingsBatch_Empty(t *testing.T) {
	db := testutil.NewPGContainer(t)
	if err := db.InsertFindingsBatch(ctx, nil); err != nil {
		t.Errorf("empty batch should not error: %v", err)
	}
}

func TestInsertFindingsBatch_And_List(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)

	run, err := db.CreateRun(ctx, "rid-1", tid, "full", "default", "git", "", 3)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	findings := []store.Finding{
		{RunID: run.ID, TenantID: tid, Tool: "semgrep", Severity: "HIGH", RuleID: "r1", Message: "sql injection", Path: "main.go", LineNum: 10},
		{RunID: run.ID, TenantID: tid, Tool: "semgrep", Severity: "CRITICAL", RuleID: "r2", Message: "rce", Path: "api.go", LineNum: 5},
		{RunID: run.ID, TenantID: tid, Tool: "trivy", Severity: "LOW", RuleID: "r3", Message: "outdated dep", Path: "go.sum", LineNum: 1},
	}

	if err := db.InsertFindingsBatch(ctx, findings); err != nil {
		t.Fatalf("InsertFindingsBatch: %v", err)
	}

	all, count, err := db.ListFindings(ctx, tid, store.FindingFilter{})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if count != 3 {
		t.Errorf("want count=3, got %d", count)
	}
	if len(all) != 3 {
		t.Errorf("want 3 findings, got %d", len(all))
	}
}

func TestInsertFindingsBatch_SeverityFilter(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)
	run, _ := db.CreateRun(ctx, "rid-2", tid, "full", "default", "git", "", 2)

	db.InsertFindingsBatch(ctx, []store.Finding{
		{RunID: run.ID, TenantID: tid, Tool: "semgrep", Severity: "HIGH", RuleID: "r1", Message: "x", Path: "a.go"},
		{RunID: run.ID, TenantID: tid, Tool: "semgrep", Severity: "LOW", RuleID: "r2", Message: "y", Path: "b.go"},
	})

	results, count, err := db.ListFindings(ctx, tid, store.FindingFilter{Severity: "HIGH"})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if count != 1 || len(results) != 1 {
		t.Errorf("want 1 HIGH finding, got count=%d len=%d", count, len(results))
	}
	if results[0].Severity != "HIGH" {
		t.Errorf("wrong severity: %s", results[0].Severity)
	}
}

func TestFindingsSummary(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)
	run, _ := db.CreateRun(ctx, "rid-3", tid, "full", "default", "git", "", 3)

	db.InsertFindingsBatch(ctx, []store.Finding{
		{RunID: run.ID, TenantID: tid, Tool: "t", Severity: "CRITICAL", RuleID: "r1", Message: "x", Path: "a.go"},
		{RunID: run.ID, TenantID: tid, Tool: "t", Severity: "CRITICAL", RuleID: "r2", Message: "x", Path: "b.go"},
		{RunID: run.ID, TenantID: tid, Tool: "t", Severity: "HIGH", RuleID: "r3", Message: "x", Path: "c.go"},
	})

	s, err := db.FindingsSummary(ctx, tid, run.ID)
	if err != nil {
		t.Fatalf("FindingsSummary: %v", err)
	}
	if s.Critical != 2 {
		t.Errorf("want critical=2, got %d", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("want high=1, got %d", s.High)
	}
	if s.Total != 3 {
		t.Errorf("want total=3, got %d", s.Total)
	}
}

// ── InsertAudit + hash chain ──────────────────────────────────────────────────

func TestInsertAudit_HashChain(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)

	// Entry đầu tiên — prevHash rỗng
	prevHash, _ := db.GetLastAuditHash(ctx, tid)
	seq1, hash1, err := db.InsertAudit(ctx, store.AuditWriteParams{
		TenantID: tid, Action: "LOGIN", Resource: "/auth",
		IP: "1.2.3.4", Payload: json.RawMessage(`{}`), PrevHash: prevHash,
	})
	if err != nil {
		t.Fatalf("InsertAudit 1: %v", err)
	}
	if seq1 == 0 {
		t.Error("want seq > 0")
	}
	if hash1 == "" {
		t.Error("want hash")
	}

	// Entry thứ 2 — prevHash = hash1
	seq2, hash2, err := db.InsertAudit(ctx, store.AuditWriteParams{
		TenantID: tid, Action: "SCAN_TRIGGER", Resource: "/runs",
		IP: "1.2.3.4", Payload: json.RawMessage(`{}`), PrevHash: hash1,
	})
	if err != nil {
		t.Fatalf("InsertAudit 2: %v", err)
	}
	if seq2 <= seq1 {
		t.Errorf("want seq2 > seq1, got %d <= %d", seq2, seq1)
	}
	if hash2 == hash1 {
		t.Error("want different hashes")
	}

	// GetLastAuditHash trả về hash mới nhất
	last, err := db.GetLastAuditHash(ctx, tid)
	if err != nil {
		t.Fatalf("GetLastAuditHash: %v", err)
	}
	if last != hash2 {
		t.Errorf("want last=%s, got %s", hash2, last)
	}
}

func TestInsertAudit_TamperDetection(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)

	_, hash1, _ := db.InsertAudit(ctx, store.AuditWriteParams{
		TenantID: tid, Action: "LOGIN", Resource: "/auth", IP: "x",
	})
	_, _, _ = db.InsertAudit(ctx, store.AuditWriteParams{
		TenantID: tid, Action: "DELETE", Resource: "/data", IP: "x",
		PrevHash: hash1,
	})

	// Tamper — sửa hash của entry đầu
	db.Pool().Exec(ctx,
		`UPDATE audit_log SET hash='tampered' WHERE seq=(SELECT seq FROM audit_log WHERE tenant_id=$1 ORDER BY seq LIMIT 1)`, tid)

	entries, err := db.ListAuditByTenant(ctx, tid)
	if err != nil {
		t.Fatalf("ListAuditByTenant: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	// Entry 0 đã bị tamper thành 'tampered'
	// Entry 1 có PrevHash = hash1 gốc — không khớp với entries[0].Hash='tampered'
	// => chain broken, tamper detected
	if entries[0].Hash != "tampered" {
		t.Errorf("want entries[0].Hash='tampered', got %s", entries[0].Hash)
	}
	if entries[1].PrevHash == entries[0].Hash {
		t.Errorf("want chain broken: prev_hash=%s should not match tampered hash=%s",
			entries[1].PrevHash, entries[0].Hash)
	}
}

// ── ListAuditPaged ────────────────────────────────────────────────────────────

func TestListAuditPaged(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)

	for i := 0; i < 7; i++ {
		db.InsertAudit(ctx, store.AuditWriteParams{
			TenantID: tid, Action: "OP", Resource: "/x", IP: "1.1.1.1",
		})
	}

	page, total, err := db.ListAuditPaged(ctx, tid, "", 3, 0)
	if err != nil {
		t.Fatalf("ListAuditPaged: %v", err)
	}
	if total != 7 {
		t.Errorf("want total=7, got %d", total)
	}
	if len(page) != 3 {
		t.Errorf("want page size=3, got %d", len(page))
	}
}

// ── Remediation ───────────────────────────────────────────────────────────────

func TestUpsertRemediation(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)
	run, _ := db.CreateRun(ctx, "rid-r", tid, "full", "default", "git", "", 1)
	db.InsertFindingsBatch(ctx, []store.Finding{
		{RunID: run.ID, TenantID: tid, Tool: "t", Severity: "HIGH", RuleID: "r1", Message: "x", Path: "a.go"},
	})
	findings, _, _ := db.ListFindings(ctx, tid, store.FindingFilter{})
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	fid := findings[0].ID

	r, err := db.UpsertRemediation(ctx, store.Remediation{
		FindingID: fid, TenantID: tid,
		Status: store.RemOpen, Priority: "P2",
	})
	if err != nil {
		t.Fatalf("UpsertRemediation: %v", err)
	}
	if r.ID == "" {
		t.Error("want ID")
	}

	// Upsert lần 2 — đổi status
	r2, err := db.UpsertRemediation(ctx, store.Remediation{
		FindingID: fid, TenantID: tid,
		Status: store.RemResolved, Priority: "P2",
	})
	if err != nil {
		t.Fatalf("UpsertRemediation update: %v", err)
	}
	if r2.Status != store.RemResolved {
		t.Errorf("want resolved, got %s", r2.Status)
	}
	if r2.ResolvedAt == nil {
		t.Error("want ResolvedAt set when status=resolved")
	}
}

// ── Password reuse ────────────────────────────────────────────────────────────

func TestIsPasswordReused(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)

	user, err := db.CreateUser(ctx, tid, "test@example.com", "hash1", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Lần đầu chưa có history
	reused, err := db.IsPasswordReused(ctx, user.ID, "newpassword")
	if err != nil {
		t.Fatalf("IsPasswordReused: %v", err)
	}
	if reused {
		t.Error("want not reused on empty history")
	}
}

// ── API Keys ──────────────────────────────────────────────────────────────────

func TestAPIKey_CreateAndTouch(t *testing.T) {
	db := testutil.NewPGContainer(t)
	tid := setupTenant(t, db)
	exp := time.Now().Add(24 * time.Hour)

	key, err := db.CreateAPIKey(ctx, tid, "ci-key", "vsp_abc", "hashxyz", "scanner", &exp)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key.ID == "" {
		t.Error("want ID")
	}

	if err := db.TouchAPIKey(ctx, key.ID); err != nil {
		t.Fatalf("TouchAPIKey: %v", err)
	}

	keys, err := db.ListAPIKeys(ctx, tid)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	if keys[0].UseCount != 1 {
		t.Errorf("want use_count=1, got %d", keys[0].UseCount)
	}
}
