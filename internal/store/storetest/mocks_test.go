package storetest_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vsp/platform/internal/store"
	"github.com/vsp/platform/internal/store/storetest"
)

var ctx = context.Background()

// ── WebhookMock tests ─────────────────────────────────────────────────────────

func TestWebhookMock_ListEmpty(t *testing.T) {
	m := &storetest.WebhookMock{}
	hooks, err := m.ListSIEMWebhooks(ctx, "tenant-1")
	if err != nil { t.Fatal(err) }
	if len(hooks) != 0 { t.Errorf("want 0, got %d", len(hooks)) }
}

func TestWebhookMock_CreateAndList(t *testing.T) {
	m := &storetest.WebhookMock{}
	h := store.SIEMWebhook{TenantID: "t1", Label: "slack", MinSev: "HIGH", Active: true}
	created, err := m.CreateSIEMWebhook(ctx, h)
	if err != nil { t.Fatal(err) }
	if created.ID == "" { t.Error("expected ID") }

	hooks, _ := m.ListSIEMWebhooks(ctx, "t1")
	if len(hooks) != 1 { t.Fatalf("want 1, got %d", len(hooks)) }
}

func TestWebhookMock_Touch(t *testing.T) {
	m := &storetest.WebhookMock{
		Hooks: []store.SIEMWebhook{{ID: "h1", TenantID: "t1", FireCount: 0}},
	}
	if err := m.TouchSIEMWebhook(ctx, "h1"); err != nil { t.Fatal(err) }
	if m.TouchCalls != 1 { t.Errorf("want 1 touch call, got %d", m.TouchCalls) }
	if m.Hooks[0].FireCount != 1 { t.Errorf("want fire_count=1, got %d", m.Hooks[0].FireCount) }
	if m.Hooks[0].LastFired == nil { t.Error("want LastFired set") }
}

func TestWebhookMock_Delete(t *testing.T) {
	m := &storetest.WebhookMock{
		Hooks: []store.SIEMWebhook{
			{ID: "h1", TenantID: "t1"},
			{ID: "h2", TenantID: "t1"},
		},
	}
	if err := m.DeleteSIEMWebhook(ctx, "t1", "h1"); err != nil { t.Fatal(err) }
	hooks, _ := m.ListSIEMWebhooks(ctx, "t1")
	if len(hooks) != 1 { t.Errorf("want 1 after delete, got %d", len(hooks)) }
	if hooks[0].ID != "h2" { t.Error("wrong hook remaining") }
}

// ── AuditMock tests ───────────────────────────────────────────────────────────

func TestAuditMock_InsertAndList(t *testing.T) {
	m := &storetest.AuditMock{}
	p := store.AuditWriteParams{
		TenantID: "t1", Action: "login", Resource: "/auth",
		IP: "1.2.3.4", Payload: json.RawMessage(`{}`),
	}
	seq, hash, err := m.InsertAudit(ctx, p)
	if err != nil { t.Fatal(err) }
	if seq != 1 { t.Errorf("want seq=1, got %d", seq) }
	if hash == "" { t.Error("want hash") }

	entries, err := m.ListAuditByTenant(ctx, "t1")
	if err != nil { t.Fatal(err) }
	if len(entries) != 1 { t.Fatalf("want 1 entry, got %d", len(entries)) }
	if entries[0].Action != "login" { t.Errorf("wrong action: %s", entries[0].Action) }
}

func TestAuditMock_GetLastHash_Empty(t *testing.T) {
	m := &storetest.AuditMock{}
	hash, err := m.GetLastAuditHash(ctx, "t1")
	if err != nil { t.Fatal(err) }
	if hash != "" { t.Errorf("want empty hash for new tenant, got %q", hash) }
}

func TestAuditMock_Paged(t *testing.T) {
	m := &storetest.AuditMock{}
	for i := 0; i < 5; i++ {
		m.InsertAudit(ctx, store.AuditWriteParams{TenantID: "t1", Action: "op"})
	}
	page, count, err := m.ListAuditPaged(ctx, "t1", "", 2, 0)
	if err != nil { t.Fatal(err) }
	if len(page) != 2 { t.Errorf("want 2, got %d", len(page)) }
	if count != 5 { t.Errorf("want total=5, got %d", count) }
}

func TestAuditMock_ActionFilter(t *testing.T) {
	m := &storetest.AuditMock{}
	m.InsertAudit(ctx, store.AuditWriteParams{TenantID: "t1", Action: "login"})
	m.InsertAudit(ctx, store.AuditWriteParams{TenantID: "t1", Action: "delete"})

	page, count, _ := m.ListAuditPaged(ctx, "t1", "login", 10, 0)
	if len(page) != 1 { t.Errorf("want 1 filtered, got %d", len(page)) }
	if count != 1 { t.Errorf("want count=1, got %d", count) }
}

// ── CorrelatorMock tests ──────────────────────────────────────────────────────

func TestCorrelatorMock_CreateAndList(t *testing.T) {
	m := &storetest.CorrelatorMock{
		Rules: []store.CorrelationRule{
			{ID: "r1", TenantID: "t1", Name: "SSH brute", Enabled: true},
		},
	}
	rules, err := m.ListCorrelationRules(ctx, "t1")
	if err != nil { t.Fatal(err) }
	if len(rules) != 1 { t.Fatalf("want 1 rule, got %d", len(rules)) }

	id, err := m.CreateIncident(ctx, store.Incident{
		TenantID: "t1", Title: "SSH brute force detected", Severity: "HIGH",
	})
	if err != nil { t.Fatal(err) }
	if id == "" { t.Error("want incident ID") }
}

func TestCorrelatorMock_UpdateStatus(t *testing.T) {
	m := &storetest.CorrelatorMock{}
	id, _ := m.CreateIncident(ctx, store.Incident{TenantID: "t1", Severity: "HIGH"})
	if err := m.UpdateIncidentStatus(ctx, "t1", id, "resolved"); err != nil { t.Fatal(err) }

	inc, err := m.GetIncident(ctx, "t1", id)
	if err != nil { t.Fatal(err) }
	if inc.Status != "resolved" { t.Errorf("want resolved, got %s", inc.Status) }
}

// ── FindingMock tests ─────────────────────────────────────────────────────────

func TestFindingMock_BatchInsert(t *testing.T) {
	m := &storetest.FindingMock{}
	now := time.Now()
	findings := []store.Finding{
		{RunID: "r1", TenantID: "t1", Severity: "HIGH", Tool: "semgrep", CreatedAt: now},
		{RunID: "r1", TenantID: "t1", Severity: "CRITICAL", Tool: "semgrep", CreatedAt: now},
		{RunID: "r1", TenantID: "t1", Severity: "LOW", Tool: "trivy", CreatedAt: now},
	}
	if err := m.InsertFindingsBatch(ctx, findings); err != nil { t.Fatal(err) }

	all, count, _ := m.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(all) != 3 { t.Errorf("want 3, got %d", len(all)) }
	if count != 3 { t.Errorf("want count=3, got %d", count) }
}

func TestFindingMock_SeverityFilter(t *testing.T) {
	m := &storetest.FindingMock{}
	now := time.Now()
	m.InsertFindingsBatch(ctx, []store.Finding{
		{TenantID: "t1", Severity: "HIGH", CreatedAt: now},
		{TenantID: "t1", Severity: "LOW", CreatedAt: now},
	})
	results, _, _ := m.ListFindings(ctx, "t1", store.FindingFilter{Severity: "HIGH"})
	if len(results) != 1 { t.Errorf("want 1 HIGH, got %d", len(results)) }
}

func TestFindingMock_Summary(t *testing.T) {
	m := &storetest.FindingMock{}
	now := time.Now()
	m.InsertFindingsBatch(ctx, []store.Finding{
		{RunID: "r1", TenantID: "t1", Severity: "CRITICAL", CreatedAt: now},
		{RunID: "r1", TenantID: "t1", Severity: "HIGH", CreatedAt: now},
		{RunID: "r1", TenantID: "t1", Severity: "HIGH", CreatedAt: now},
	})
	s, err := m.FindingsSummary(ctx, "t1", "r1")
	if err != nil { t.Fatal(err) }
	if s.Total != 3 { t.Errorf("total: want 3, got %d", s.Total) }
	if s.Critical != 1 { t.Errorf("critical: want 1, got %d", s.Critical) }
	if s.High != 2 { t.Errorf("high: want 2, got %d", s.High) }
}
