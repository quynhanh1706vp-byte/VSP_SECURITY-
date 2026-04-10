// Package storetest cung cấp mock implementations của store interfaces.
// Dùng trong unit test — không cần PostgreSQL thật.
//
// Cách dùng:
//
//	func TestDeliver(t *testing.T) {
//	    db := &storetest.WebhookMock{
//	        Hooks: []store.SIEMWebhook{{ID: "h1", Active: true, MinSev: "LOW"}},
//	    }
//	    siem.Deliver(ctx, db, event)
//	    assert.Equal(t, 1, db.TouchCalls)
//	}
package storetest

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/jackc/pgx/v5"
	"time"

	"github.com/vsp/platform/internal/store"
)

// ── WebhookMock ───────────────────────────────────────────────────────────────

type WebhookMock struct {
	mu         sync.Mutex
	Hooks      []store.SIEMWebhook
	TouchCalls int
	TouchErr   error
	CreateErr  error
	DeleteErr  error
}

func (m *WebhookMock) ListSIEMWebhooks(_ context.Context, tenantID string) ([]store.SIEMWebhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.SIEMWebhook
	for _, h := range m.Hooks {
		if h.TenantID == tenantID || tenantID == "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func (m *WebhookMock) CreateSIEMWebhook(_ context.Context, h store.SIEMWebhook) (store.SIEMWebhook, error) {
	if m.CreateErr != nil {
		return store.SIEMWebhook{}, m.CreateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h.ID = "mock-" + h.Label
	h.CreatedAt = time.Now()
	m.Hooks = append(m.Hooks, h)
	return h, nil
}

func (m *WebhookMock) DeleteSIEMWebhook(_ context.Context, _, id string) error {
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, h := range m.Hooks {
		if h.ID == id {
			m.Hooks = append(m.Hooks[:i], m.Hooks[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *WebhookMock) TouchSIEMWebhook(_ context.Context, id string) error {
	if m.TouchErr != nil {
		return m.TouchErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TouchCalls++
	for i, h := range m.Hooks {
		if h.ID == id {
			now := time.Now()
			m.Hooks[i].LastFired = &now
			m.Hooks[i].FireCount++
		}
	}
	return nil
}

// ── AuditMock ─────────────────────────────────────────────────────────────────

type AuditMock struct {
	mu      sync.Mutex
	Entries []store.AuditEntry
	NextSeq int64
}

func (m *AuditMock) InsertAudit(_ context.Context, p store.AuditWriteParams) (int64, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NextSeq++
	e := store.AuditEntry{
		Seq:       m.NextSeq,
		TenantID:  p.TenantID,
		UserID:    p.UserID,
		Action:    p.Action,
		Resource:  p.Resource,
		IP:        p.IP,
		Payload:   p.Payload,
		PrevHash:  p.PrevHash,
		Hash:      "mock-hash",
		CreatedAt: time.Now(),
	}
	m.Entries = append(m.Entries, e)
	return e.Seq, e.Hash, nil
}

func (m *AuditMock) GetLastAuditHash(_ context.Context, tenantID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.Entries) - 1; i >= 0; i-- {
		if m.Entries[i].TenantID == tenantID {
			return m.Entries[i].Hash, nil
		}
	}
	return "", nil
}

func (m *AuditMock) ListAuditByTenant(_ context.Context, tenantID string) ([]store.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AuditEntry
	for _, e := range m.Entries {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *AuditMock) ListAuditPaged(_ context.Context, tenantID, action string, limit, offset int) ([]store.AuditEntry, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []store.AuditEntry
	for _, e := range m.Entries {
		if e.TenantID == tenantID && (action == "" || e.Action == action) {
			filtered = append(filtered, e)
		}
	}
	total := int64(len(filtered))
	if offset >= len(filtered) {
		return nil, total, nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], total, nil
}

// ── CorrelatorMock ────────────────────────────────────────────────────────────

type CorrelatorMock struct {
	mu        sync.Mutex
	Rules     []store.CorrelationRule
	Incidents []store.Incident
	CreateErr error
}

func (m *CorrelatorMock) ListCorrelationRules(_ context.Context, tenantID string) ([]store.CorrelationRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CorrelationRule
	for _, r := range m.Rules {
		if r.TenantID == tenantID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *CorrelatorMock) CreateIncident(_ context.Context, inc store.Incident) (string, error) {
	if m.CreateErr != nil {
		return "", m.CreateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inc.ID = "mock-inc-" + time.Now().Format("150405.000")
	inc.CreatedAt = time.Now()
	m.Incidents = append(m.Incidents, inc)
	return inc.ID, nil
}

func (m *CorrelatorMock) GetIncident(_ context.Context, _, id string) (*store.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.Incidents {
		if m.Incidents[i].ID == id {
			return &m.Incidents[i], nil
		}
	}
	return nil, nil
}

func (m *CorrelatorMock) UpdateIncidentStatus(_ context.Context, _, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.Incidents {
		if m.Incidents[i].ID == id {
			m.Incidents[i].Status = status
		}
	}
	return nil
}

func (m *CorrelatorMock) ListIncidents(_ context.Context, tenantID, status, sev string, limit int) ([]store.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Incident
	for _, inc := range m.Incidents {
		if inc.TenantID != tenantID {
			continue
		}
		if status != "" && inc.Status != status {
			continue
		}
		if sev != "" && inc.Severity != sev {
			continue
		}
		out = append(out, inc)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// ── FindingMock ───────────────────────────────────────────────────────────────

type FindingMock struct {
	mu       sync.Mutex
	Findings []store.Finding
	BatchErr error
}

func (m *FindingMock) InsertFindingsBatch(_ context.Context, findings []store.Finding) error {
	if m.BatchErr != nil {
		return m.BatchErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Findings = append(m.Findings, findings...)
	return nil
}

func (m *FindingMock) ListFindings(_ context.Context, tenantID string, f store.FindingFilter) ([]store.Finding, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Finding
	for _, fi := range m.Findings {
		if fi.TenantID != tenantID {
			continue
		}
		if f.RunID != "" && fi.RunID != f.RunID {
			continue
		}
		if f.Severity != "" && fi.Severity != f.Severity {
			continue
		}
		out = append(out, fi)
	}
	return out, int64(len(out)), nil
}

func (m *FindingMock) FindingsSummary(_ context.Context, tenantID, runID string) (*store.FindingSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &store.FindingSummary{}
	for _, f := range m.Findings {
		if f.TenantID != tenantID {
			continue
		}
		if runID != "" && f.RunID != runID {
			continue
		}
		s.Total++
		switch f.Severity {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		}
	}
	return s, nil
}

func (m *CorrelatorMock) UpdateCorrelationRuleHits(_ context.Context, id string) error {
	return nil
}

func (m *CorrelatorMock) CountRecentIncidents(_ context.Context, ruleID string, windowMin int) (int, error) {
	return 0, nil
}

func (m *CorrelatorMock) ListAllEnabledRules(_ context.Context) (pgx.Rows, error) {
	return nil, nil
}

func (m *CorrelatorMock) FindEnabledPlaybooks(_ context.Context, tenantID, trigger, sev string) ([]store.Playbook, error) {
	return nil, nil
}

func (m *CorrelatorMock) CreatePlaybookRun(_ context.Context, playbookID, tenantID, trigger string, ctx2 json.RawMessage) (string, error) {
	return "mock-run-id", nil
}

func (m *CorrelatorMock) CountEventsInWindow(_ context.Context, tenantID string, since time.Time, extraWhere string, args []any) (int, []string, error) {
	return 0, nil, nil
}

func (m *CorrelatorMock) QueryEventCount(_ context.Context, q string, args []any) (int, []string, error) {
	return 0, nil, nil
}

// RemediationMock không có trong mocks vì chưa cần — thêm nếu cần test pipeline
// BulkUpsertRemediations stub cho FindingMock (nếu embed RemediationStore)

// compile-time interface checks — fail fast nếu mock thiếu method
var (
	_ store.WebhookStore    = (*WebhookMock)(nil)
	_ store.AuditStore      = (*AuditMock)(nil)
	_ store.CorrelatorStore = (*CorrelatorMock)(nil)
	_ store.FindingStore    = (*FindingMock)(nil)
)

// Dummy json import để tránh unused import khi FindingMock dùng json.RawMessage
var _ = json.RawMessage(nil)
