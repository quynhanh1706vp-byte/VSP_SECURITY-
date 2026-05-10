package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ════════════════════════════════════════════════════════════════════
// Endpoint Agents — store layer.
//
// Tables (see migration 018_agents_tables.sql):
//   - agents              (id, tenant_id, hostname, os_*, api_key_hash, ...)
//   - software_packages   (id, tenant_id, agent_id, name, version, ...)
//   - inventory_reports   (id, tenant_id, agent_id, received_at, ...)
//
// API key handling:
//   - On enrollment, we generate 32 random bytes → hex-encoded plain key.
//   - We store sha256(plainKey) as api_key_hash; the plain key is shown
//     ONCE to the caller and never persisted in DB or logs.
//   - On agent requests, the agent supplies the plain key via X-Agent-Key
//     header; we sha256 it and look up the matching agent.
// ════════════════════════════════════════════════════════════════════

var ErrAgentNotFound = errors.New("agent not found")

// Agent — public-safe agent metadata.
type Agent struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Hostname   string     `json:"hostname"`
	OSFamily   string     `json:"os_family,omitempty"`
	OSVersion  string     `json:"os_version,omitempty"`
	Arch       string     `json:"arch,omitempty"`
	AssetID    *string    `json:"asset_id,omitempty"`
	APIKeyHint string     `json:"api_key_hint"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	LastIP     string     `json:"last_ip,omitempty"`
	Status     string     `json:"status"`
	Version    string     `json:"version,omitempty"`
}

// SoftwarePackage — single software inventory entry.
type SoftwarePackage struct {
	ID           int64      `json:"id"`
	AgentID      string     `json:"agent_id"`
	Name         string     `json:"name"`
	Version      string     `json:"version,omitempty"`
	PackageMgr   string     `json:"package_mgr,omitempty"`
	Architecture string     `json:"architecture,omitempty"`
	InstallDate  *time.Time `json:"install_date,omitempty"`
	ReportedAt   time.Time  `json:"reported_at"`
	CVEMatched   []string   `json:"cve_matched,omitempty"`
}

// EnrollAgentResult — returned from EnrollAgent so the caller can show the
// raw API key exactly once.
type EnrollAgentResult struct {
	Agent     *Agent
	RawAPIKey string // SHOW ONCE — never persisted
}

// generateAPIKey — 32 random bytes → 64 hex chars. Deterministic prefix
// "vspa_" makes server-side detection of agent keys easy in logs.
func generateAPIKey() (raw, hash, hint string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("rand: %w", err)
	}
	raw = "vspa_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	if len(raw) >= 4 {
		hint = raw[len(raw)-4:]
	}
	return
}

// HashAPIKey — public helper for middleware to lookup by hash.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// EnrollAgent — generate API key, persist agent record, return raw key once.
func (db *DB) EnrollAgent(ctx context.Context, tenantID, hostname, osFamily, osVersion, arch, version string) (*EnrollAgentResult, error) {
	if tenantID == "" || hostname == "" {
		return nil, errors.New("tenant_id and hostname required")
	}
	rawKey, keyHash, hint, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	a := &Agent{TenantID: tenantID, Hostname: hostname, OSFamily: osFamily, OSVersion: osVersion, Arch: arch, Version: version, APIKeyHint: hint, Status: "active"}

	row := db.pool.QueryRow(ctx, `
		INSERT INTO agents (tenant_id, hostname, os_family, os_version, arch, api_key_hash, api_key_hint, version, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active')
		RETURNING id, enrolled_at
	`, tenantID, hostname, osFamily, osVersion, arch, keyHash, hint, version)

	if err := row.Scan(&a.ID, &a.EnrolledAt); err != nil {
		return nil, fmt.Errorf("insert agent: %w", err)
	}
	return &EnrollAgentResult{Agent: a, RawAPIKey: rawKey}, nil
}

// GetAgentByAPIKeyHash — used by agent-key middleware on heartbeat/inventory.
func (db *DB) GetAgentByAPIKeyHash(ctx context.Context, hash string) (*Agent, error) {
	a := &Agent{}
	var lastIP *string
	row := db.pool.QueryRow(ctx, `
		SELECT id, tenant_id, hostname, COALESCE(os_family,''), COALESCE(os_version,''),
		       COALESCE(arch,''), COALESCE(api_key_hint,''), enrolled_at, last_seen_at,
		       host(last_ip)::text, status, COALESCE(version,'')
		FROM agents
		WHERE api_key_hash = $1 AND status = 'active'
	`, hash)
	if err := row.Scan(&a.ID, &a.TenantID, &a.Hostname, &a.OSFamily, &a.OSVersion,
		&a.Arch, &a.APIKeyHint, &a.EnrolledAt, &a.LastSeenAt,
		&lastIP, &a.Status, &a.Version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentNotFound
		}
		return nil, err
	}
	if lastIP != nil {
		a.LastIP = *lastIP
	}
	return a, nil
}

// GetAgentByID — tenant-scoped fetch for UI.
func (db *DB) GetAgentByID(ctx context.Context, tenantID, agentID string) (*Agent, error) {
	a := &Agent{}
	var lastIP *string
	row := db.pool.QueryRow(ctx, `
		SELECT id, tenant_id, hostname, COALESCE(os_family,''), COALESCE(os_version,''),
		       COALESCE(arch,''), COALESCE(api_key_hint,''), enrolled_at, last_seen_at,
		       host(last_ip)::text, status, COALESCE(version,'')
		FROM agents
		WHERE id = $1 AND tenant_id = $2
	`, agentID, tenantID)
	if err := row.Scan(&a.ID, &a.TenantID, &a.Hostname, &a.OSFamily, &a.OSVersion,
		&a.Arch, &a.APIKeyHint, &a.EnrolledAt, &a.LastSeenAt,
		&lastIP, &a.Status, &a.Version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentNotFound
		}
		return nil, err
	}
	if lastIP != nil {
		a.LastIP = *lastIP
	}
	return a, nil
}

// ListAgents — paginated tenant-scoped list. Newest first.
func (db *DB) ListAgents(ctx context.Context, tenantID string, limit int) ([]Agent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, tenant_id, hostname, COALESCE(os_family,''), COALESCE(os_version,''),
		       COALESCE(arch,''), COALESCE(api_key_hint,''), enrolled_at, last_seen_at,
		       host(last_ip)::text, status, COALESCE(version,'')
		FROM agents
		WHERE tenant_id = $1
		ORDER BY enrolled_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Agent
	for rows.Next() {
		var a Agent
		var lastIP *string
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Hostname, &a.OSFamily, &a.OSVersion,
			&a.Arch, &a.APIKeyHint, &a.EnrolledAt, &a.LastSeenAt,
			&lastIP, &a.Status, &a.Version); err != nil {
			return nil, err
		}
		if lastIP != nil {
			a.LastIP = *lastIP
		}
		out = append(out, a)
	}
	if out == nil {
		out = []Agent{}
	}
	return out, nil
}

// RevokeAgent — soft delete; agent's API key stops working immediately.
func (db *DB) RevokeAgent(ctx context.Context, tenantID, agentID string) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE agents SET status='revoked' WHERE id=$1 AND tenant_id=$2 AND status='active'
	`, agentID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// TouchAgent — update last_seen_at and last_ip on heartbeat.
func (db *DB) TouchAgent(ctx context.Context, agentID, ip, version string) error {
	if version == "" {
		_, err := db.pool.Exec(ctx, `
			UPDATE agents SET last_seen_at=NOW(), last_ip=$2::inet WHERE id=$1
		`, agentID, ip)
		return err
	}
	_, err := db.pool.Exec(ctx, `
		UPDATE agents SET last_seen_at=NOW(), last_ip=$2::inet, version=$3 WHERE id=$1
	`, agentID, ip, version)
	return err
}

// IngestInventory — UPSERT a batch of software packages for one agent.
// Existing (agent_id, name, version) rows are refreshed; new ones inserted.
// Also writes one row to inventory_reports for audit/billing.
func (db *DB) IngestInventory(ctx context.Context, tenantID, agentID, sourceIP, userAgent string, packages []SoftwarePackage) (int, error) {
	if len(packages) == 0 {
		return 0, nil
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort rollback on commit failure

	bytesTotal := 0
	for _, p := range packages {
		if p.Name == "" {
			continue
		}
		bytesTotal += len(p.Name) + len(p.Version) + len(p.PackageMgr) + len(p.Architecture)
		_, err := tx.Exec(ctx, `
			INSERT INTO software_packages (tenant_id, agent_id, name, version, package_mgr, architecture, install_date, reported_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
			ON CONFLICT (agent_id, name, version) DO UPDATE
			SET package_mgr   = EXCLUDED.package_mgr,
			    architecture = EXCLUDED.architecture,
			    install_date = COALESCE(EXCLUDED.install_date, software_packages.install_date),
			    reported_at  = NOW()
		`, tenantID, agentID, p.Name, p.Version, p.PackageMgr, p.Architecture, p.InstallDate)
		if err != nil {
			return 0, fmt.Errorf("upsert pkg %q: %w", p.Name, err)
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO inventory_reports (tenant_id, agent_id, package_count, bytes, source_ip, user_agent)
		VALUES ($1,$2,$3,$4, NULLIF($5,'')::inet, $6)
	`, tenantID, agentID, len(packages), bytesTotal, sourceIP, userAgent)
	if err != nil {
		return 0, fmt.Errorf("insert audit: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(packages), nil
}

// ListAgentPackages — return all packages for an agent (tenant-scoped).
func (db *DB) ListAgentPackages(ctx context.Context, tenantID, agentID string, limit int) ([]SoftwarePackage, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, agent_id, name, COALESCE(version,''), COALESCE(package_mgr,''), COALESCE(architecture,''),
		       install_date, reported_at, COALESCE(cve_matched, ARRAY[]::text[])
		FROM software_packages
		WHERE tenant_id = $1 AND agent_id = $2
		ORDER BY reported_at DESC
		LIMIT $3
	`, tenantID, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SoftwarePackage
	for rows.Next() {
		var p SoftwarePackage
		if err := rows.Scan(&p.ID, &p.AgentID, &p.Name, &p.Version, &p.PackageMgr,
			&p.Architecture, &p.InstallDate, &p.ReportedAt, &p.CVEMatched); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []SoftwarePackage{}
	}
	return out, nil
}
