// Package store — Phase B Step 2: tenant tool config CRUD.
//
// Per-tenant scanner tool enable/disable.
// Default-on opt-out model: rows absent from tenant_tool_config = enabled.
// Pipeline calls GetDisabledTools(tenantID) to filter runners.
package store

import (
	"context"
	"encoding/json"
	"time"
)

// ToolConfig represents a single per-tenant tool config row.
type ToolConfig struct {
	TenantID   string          `json:"tenant_id"`
	ToolName   string          `json:"tool_name"`
	Enabled    bool            `json:"enabled"`
	CustomArgs json.RawMessage `json:"custom_args,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
	UpdatedBy  *string         `json:"updated_by,omitempty"`
}

// GetDisabledTools returns tool names that the tenant has explicitly disabled.
// Used by pipeline.RunnersFor() to filter out runners.
// Empty result = all tools enabled (default-on).
func (db *DB) GetDisabledTools(ctx context.Context, tenantID string) ([]string, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT tool_name FROM tenant_tool_config
		 WHERE tenant_id = $1 AND enabled = false
		 LIMIT 500`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	disabled := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		disabled = append(disabled, name)
	}
	return disabled, rows.Err()
}

// ListToolConfig returns all explicit config rows for a tenant.
// Tools with no row are considered enabled by default — caller can compute
// the union with the canonical tool list (e.g. pipeline.AllToolNames()).
func (db *DB) ListToolConfig(ctx context.Context, tenantID string) ([]ToolConfig, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT tenant_id, tool_name, enabled, custom_args, updated_at, updated_by
		 FROM tenant_tool_config WHERE tenant_id = $1
		 ORDER BY tool_name ASC
		 LIMIT 500`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ToolConfig, 0)
	for rows.Next() {
		var c ToolConfig
		var updatedBy *string
		if err := rows.Scan(&c.TenantID, &c.ToolName, &c.Enabled,
			&c.CustomArgs, &c.UpdatedAt, &updatedBy); err != nil {
			return nil, err
		}
		c.UpdatedBy = updatedBy
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetToolEnabled upserts a config row for a single tool.
// userID may be empty if no user context (e.g. system override).
func (db *DB) SetToolEnabled(ctx context.Context, tenantID, toolName string, enabled bool, userID string) error {
	var updatedBy interface{}
	if userID != "" {
		updatedBy = userID
	}
	_, err := db.pool.Exec(ctx,
		`INSERT INTO tenant_tool_config (tenant_id, tool_name, enabled, updated_by, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (tenant_id, tool_name) DO UPDATE
		 SET enabled = EXCLUDED.enabled,
		     updated_by = EXCLUDED.updated_by,
		     updated_at = NOW()`,
		tenantID, toolName, enabled, updatedBy)
	return err
}

// BulkSetToolEnabled updates multiple tools in one transaction.
// Useful when user toggles many tools in Settings UI.
func (db *DB) BulkSetToolEnabled(ctx context.Context, tenantID, userID string, toolEnabled map[string]bool) error {
	if len(toolEnabled) == 0 {
		return nil
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var updatedBy interface{}
	if userID != "" {
		updatedBy = userID
	}
	for tool, enabled := range toolEnabled {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant_tool_config (tenant_id, tool_name, enabled, updated_by, updated_at)
			 VALUES ($1, $2, $3, $4, NOW())
			 ON CONFLICT (tenant_id, tool_name) DO UPDATE
			 SET enabled = EXCLUDED.enabled,
			     updated_by = EXCLUDED.updated_by,
			     updated_at = NOW()`,
			tenantID, tool, enabled, updatedBy); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ResetToolConfig deletes all tool config rows for a tenant (back to default-on).
func (db *DB) ResetToolConfig(ctx context.Context, tenantID string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM tenant_tool_config WHERE tenant_id = $1`,
		tenantID)
	return err
}
