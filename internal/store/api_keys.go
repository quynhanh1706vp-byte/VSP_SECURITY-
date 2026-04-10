package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type APIKey struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Label     string     `json:"label"`
	Prefix    string     `json:"prefix"`
	Hash      string     `json:"-"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used"`
	UseCount  int        `json:"use_count"`
	CreatedAt time.Time  `json:"created_at"`
}

func (db *DB) CreateAPIKey(ctx context.Context, tenantID, label, prefix, hash, role string, expiresAt *time.Time) (*APIKey, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO api_keys (tenant_id, label, prefix, hash, role, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 RETURNING id, tenant_id, label, prefix, hash, role, expires_at, last_used, use_count, created_at`,
		tenantID, label, prefix, hash, role, expiresAt)
	return scanAPIKey(row)
}

func (db *DB) GetAPIKeyByPrefix(ctx context.Context, tenantID, prefix string) (*APIKey, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, label, prefix, hash, role, expires_at, last_used, use_count, created_at
		 FROM api_keys WHERE prefix = $1 AND tenant_id = $2 LIMIT 1`,
		prefix, tenantID)
	return scanAPIKey(row)
}

func (db *DB) ListAPIKeys(ctx context.Context, tenantID string) ([]APIKey, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, label, prefix, hash, role, expires_at, last_used, use_count, created_at
		 FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		if k == nil { continue }
		keys = append(keys, *k)
	}
	return keys, nil
}

func (db *DB) DeleteAPIKey(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (db *DB) TouchAPIKey(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE api_keys SET last_used = NOW(), use_count = use_count + 1 WHERE id = $1`, id)
	return err
}

func scanAPIKey(row scanner) (*APIKey, error) {
	var k APIKey
	err := row.Scan(&k.ID, &k.TenantID, &k.Label, &k.Prefix, &k.Hash,
		&k.Role, &k.ExpiresAt, &k.LastUsed, &k.UseCount, &k.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan api key: %w", err)
	}
	return &k, nil
}
