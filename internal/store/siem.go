package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type SIEMWebhook struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Label      string    `json:"label"`
	Type       string    `json:"type"`
	URL        string    `json:"url"`
	SecretHash string    `json:"-"`
	MinSev     string    `json:"min_sev"`
	Active     bool      `json:"active"`
	LastFired  *time.Time `json:"last_fired"`
	FireCount  int       `json:"fire_count"`
	CreatedAt  time.Time `json:"created_at"`
}

func (db *DB) ListSIEMWebhooks(ctx context.Context, tenantID string) ([]SIEMWebhook, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, label, type, url, secret_hash,
		        min_sev, active, last_fired, fire_count, created_at
		 FROM siem_webhooks WHERE tenant_id=$1 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hooks []SIEMWebhook
	for rows.Next() {
		var h SIEMWebhook
		rows.Scan(&h.ID, &h.TenantID, &h.Label, &h.Type, &h.URL, &h.SecretHash,
			&h.MinSev, &h.Active, &h.LastFired, &h.FireCount, &h.CreatedAt)
		hooks = append(hooks, h)
	}
	return hooks, nil
}

func (db *DB) CreateSIEMWebhook(ctx context.Context, h SIEMWebhook) (*SIEMWebhook, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO siem_webhooks (tenant_id,label,type,url,secret_hash,min_sev)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 RETURNING id,tenant_id,label,type,url,secret_hash,min_sev,active,last_fired,fire_count,created_at`,
		h.TenantID, h.Label, h.Type, h.URL, h.SecretHash, h.MinSev)
	var out SIEMWebhook
	err := row.Scan(&out.ID, &out.TenantID, &out.Label, &out.Type, &out.URL, &out.SecretHash,
		&out.MinSev, &out.Active, &out.LastFired, &out.FireCount, &out.CreatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, fmt.Errorf("create siem webhook: %w", err) }
	return &out, nil
}

func (db *DB) DeleteSIEMWebhook(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM siem_webhooks WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (db *DB) TouchSIEMWebhook(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE siem_webhooks SET last_fired=NOW(), fire_count=fire_count+1 WHERE id=$1`, id)
	return err
}
