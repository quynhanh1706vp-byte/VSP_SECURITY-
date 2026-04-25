package sso

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

// CreateProvider inserts a new SSO provider configuration.
func CreateProvider(ctx context.Context, db *sql.DB, p Provider) (int64, error) {
	if p.Type != "oidc" && p.Type != "saml" {
		return 0, fmt.Errorf("type must be oidc or saml")
	}
	if p.IssuerURL == "" || p.ClientID == "" {
		return 0, fmt.Errorf("issuer_url and client_id required")
	}
	if p.Scopes == "" {
		p.Scopes = "openid email profile"
	}
	if p.DefaultRole == "" {
		p.DefaultRole = "analyst"
	}

	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO sso_providers
		  (tenant_id, name, type, issuer_url, client_id, client_secret,
		   redirect_uri, scopes, enabled, allowed_domains, default_role)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id
	`, p.TenantID, p.Name, p.Type, p.IssuerURL, p.ClientID, p.ClientSecret,
		p.RedirectURI, p.Scopes, p.Enabled, pq.Array(p.AllowedDomains), p.DefaultRole).Scan(&id)
	return id, err
}

// ListProviders returns all SSO providers for a tenant.
func ListProviders(ctx context.Context, db *sql.DB, tenantID string) ([]Provider, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, '' AS client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE tenant_id = $1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
			&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
			pq.Array(&p.AllowedDomains), &p.DefaultRole); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProvider fetches a single provider including its secret.
func GetProvider(ctx context.Context, db *sql.DB, id int64) (*Provider, error) {
	var p Provider
	err := db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE id = $1
	`, id).Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
		&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
		pq.Array(&p.AllowedDomains), &p.DefaultRole)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetProviderByName looks up a provider by tenant + name (used at login).
func GetProviderByName(ctx context.Context, db *sql.DB, tenantID, name string) (*Provider, error) {
	var p Provider
	err := db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE tenant_id = $1 AND name = $2 AND enabled = true
	`, tenantID, name).Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
		&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
		pq.Array(&p.AllowedDomains), &p.DefaultRole)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProvider modifies an existing provider (partial update via NULL omit).
func UpdateProvider(ctx context.Context, db *sql.DB, p Provider) error {
	res, err := db.ExecContext(ctx, `
		UPDATE sso_providers
		SET name = $1, issuer_url = $2, client_id = $3,
		    client_secret = CASE WHEN $4 = '' THEN client_secret ELSE $4 END,
		    redirect_uri = $5, scopes = $6, enabled = $7,
		    allowed_domains = $8, default_role = $9, updated_at = now(),
		    discovery_json = NULL, discovery_at = NULL
		WHERE id = $10 AND tenant_id = $11
	`, p.Name, p.IssuerURL, p.ClientID, p.ClientSecret, p.RedirectURI,
		p.Scopes, p.Enabled, pq.Array(p.AllowedDomains), p.DefaultRole, p.ID, p.TenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteProvider removes a provider.
func DeleteProvider(ctx context.Context, db *sql.DB, id int64, tenantID string) error {
	res, err := db.ExecContext(ctx, `
		DELETE FROM sso_providers WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
