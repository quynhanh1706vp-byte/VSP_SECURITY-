package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── User model ───────────────────────────────────────────────────────────────

type User struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Email        string     `json:"email"`
	PwHash       string     `json:"-"`
	Role         string     `json:"role"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	MFASecret    string     `json:"-"`
	MFAVerified  bool       `json:"mfa_verified"`
	FailedLogins int        `json:"failed_logins,omitempty"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login"`
}

func (db *DB) GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled,
		        COALESCE(mfa_secret,''), COALESCE(mfa_verified, false),
		        COALESCE(failed_logins,0), locked_until, created_at, last_login
		 FROM users WHERE tenant_id = $1 AND email = $2 LIMIT 1`,
		tenantID, email)
	return scanUser(row)
}

func (db *DB) GetUserByID(ctx context.Context, tenantID, id string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled,
		        COALESCE(mfa_secret,''), COALESCE(mfa_verified, false),
		        COALESCE(failed_logins,0), locked_until, created_at, last_login
		 FROM users WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
		id, tenantID)
	return scanUser(row)
}

func (db *DB) CreateUser(ctx context.Context, tenantID, email, pwHash, role string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, pw_hash, role)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login`,
		tenantID, email, pwHash, role)
	return scanUser(row)
}

func (db *DB) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int64, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled,
		        COALESCE(mfa_secret,''), COALESCE(mfa_verified, false),
		        COALESCE(failed_logins,0), locked_until, created_at, last_login
		 FROM users WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, *u)
	}

	var count int64
	db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id = $1`, tenantID).Scan(&count)
	return users, count, nil
}

func (db *DB) DeleteUser(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM users WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (db *DB) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `UPDATE users SET last_login = NOW() WHERE id = $1`, id)
	return err
}


// ── MFA methods ───────────────────────────────────────────────────────────────

func (db *DB) SetMFASecret(ctx context.Context, userID, secret string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE users SET mfa_secret = $1, mfa_enabled = true WHERE id = $2`,
		secret, userID)
	return err
}

func (db *DB) VerifyMFASetup(ctx context.Context, userID string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE users SET mfa_verified = true WHERE id = $1`, userID)
	return err
}

func (db *DB) DisableMFA(ctx context.Context, tenantID, userID string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE users SET mfa_secret = NULL, mfa_enabled = false, mfa_verified = false
		 WHERE id = $1 AND tenant_id = $2`, userID, tenantID)
	return err
}

// ── Account lockout ───────────────────────────────────────────────────────────

func (db *DB) RecordFailedLogin(ctx context.Context, userID string) (int, error) {
	var count int
	err := db.pool.QueryRow(ctx,
		`UPDATE users SET failed_logins = failed_logins + 1
		 WHERE id = $1 RETURNING failed_logins`, userID).Scan(&count)
	if err != nil { return 0, err }
	// Lockout sau 5 lần fail: 15 phút
	if count >= 5 {
		db.pool.Exec(ctx,
			`UPDATE users SET locked_until = NOW() + interval '15 minutes' WHERE id = $1`,
			userID)
	}
	return count, nil
}

func (db *DB) ResetFailedLogins(ctx context.Context, userID string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, userID)
	return err
}

// scanUser works for both pgx.Row and pgx.Rows
type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.PwHash,
		&u.Role, &u.MFAEnabled, &u.MFASecret, &u.MFAVerified,
		&u.FailedLogins, &u.LockedUntil, &u.CreatedAt, &u.LastLogin)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}
