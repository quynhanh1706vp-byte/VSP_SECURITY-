package store

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/rs/zerolog/log"
)

// ── Password change ───────────────────────────────────────────────────────

func (db *DB) UpdatePassword(ctx context.Context, userID, newHash string) error {
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx,
		`INSERT INTO password_history(user_id, pw_hash) SELECT id, pw_hash FROM users WHERE id=$1`,
		userID)
	if err != nil {
		return fmt.Errorf("save password history: %w", err)
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM password_history WHERE user_id=$1 AND id NOT IN (
			SELECT id FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT 5
		)`, userID)
	if err != nil {
		return fmt.Errorf("trim password history: %w", err)
	}

	_, err = tx.Exec(ctx, `UPDATE users SET pw_hash=$1 WHERE id=$2`, newHash, userID)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return tx.Commit(ctx)
}

func (db *DB) IsPasswordReused(ctx context.Context, userID, newPassword string) (bool, error) {
	rows, err := db.Pool().Query(ctx,
		`SELECT pw_hash FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT 5`,
		userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil { log.Warn().Err(err).Caller().Msg("ignored error") }
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// ── Refresh token rotation ────────────────────────────────────────────────

func (db *DB) CreateRefreshToken(ctx context.Context, userID, tenantID, hash string, expiresAt time.Time) error {
	_, err := db.Pool().Exec(ctx, `
		INSERT INTO refresh_tokens(user_id, tenant_id, token_hash, family, expires_at)
		VALUES($1, $2, $3, gen_random_uuid(), $4)`,
		userID, tenantID, hash, expiresAt)
	return err
}

func (db *DB) RevokeRefreshFamily(ctx context.Context, family string) error {
	_, err := db.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET rotated=true WHERE family=$1::uuid`, family)
	return err
}

func (db *DB) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	_, err := db.Pool().Exec(ctx,
		`UPDATE refresh_tokens SET rotated=true WHERE user_id=$1`, userID)
	return err
}

// ── Webhook helpers ───────────────────────────────────────────────────────

func (db *DB) RecordWebhookFire(ctx context.Context, webhookID string, _ bool) error {
	_, err := db.Pool().Exec(ctx,
		`UPDATE siem_webhooks SET last_fired=NOW(), fire_count=fire_count+1 WHERE id=$1`,
		webhookID)
	return err
}
