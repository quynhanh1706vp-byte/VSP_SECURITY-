package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenBlacklist dùng Redis để revoke JWT tokens trước khi hết hạn
type TokenBlacklist struct {
	rdb *redis.Client
}

func NewTokenBlacklist(addr, password string) *TokenBlacklist {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       1, // DB 1 riêng cho blacklist, DB 0 cho asynq
	})
	return &TokenBlacklist{rdb: rdb}
}

// Revoke thêm token vào blacklist với TTL bằng thời gian còn lại của token
func (b *TokenBlacklist) Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // token đã hết hạn, không cần blacklist
	}
	key := fmt.Sprintf("vsp:blacklist:%s", tokenID)
	return b.rdb.Set(ctx, key, "1", ttl).Err()
}

// IsRevoked kiểm tra token có trong blacklist không
func (b *TokenBlacklist) IsRevoked(ctx context.Context, tokenID string) bool {
	key := fmt.Sprintf("vsp:blacklist:%s", tokenID)
	val, err := b.rdb.Get(ctx, key).Result()
	return err == nil && val == "1"
}

// RevokeAllForUser revoke tất cả tokens của một user (dùng khi đổi password)
func (b *TokenBlacklist) RevokeAllForUser(ctx context.Context, userID string, until time.Time) error {
	key := fmt.Sprintf("vsp:blacklist:user:%s", userID)
	ttl := time.Until(until)
	if ttl <= 0 {
		ttl = 25 * time.Hour // default 25h
	}
	return b.rdb.Set(ctx, key, time.Now().Unix(), ttl).Err()
}

// IsUserRevoked kiểm tra user có bị revoke all tokens không
func (b *TokenBlacklist) IsUserRevoked(ctx context.Context, userID string, issuedAt time.Time) bool {
	key := fmt.Sprintf("vsp:blacklist:user:%s", userID)
	val, err := b.rdb.Get(ctx, key).Result()
	if err != nil {
		return false
	}
	// Nếu token được issue trước thời điểm revoke → bị block
	var revokedAt int64
	fmt.Sscanf(val, "%d", &revokedAt)
	return issuedAt.Unix() < revokedAt
}
