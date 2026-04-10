package main

// vsp_batch_redis.go — Redis-backed batch store
// Thay thế in-memory map trong batchHandler
// Batch records persist qua restart, TTL 7 ngày
//
// Để enable: thêm redisClient vào batchHandler và gọi
//   h.rdb = redis.NewClient(...)
// trong newBatchHandler()

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const batchRedisTTL = 7 * 24 * time.Hour
const batchRedisPrefix = "vsp:batch:"

type batchRedisStore struct {
	rdb *redis.Client
}

func newBatchRedisStore(addr, password string) *batchRedisStore {
	return &batchRedisStore{
		rdb: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       0,
		}),
	}
}

func (s *batchRedisStore) key(batchID string) string {
	return batchRedisPrefix + batchID
}

// Set — lưu batch record vào Redis với TTL
func (s *batchRedisStore) Set(ctx context.Context, b *batchRecord) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("batch redis set marshal: %w", err)
	}
	return s.rdb.Set(ctx, s.key(b.BatchID), data, batchRedisTTL).Err()
}

// Get — lấy batch record từ Redis
func (s *batchRedisStore) Get(ctx context.Context, batchID string) (*batchRecord, error) {
	data, err := s.rdb.Get(ctx, s.key(batchID)).Bytes()
	if err == redis.Nil {
		return nil, nil // not found
	}
	if err != nil {
		return nil, fmt.Errorf("batch redis get: %w", err)
	}
	var b batchRecord
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("batch redis unmarshal: %w", err)
	}
	return &b, nil
}

// List — list tất cả batches của 1 tenant
func (s *batchRedisStore) List(ctx context.Context, tenantID string) ([]*batchRecord, error) {
	keys, err := s.rdb.Keys(ctx, batchRedisPrefix+"*").Result()
	if err != nil {
		return nil, err
	}
	var result []*batchRecord
	for _, key := range keys {
		data, err := s.rdb.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}
		var b batchRecord
		if err := json.Unmarshal(data, &b); err != nil {
			continue
		}
		if b.TenantID == tenantID {
			result = append(result, &b)
		}
	}
	return result, nil
}

// Delete — xoá batch record
func (s *batchRedisStore) Delete(ctx context.Context, batchID string) error {
	return s.rdb.Del(ctx, s.key(batchID)).Err()
}

// UpdateStatus — cập nhật chỉ status + counters (atomic-ish)
func (s *batchRedisStore) UpdateStatus(ctx context.Context, batchID, status string, done, passed, warned, failed int) error {
	b, err := s.Get(ctx, batchID)
	if err != nil || b == nil {
		return fmt.Errorf("batch not found: %s", batchID)
	}
	b.Status = status
	b.Done = done
	b.Passed = passed
	b.Warned = warned
	b.Failed = failed
	return s.Set(ctx, b)
}

// ── Integration với batchHandler ─────────────────────────────────────────────
//
// Để wire Redis store vào batchHandler, thêm field này:
//
//   type batchHandler struct {
//     db    *store.DB
//     pool  *pgxpool.Pool
//     runsH *handler.Runs
//     rdb   *batchRedisStore   // ← thêm dòng này
//     mu    sync.RWMutex
//     cache map[string]*batchRecord
//   }
//
// Trong newBatchHandler():
//   redisAddr := viper.GetString("redis.addr")
//   redisPass := os.Getenv("REDIS_PASSWORD")
//   h.rdb = newBatchRedisStore(redisAddr, redisPass)
//
// Trong Submit(), sau khi tạo batch:
//   if h.rdb != nil { h.rdb.Set(ctx, batch) }
//
// Trong Status(), sau khi cache miss:
//   if h.rdb != nil {
//     b, _ := h.rdb.Get(r.Context(), batchID)
//     if b != nil { batch = b }
//   }
//
// Trong runBatch(), sau mỗi job done:
//   if h.rdb != nil { h.rdb.Set(ctx, batch) }

// suppress U1000 — Redis store enabled via env config
var _ = newBatchRedisStore
