#!/usr/bin/env bash
# ================================================================
# VSP Go Platform — setup.sh
# Chay tu thu muc goc project (~/Data/GOLANG_VSP hoac tuong duong)
# Usage:  bash setup.sh
# ================================================================
set -e
ROOT="$(pwd)"
echo ">>> Tao cau truc thu muc trong: $ROOT"

mkdir -p cmd/{gateway,scanner,soc-shell}
mkdir -p internal/{api/{handler,middleware},auth,audit,tenant,pipeline,gate}
mkdir -p internal/scanner/{bandit,semgrep,grype,trivy,kics,gitleaks,codeql,nikto}
mkdir -p internal/{findings,siem,compliance,governance,report,store}
mkdir -p pkg/{sarif,oscal,hashchain}
mkdir -p migrations config docs docker

echo ">>> Ghi files..."

# ── Makefile
cat > 'Makefile' << 'VSPEOFMAKEFILE'
.PHONY: build dev generate migrate-up migrate-down test test-integration lint docker-up docker-down

build:
	go build ./cmd/gateway/...
	go build ./cmd/scanner/...
	go build ./cmd/soc-shell/...

dev:
	air -c .air.toml

generate:
	sqlc generate
	swag init -g cmd/gateway/main.go

migrate-up:
	goose -dir migrations postgres "$(DATABASE_URL)" up

migrate-down:
	goose -dir migrations postgres "$(DATABASE_URL)" down

test:
	go test ./... -v -count=1

test-integration:
	DOCKER_TEST=1 go test ./... -v -count=1 -tags=integration

lint:
	golangci-lint run ./...

docker-up:
	docker compose -f docker/compose.dev.yml up -d

docker-down:
	docker compose -f docker/compose.dev.yml down
VSPEOFMAKEFILE

# ── cmd/scanner/main.go
mkdir -p "cmd/scanner"
cat > 'cmd/scanner/main.go' << 'VSPEOFCMD_SCANNER_MAIN_GO'
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/pipeline"
)

// TaskTypeScan is the asynq task type for scan jobs.
const TaskTypeScan = "scan:run"

func main() {
	// ── Config ────────────────────────────────────────────────────────────────
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("scanner.concurrency", 4)
	viper.SetDefault("gateway.url", "http://localhost:8920")
	viper.SetDefault("log.level", "info")

	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("no config file — using defaults + env")
	}

	// ── Logger ────────────────────────────────────────────────────────────────
	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	log.Info().
		Str("redis", viper.GetString("redis.addr")).
		Int("concurrency", viper.GetInt("scanner.concurrency")).
		Msg("VSP scanner worker starting")

	// ── Asynq server ──────────────────────────────────────────────────────────
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: viper.GetString("redis.addr")},
		asynq.Config{
			Concurrency: viper.GetInt("scanner.concurrency"),
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
			// Retry with exponential backoff
			RetryDelayFunc: func(n int, e error, t *asynq.Task) time.Duration {
				return time.Duration(n*n) * 10 * time.Second
			},
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				log.Error().Err(err).Str("task", task.Type()).Msg("task failed")
			}),
		},
	)

	mux := asynq.NewServeMux()
	mux.HandleFunc(TaskTypeScan, handleScan)

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Info().Msg("shutdown signal received — draining in-flight tasks")
		srv.Shutdown()
	}()

	if err := srv.Run(mux); err != nil {
		log.Fatal().Err(err).Msg("asynq server failed")
	}
}

// ── Task Handler ──────────────────────────────────────────────────────────────

func handleScan(ctx context.Context, task *asynq.Task) error {
	var payload pipeline.JobPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	log.Info().
		Str("rid", payload.RID).
		Str("mode", string(payload.Mode)).
		Str("src", payload.Src).
		Msg("scan job started")

	exec := &pipeline.Executor{
		OnProgress: func(tool string, done, total, findings int) {
			log.Info().
				Str("rid", payload.RID).
				Str("tool", tool).
				Int("done", done).
				Int("total", total).
				Int("findings_so_far", findings).
				Msg("tool completed")
			// TODO: POST progress update to gateway at /internal/scan/progress
		},
	}

	result, err := exec.Execute(ctx, payload)
	if err != nil {
		return fmt.Errorf("execute scan %s: %w", payload.RID, err)
	}

	// Report results back to gateway
	if err := reportToGateway(ctx, payload.RID, result); err != nil {
		return fmt.Errorf("report to gateway: %w", err)
	}

	log.Info().
		Str("rid", payload.RID).
		Int("total_findings", len(result.Findings)).
		Int("critical", result.Summary.Critical).
		Int("high", result.Summary.High).
		Dur("duration", result.Duration).
		Msg("scan job completed")

	return nil
}

// reportToGateway sends the completed scan results to the gateway API.
// The gateway persists findings to PostgreSQL and updates run status.
func reportToGateway(ctx context.Context, rid string, result *pipeline.ExecuteResult) error {
	// TODO: implement HTTP POST to gateway /internal/scan/complete
	// payload: { rid, findings, summary, tool_errors, duration }
	_ = ctx
	_ = rid
	_ = result
	log.Debug().Str("rid", rid).Msg("reportToGateway: TODO implement")
	return nil
}
VSPEOFCMD_SCANNER_MAIN_GO

# ── config/config.yaml
mkdir -p "config"
cat > 'config/config.yaml' << 'VSPEOFCONFIG_CONFIG_YAML'
server:
  gateway_port: 8920
  scanner_port: 8921
  shell_port:   8922
  read_timeout:  30s
  write_timeout: 60s

database:
  url: postgres://vsp:vsp@localhost:5432/vsp_go?sslmode=disable
  max_conns: 20
  min_conns: 2

redis:
  addr: localhost:6379

auth:
  jwt_secret: "change-me-in-production"
  jwt_ttl:    24h
  api_key_ttl: 90d

scanner:
  concurrency: 4
  default_timeout_sec: 300

log:
  level: info
  format: json
VSPEOFCONFIG_CONFIG_YAML

# ── docker/compose.dev.yml
mkdir -p "docker"
cat > 'docker/compose.dev.yml' << 'VSPEOFDOCKER_COMPOSE_DEV_YML'
version: '3.9'

services:
  postgres:
    image: postgres:16-alpine
    container_name: vsp_postgres
    environment:
      POSTGRES_USER: vsp
      POSTGRES_PASSWORD: vsp
      POSTGRES_DB: vsp_go
    ports:
      - "5432:5432"
    volumes:
      - vsp_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vsp -d vsp_go"]
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    container_name: vsp_redis
    ports:
      - "6379:6379"
    command: redis-server --save "" --appendonly no
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  vsp_pgdata:
VSPEOFDOCKER_COMPOSE_DEV_YML

# ── go.mod
cat > 'go.mod' << 'VSPEOFGO_MOD'
module github.com/vsp/platform

go 1.22

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/hibiken/asynq v0.24.1
	github.com/jackc/pgx/v5 v5.6.0
	github.com/pressly/goose/v3 v3.21.1
	github.com/prometheus/client_golang v1.19.1
	github.com/rs/zerolog v1.33.0
	github.com/spf13/viper v1.19.0
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.24.0
)
VSPEOFGO_MOD

# ── internal/audit/chain.go
mkdir -p "internal/audit"
cat > 'internal/audit/chain.go' << 'VSPEOFINTERNAL_AUDIT_CHAIN_GO'
package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
)

// ── Entry ─────────────────────────────────────────────────────────────────────

// Entry represents one immutable audit log row.
// StoredHash is read from DB; all other fields are used to recompute it.
type Entry struct {
	Seq      int64
	TenantID string
	UserID   string
	Action   string
	Resource string
	IP       string
	PrevHash string
	// StoredHash is the hash written in the DB row — not used in Hash()
	StoredHash string
}

// ── Hash ──────────────────────────────────────────────────────────────────────

// Hash computes the canonical SHA-256 for an entry.
// Format: "seq|tenant_id|action|resource|prev_hash"
// This format MUST remain stable forever — changing it breaks chain verify.
func Hash(e Entry) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s",
		e.Seq, e.TenantID, e.Action, e.Resource, e.PrevHash)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// ── Store interface ───────────────────────────────────────────────────────────

// Store is implemented by the PostgreSQL store layer.
type Store interface {
	// ListAuditByTenant returns all audit entries for a tenant in ascending seq order.
	ListAuditByTenant(ctx context.Context, tenantID string) ([]Entry, error)

	// WriteAudit appends one entry and returns the assigned seq number.
	// The implementation MUST compute Hash(e) and store it in the hash column.
	WriteAudit(ctx context.Context, e Entry) (int64, error)
}

// ── Verify ────────────────────────────────────────────────────────────────────

// VerifyResult is returned by Verify.
type VerifyResult struct {
	OK          bool
	Checked     int
	BrokenAtSeq int64
	Err         error
}

// Verify walks all audit entries for a tenant and validates the hash chain.
// Returns VerifyResult with OK=true if the entire chain is intact.
func Verify(ctx context.Context, store Store, tenantID string) VerifyResult {
	entries, err := store.ListAuditByTenant(ctx, tenantID)
	if err != nil {
		return VerifyResult{Err: fmt.Errorf("audit verify: list entries: %w", err)}
	}

	for i, e := range entries {
		expected := Hash(e)
		if expected != e.StoredHash {
			return VerifyResult{
				OK:          false,
				Checked:     i,
				BrokenAtSeq: e.Seq,
				Err: fmt.Errorf("chain broken at seq %d: expected %s, got %s",
					e.Seq, expected, e.StoredHash),
			}
		}
		if i > 0 && e.PrevHash != entries[i-1].StoredHash {
			return VerifyResult{
				OK:          false,
				Checked:     i,
				BrokenAtSeq: e.Seq,
				Err: fmt.Errorf("prev_hash mismatch at seq %d", e.Seq),
			}
		}
	}

	return VerifyResult{OK: true, Checked: len(entries)}
}

// ── Write ─────────────────────────────────────────────────────────────────────

// Write appends a new audit entry, computing the hash from the previous entry's hash.
// prevHash should be the StoredHash of the most recent entry for this tenant,
// or empty string for the first entry.
func Write(ctx context.Context, store Store, e Entry, prevHash string) (int64, error) {
	e.PrevHash = prevHash
	e.StoredHash = Hash(e)
	return store.WriteAudit(ctx, e)
}
VSPEOFINTERNAL_AUDIT_CHAIN_GO

# ── internal/auth/middleware.go
mkdir -p "internal/auth"
cat > 'internal/auth/middleware.go' << 'VSPEOFINTERNAL_AUTH_MIDDLEWARE_GO'
package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// ── Context keys ──────────────────────────────────────────────────────────────

type contextKey string

const (
	CtxUserID   contextKey = "user_id"
	CtxTenantID contextKey = "tenant_id"
	CtxRole     contextKey = "role"
	CtxEmail    contextKey = "email"
)

// ── Claims ────────────────────────────────────────────────────────────────────

// Claims holds the parsed identity from JWT or API key.
type Claims struct {
	UserID   string
	TenantID string
	Role     string
	Email    string
}

func FromContext(ctx context.Context) (Claims, bool) {
	uid, ok1 := ctx.Value(CtxUserID).(string)
	tid, ok2 := ctx.Value(CtxTenantID).(string)
	role, _ := ctx.Value(CtxRole).(string)
	email, _ := ctx.Value(CtxEmail).(string)
	if !ok1 || !ok2 || uid == "" || tid == "" {
		return Claims{}, false
	}
	return Claims{UserID: uid, TenantID: tid, Role: role, Email: email}, true
}

// ── APIKeyStore interface ─────────────────────────────────────────────────────

// APIKeyStore is implemented by the store layer.
type APIKeyStore interface {
	// ValidateAPIKey checks the key, updates last_used, and returns the owner's claims.
	ValidateAPIKey(ctx context.Context, rawKey string) (Claims, error)
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Middleware returns a chi-compatible auth middleware.
// It tries X-API-Key first, then Authorization: Bearer JWT.
// On success it injects Claims into the request context.
func Middleware(jwtSecret string, keyStore APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var claims Claims
			var ok bool

			// 1. Try API Key (CI/CD integration path)
			if k := r.Header.Get("X-API-Key"); k != "" {
				c, err := keyStore.ValidateAPIKey(r.Context(), k)
				if err != nil {
					log.Warn().Str("ip", r.RemoteAddr).Err(err).Msg("invalid api key")
					http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
					return
				}
				claims, ok = c, true
			}

			// 2. Try Bearer JWT (browser/UI path)
			if !ok {
				bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if bearer != "" {
					c, err := parseJWT(bearer, jwtSecret)
					if err != nil {
						log.Warn().Str("ip", r.RemoteAddr).Err(err).Msg("invalid jwt")
						http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
						return
					}
					claims, ok = c, true
				}
			}

			if !ok {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			ctx := injectClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that enforces a minimum role level.
// Role hierarchy: admin > analyst > dev > auditor
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := FromContext(r.Context())
			if !ok || !allowed[c.Role] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── JWT helpers ───────────────────────────────────────────────────────────────

type jwtClaims struct {
	UserID   string `json:"uid"`
	TenantID string `json:"tid"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

// IssueJWT creates a signed JWT for the given user.
func IssueJWT(secret string, c Claims, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwtClaims{
		UserID:   c.UserID,
		TenantID: c.TenantID,
		Role:     c.Role,
		Email:    c.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func parseJWT(tokenStr, secret string) (Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return Claims{}, err
	}
	c, ok := token.Claims.(*jwtClaims)
	if !ok {
		return Claims{}, jwt.ErrTokenInvalidClaims
	}
	return Claims{
		UserID:   c.UserID,
		TenantID: c.TenantID,
		Role:     c.Role,
		Email:    c.Email,
	}, nil
}

func injectClaims(ctx context.Context, c Claims) context.Context {
	ctx = context.WithValue(ctx, CtxUserID, c.UserID)
	ctx = context.WithValue(ctx, CtxTenantID, c.TenantID)
	ctx = context.WithValue(ctx, CtxRole, c.Role)
	ctx = context.WithValue(ctx, CtxEmail, c.Email)
	return ctx
}
VSPEOFINTERNAL_AUTH_MIDDLEWARE_GO

# ── internal/gate/engine.go
mkdir -p "internal/gate"
cat > 'internal/gate/engine.go' << 'VSPEOFINTERNAL_GATE_ENGINE_GO'
package gate

import (
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// ── Decision ──────────────────────────────────────────────────────────────────

type Decision string

const (
	DecisionPass Decision = "PASS"
	DecisionWarn Decision = "WARN"
	DecisionFail Decision = "FAIL"
)

// ── PolicyRule ────────────────────────────────────────────────────────────────

// PolicyRule mirrors the policy_rules DB table.
type PolicyRule struct {
	ID            string
	Name          string
	RepoPattern   string
	FailOn        string // "FAIL" | "WARN" | "never"
	MinScore      int    // 0 = disabled
	MaxHigh       int    // -1 = unlimited
	BlockSecrets  bool
	BlockCritical bool
}

// DefaultRule returns a sensible production-grade default policy.
func DefaultRule() PolicyRule {
	return PolicyRule{
		FailOn:        "FAIL",
		MaxHigh:       -1,
		BlockSecrets:  true,
		BlockCritical: true,
	}
}

// ── EvalResult ────────────────────────────────────────────────────────────────

// EvalResult is the outcome of evaluating a policy against a scan summary.
type EvalResult struct {
	Decision Decision
	Reason   string
	Score    int // 0-100
	Posture  string // A | B | C | D | F
}

// ── Evaluate ──────────────────────────────────────────────────────────────────

// Evaluate applies rule against summary and returns a gate decision.
// Rules are checked in order of severity — first match wins.
func Evaluate(rule PolicyRule, s scanner.Summary) EvalResult {
	score := Score(s)

	// 1. Critical findings block immediately
	if rule.BlockCritical && s.Critical > 0 {
		return EvalResult{
			Decision: DecisionFail,
			Reason:   fmt.Sprintf("critical findings present (%d)", s.Critical),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 2. Secrets are always blocking
	if rule.BlockSecrets && s.HasSecrets {
		return EvalResult{
			Decision: DecisionFail,
			Reason:   "secrets detected in source code",
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 3. Score threshold
	if rule.MinScore > 0 && score < rule.MinScore {
		return EvalResult{
			Decision: DecisionFail,
			Reason:   fmt.Sprintf("security score %d below minimum %d", score, rule.MinScore),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 4. High count threshold
	if rule.MaxHigh >= 0 && s.High > rule.MaxHigh {
		decision := DecisionFail
		if rule.FailOn == "WARN" {
			decision = DecisionWarn
		}
		return EvalResult{
			Decision: decision,
			Reason:   fmt.Sprintf("high severity count %d exceeds maximum %d", s.High, rule.MaxHigh),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 5. Any HIGH or MEDIUM → WARN (not blocking)
	if s.High > 0 || s.Medium > 0 {
		return EvalResult{
			Decision: DecisionWarn,
			Reason:   fmt.Sprintf("findings present: %d high, %d medium", s.High, s.Medium),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	return EvalResult{
		Decision: DecisionPass,
		Reason:   "clean — no blocking findings",
		Score:    score,
		Posture:  Posture(s),
	}
}

// ── Score ─────────────────────────────────────────────────────────────────────

// Score computes a 0-100 security score from a summary.
// Formula: start at 100, deduct weighted penalty per severity bucket.
func Score(s scanner.Summary) int {
	const (
		penaltyCritical = 25
		penaltyHigh     = 10
		penaltyMedium   = 3
		penaltyLow      = 1
	)

	deduction := s.Critical*penaltyCritical +
		s.High*penaltyHigh +
		s.Medium*penaltyMedium +
		s.Low*penaltyLow

	score := 100 - deduction
	if score < 0 {
		return 0
	}
	return score
}

// ── Posture ───────────────────────────────────────────────────────────────────

// Posture returns a letter grade A–F based on the finding summary.
//
//	A = zero critical/high/medium
//	B = some medium/low but no high/critical
//	C = 1-2 high findings
//	D = 3-10 high findings OR any critical
//	F = critical present
func Posture(s scanner.Summary) string {
	switch {
	case s.Critical > 0:
		return "F"
	case s.High > 10:
		return "D"
	case s.High > 2 || s.Medium > 5:
		return "C"
	case s.High > 0 || s.Medium > 0:
		return "B"
	default:
		return "A"
	}
}
VSPEOFINTERNAL_GATE_ENGINE_GO

# ── internal/gate/engine_test.go
mkdir -p "internal/gate"
cat > 'internal/gate/engine_test.go' << 'VSPEOFINTERNAL_GATE_ENGINE_TEST_GO'
package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
)

func TestEvaluate_CleanScan(t *testing.T) {
	rule := gate.DefaultRule()
	s := scanner.Summary{}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionPass, r.Decision)
	assert.Equal(t, "A", r.Posture)
	assert.Equal(t, 100, r.Score)
}

func TestEvaluate_CriticalBlocks(t *testing.T) {
	rule := gate.DefaultRule()
	s := scanner.Summary{Critical: 1}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Equal(t, "F", r.Posture)
}

func TestEvaluate_SecretsBlock(t *testing.T) {
	rule := gate.DefaultRule()
	s := scanner.Summary{HasSecrets: true}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Contains(t, r.Reason, "secrets")
}

func TestEvaluate_HighWarn(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MaxHigh = -1 // unlimited — should only warn
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionWarn, r.Decision)
	assert.Equal(t, "B", r.Posture)
}

func TestEvaluate_MaxHighFail(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MaxHigh = 2
	rule.FailOn = "FAIL"
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
}

func TestEvaluate_MaxHighWarnMode(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MaxHigh = 2
	rule.FailOn = "WARN"
	s := scanner.Summary{High: 5}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionWarn, r.Decision)
}

func TestEvaluate_ScoreThreshold(t *testing.T) {
	rule := gate.DefaultRule()
	rule.MinScore = 80
	// 10 medium findings = -30 → score 70
	s := scanner.Summary{Medium: 10}
	r := gate.Evaluate(rule, s)
	assert.Equal(t, gate.DecisionFail, r.Decision)
	assert.Equal(t, 70, r.Score)
}

func TestPosture(t *testing.T) {
	cases := []struct {
		s       scanner.Summary
		posture string
	}{
		{scanner.Summary{}, "A"},
		{scanner.Summary{Medium: 1}, "B"},
		{scanner.Summary{High: 1}, "B"},
		{scanner.Summary{High: 3}, "C"},
		{scanner.Summary{Medium: 6}, "C"},
		{scanner.Summary{High: 11}, "D"},
		{scanner.Summary{Critical: 1}, "F"},
	}
	for _, c := range cases {
		assert.Equal(t, c.posture, gate.Posture(c.s))
	}
}

func TestScore(t *testing.T) {
	assert.Equal(t, 100, gate.Score(scanner.Summary{}))
	assert.Equal(t, 90, gate.Score(scanner.Summary{High: 1}))  // 100-10
	assert.Equal(t, 75, gate.Score(scanner.Summary{Critical: 1})) // 100-25
	assert.Equal(t, 0, gate.Score(scanner.Summary{Critical: 10})) // floored at 0
}
VSPEOFINTERNAL_GATE_ENGINE_TEST_GO

# ── internal/pipeline/pipeline.go
mkdir -p "internal/pipeline"
cat > 'internal/pipeline/pipeline.go' << 'VSPEOFINTERNAL_PIPELINE_PIPELINE_GO'
package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/scanner"
	"github.com/vsp/platform/internal/scanner/bandit"
	"github.com/vsp/platform/internal/scanner/codeql"
	"github.com/vsp/platform/internal/scanner/gitleaks"
	"github.com/vsp/platform/internal/scanner/grype"
	"github.com/vsp/platform/internal/scanner/kics"
	"github.com/vsp/platform/internal/scanner/nikto"
	"github.com/vsp/platform/internal/scanner/semgrep"
	"github.com/vsp/platform/internal/scanner/trivy"
)

// ── Status ────────────────────────────────────────────────────────────────────

type Status string

const (
	StatusQueued    Status = "QUEUED"
	StatusRunning   Status = "RUNNING"
	StatusDone      Status = "DONE"
	StatusFailed    Status = "FAILED"
	StatusCancelled Status = "CANCELLED"
)

// ── Mode / Profile ────────────────────────────────────────────────────────────

type Mode string

const (
	ModeSAST    Mode = "SAST"
	ModeDAST    Mode = "DAST"
	ModeSCA     Mode = "SCA"
	ModeSecrets Mode = "SECRETS"
	ModeIAC     Mode = "IAC"
	ModeFull    Mode = "FULL"
)

type Profile string

const (
	ProfileFast    Profile = "FAST"
	ProfileExt     Profile = "EXT"
	ProfileAggr    Profile = "AGGR"
	ProfilePremium Profile = "PREMIUM"
	ProfileFull    Profile = "FULL"
	ProfileFullSOC Profile = "FULL_SOC"
)

// ── Run ───────────────────────────────────────────────────────────────────────

// Run is the canonical representation of one scan job.
// Stored in DB table `runs` and used as the job payload.
type Run struct {
	ID        string    `json:"id"`         // UUID
	RID       string    `json:"rid"`        // human-readable: RID_VSPGO_RUN_YYYYMMDD_HHMMSS_xxxxxxxx
	TenantID  string    `json:"tenant_id"`
	Mode      Mode      `json:"mode"`
	Profile   Profile   `json:"profile"`
	Src       string    `json:"src"`
	TargetURL string    `json:"target_url"`
	Status    Status    `json:"status"`
	ToolsDone int       `json:"tools_done"`
	ToolsTotal int      `json:"tools_total"`
	CreatedAt time.Time `json:"created_at"`
	StartedAt *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// ── JobPayload ────────────────────────────────────────────────────────────────

// JobPayload is serialised into the asynq task and consumed by the worker.
type JobPayload struct {
	RunID     string            `json:"run_id"`
	RID       string            `json:"rid"`
	TenantID  string            `json:"tenant_id"`
	Mode      Mode              `json:"mode"`
	Profile   Profile           `json:"profile"`
	Src       string            `json:"src"`
	TargetURL string            `json:"target_url"`
	ExtraArgs map[string][]string `json:"extra_args,omitempty"`
}

// ── ToolSet — select runners based on mode ────────────────────────────────────

// RunnersFor returns the set of tool runners appropriate for the given mode.
// This is the single place that controls which tools run per mode.
func RunnersFor(mode Mode) []scanner.Runner {
	sast := []scanner.Runner{
		bandit.New(),
		semgrep.New(),
		codeql.New(),
	}
	sca := []scanner.Runner{
		grype.New(),
		trivy.New(),
	}
	secrets := []scanner.Runner{
		gitleaks.New(),
	}
	iac := []scanner.Runner{
		kics.New(),
	}
	dast := []scanner.Runner{
		nikto.New(),
	}

	switch mode {
	case ModeSAST:
		return sast
	case ModeSCA:
		return sca
	case ModeSecrets:
		return secrets
	case ModeIAC:
		return iac
	case ModeDAST:
		return dast
	case ModeFull:
		all := make([]scanner.Runner, 0, 9)
		all = append(all, sast...)
		all = append(all, sca...)
		all = append(all, secrets...)
		all = append(all, iac...)
		all = append(all, dast...)
		return all
	default:
		// Default: SAST + SCA + Secrets (safe for most repos)
		r := make([]scanner.Runner, 0, 6)
		r = append(r, sast...)
		r = append(r, sca...)
		r = append(r, secrets...)
		return r
	}
}

// ── Executor ─────────────────────────────────────────────────────────────────

// Executor runs a pipeline job: selects tools, executes them, returns results.
// The caller is responsible for persisting Run state and Findings to the DB.
type Executor struct {
	// OnProgress is called after each tool completes (for real-time updates).
	// May be nil.
	OnProgress func(toolName string, done int, total int, findings int)
}

// ExecuteResult is returned by Execute.
type ExecuteResult struct {
	Findings   []scanner.Finding
	ToolErrors map[string]error
	Summary    scanner.Summary
	Duration   time.Duration
}

// Execute runs all tools for the given payload and returns the merged result.
// It does NOT write to the database — that is the caller's responsibility.
func (e *Executor) Execute(ctx context.Context, payload JobPayload) (*ExecuteResult, error) {
	runners := RunnersFor(payload.Mode)
	if len(runners) == 0 {
		return nil, fmt.Errorf("no runners available for mode %s", payload.Mode)
	}

	opts := scanner.RunOpts{
		Src:       payload.Src,
		URL:       payload.TargetURL,
		Mode:      string(payload.Mode),
		ExtraArgs: payload.ExtraArgs,
	}

	log.Info().
		Str("rid", payload.RID).
		Str("mode", string(payload.Mode)).
		Int("tools", len(runners)).
		Msg("pipeline starting")

	start := time.Now()

	// Run all tools concurrently; OnProgress fires as results come in.
	allFindings, details := e.runWithProgress(ctx, runners, opts)

	toolErrors := make(map[string]error)
	for _, d := range details {
		if d.Err != nil {
			toolErrors[d.Tool] = d.Err
			log.Warn().
				Str("rid", payload.RID).
				Str("tool", d.Tool).
				Err(d.Err).
				Msg("tool failed")
		} else {
			log.Info().
				Str("rid", payload.RID).
				Str("tool", d.Tool).
				Int("findings", len(d.Findings)).
				Dur("duration", d.Duration).
				Msg("tool done")
		}
	}

	return &ExecuteResult{
		Findings:   allFindings,
		ToolErrors: toolErrors,
		Summary:    scanner.Summarise(allFindings),
		Duration:   time.Since(start),
	}, nil
}

// runWithProgress wraps scanner.RunAll with per-tool progress callbacks.
func (e *Executor) runWithProgress(ctx context.Context, runners []scanner.Runner, opts scanner.RunOpts) ([]scanner.Finding, []scanner.RunResult) {
	if e.OnProgress == nil {
		return scanner.RunAll(ctx, runners, opts)
	}

	results := make(chan scanner.RunResult, len(runners))
	for _, r := range runners {
		r := r
		go func() {
			tctx, cancel := context.WithTimeout(ctx, opts.TimeoutOrDefault())
			defer cancel()
			start := time.Now()
			findings, err := r.Run(tctx, opts)
			results <- scanner.RunResult{
				Tool:     r.Name(),
				Findings: findings,
				Err:      err,
				Duration: time.Since(start),
			}
		}()
	}

	var allFindings []scanner.Finding
	var details []scanner.RunResult
	done := 0
	for range runners {
		res := <-results
		done++
		details = append(details, res)
		if res.Err == nil {
			allFindings = append(allFindings, res.Findings...)
		}
		e.OnProgress(res.Tool, done, len(runners), len(allFindings))
	}
	return allFindings, details
}
VSPEOFINTERNAL_PIPELINE_PIPELINE_GO

# ── internal/scanner/bandit/bandit.go
mkdir -p "internal/scanner/bandit"
cat > 'internal/scanner/bandit/bandit.go' << 'VSPEOFINTERNAL_SCANNER_BANDIT_BANDIT_GO'
package bandit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Bandit — Python SAST tool.
// Bandit outputs JSON with this shape:
//
//	{ "results": [ { "issue_severity": "HIGH", "issue_text": "...",
//	                 "filename": "...", "line_number": 1,
//	                 "test_id": "B101", "issue_cwe": {"id": 78} } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "bandit" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("bandit: Src path is required")
	}

	args := []string{
		"-r", opts.Src,
		"-f", "json",
		"-q", // quiet — suppress progress output
	}
	if extra, ok := opts.ExtraArgs["bandit"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "bandit", args...)
	if err != nil {
		return nil, err
	}

	// bandit exits 1 when findings exist — not an error for us
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type banditOutput struct {
	Results []banditResult `json:"results"`
}

type banditResult struct {
	TestID        string    `json:"test_id"`
	TestName      string    `json:"test_name"`
	IssueSeverity string    `json:"issue_severity"`
	IssueText     string    `json:"issue_text"`
	Filename      string    `json:"filename"`
	LineNumber    int       `json:"line_number"`
	IssueCWE      banditCWE `json:"issue_cwe"`
	MoreInfo      string    `json:"more_info"`
	Code          string    `json:"code"`
}

type banditCWE struct {
	ID   int    `json:"id"`
	Link string `json:"link"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out banditOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("bandit: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		cwe := ""
		if r.IssueCWE.ID > 0 {
			cwe = fmt.Sprintf("CWE-%d", r.IssueCWE.ID)
		}

		findings = append(findings, scanner.Finding{
			Tool:      "bandit",
			Severity:  scanner.NormaliseSeverity(r.IssueSeverity),
			RuleID:    r.TestID,
			Message:   r.IssueText,
			Path:      r.Filename,
			Line:      r.LineNumber,
			CWE:       cwe,
			FixSignal: r.MoreInfo,
			Raw: map[string]any{
				"test_name": r.TestName,
				"code":      r.Code,
			},
		})
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_BANDIT_BANDIT_GO

# ── internal/scanner/codeql/codeql.go
mkdir -p "internal/scanner/codeql"
cat > 'internal/scanner/codeql/codeql.go' << 'VSPEOFINTERNAL_SCANNER_CODEQL_CODEQL_GO'
package codeql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs CodeQL — deep semantic SAST via query-based engine.
// CodeQL requires a pre-built database. We support two modes:
//  1. If CodeQL DB already exists at opts.Src + "/.codeql-db" → run analyze directly
//  2. Otherwise → create database first, then analyze
//
// Output is SARIF 2.1.0 which we parse into canonical Findings.
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "codeql" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("codeql: Src path is required")
	}

	sarifPath := "/tmp/codeql_results.sarif"
	dbPath := opts.Src + "/.codeql-db"

	// Step 1: create database (skip if already exists)
	dbArgs := []string{
		"database", "create", dbPath,
		"--source-root", opts.Src,
		"--language", "python", // TODO: auto-detect language
		"--overwrite",
	}
	if _, err := scanner.Run(ctx, "codeql", dbArgs...); err != nil {
		return nil, fmt.Errorf("codeql: database create: %w", err)
	}

	// Step 2: analyze
	analyzeArgs := []string{
		"database", "analyze",
		dbPath,
		"--format", "sarif-latest",
		"--output", sarifPath,
		"--quiet",
	}
	if extra, ok := opts.ExtraArgs["codeql"]; ok {
		analyzeArgs = append(analyzeArgs, extra...)
	}
	if _, err := scanner.Run(ctx, "codeql", analyzeArgs...); err != nil {
		return nil, fmt.Errorf("codeql: analyze: %w", err)
	}

	// Step 3: read SARIF output
	catRes, err := scanner.Run(ctx, "cat", sarifPath)
	if err != nil || len(catRes.Stdout) == 0 {
		return nil, nil
	}

	return parseSARIF(catRes.Stdout)
}

// ── SARIF Parser (minimal, covers CodeQL output) ──────────────────────────────

type sarifDoc struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	Precision string   `json:"precision"`
	Tags      []string `json:"tags"`
}

type sarifResult struct {
	RuleID  string          `json:"ruleId"`
	Level   string          `json:"level"` // "error"|"warning"|"note"
	Message sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func parseSARIF(data []byte) ([]scanner.Finding, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("codeql: parse SARIF: %w", err)
	}

	var findings []scanner.Finding
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			path := ""
			line := 0
			if len(r.Locations) > 0 {
				path = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				line = r.Locations[0].PhysicalLocation.Region.StartLine
			}

			// Extract CWE from rule tags
			cwe := extractCWE(run.Tool.Driver.Rules, r.RuleID)

			findings = append(findings, scanner.Finding{
				Tool:      "codeql",
				Severity:  sarifLevelToSeverity(r.Level),
				RuleID:    r.RuleID,
				Message:   r.Message.Text,
				Path:      path,
				Line:      line,
				CWE:       cwe,
				FixSignal: "see codeql rule: " + r.RuleID,
				Raw: map[string]any{
					"sarif_level": r.Level,
				},
			})
		}
	}
	return findings, nil
}

func sarifLevelToSeverity(level string) scanner.Severity {
	switch strings.ToLower(level) {
	case "error":
		return scanner.SevHigh
	case "warning":
		return scanner.SevMedium
	case "note":
		return scanner.SevLow
	default:
		return scanner.SevInfo
	}
}

func extractCWE(rules []sarifRule, ruleID string) string {
	for _, r := range rules {
		if r.ID != ruleID {
			continue
		}
		for _, tag := range r.Properties.Tags {
			if strings.HasPrefix(tag, "CWE-") {
				return tag
			}
		}
	}
	return ""
}
VSPEOFINTERNAL_SCANNER_CODEQL_CODEQL_GO

# ── internal/scanner/exec.go
mkdir -p "internal/scanner"
cat > 'internal/scanner/exec.go' << 'VSPEOFINTERNAL_SCANNER_EXEC_GO'
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ExecResult holds the raw output from a tool invocation.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// Run executes binary with args under ctx.
// It returns an error only for fatal failures (binary not found, context
// cancelled). Non-zero exit codes from security tools are NOT treated as
// errors because most tools exit non-zero when they find issues.
func Run(ctx context.Context, binary string, args ...string) (ExecResult, error) {
	// Verify tool exists before spawning
	if _, err := exec.LookPath(binary); err != nil {
		return ExecResult{}, ErrToolNotFound{Tool: binary}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	res := ExecResult{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if cmd.ProcessState != nil {
		res.Exit = cmd.ProcessState.ExitCode()
	}

	// Context cancellation is a hard error
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s: %w (stderr: %s)", binary, ctx.Err(), truncate(stderr.String(), 200))
	}

	// Binary not found / permission error
	if err != nil && res.Exit == -1 {
		return res, fmt.Errorf("%s: failed to start: %w", binary, err)
	}

	return res, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
VSPEOFINTERNAL_SCANNER_EXEC_GO

# ── internal/scanner/gitleaks/gitleaks.go
mkdir -p "internal/scanner/gitleaks"
cat > 'internal/scanner/gitleaks/gitleaks.go' << 'VSPEOFINTERNAL_SCANNER_GITLEAKS_GITLEAKS_GO'
package gitleaks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Gitleaks — git history secret and credential scanning.
// gitleaks detect --source [path] --report-format json --report-path /dev/stdout
//
// Output: JSON array of leak objects
//
//	[ { "Description": "...", "StartLine": 10, "File": "...",
//	    "RuleID": "aws-access-token", "Secret": "AKI...",
//	    "Match": "...", "Author": "...", "Date": "..." } ]
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "gitleaks" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("gitleaks: Src path is required")
	}

	args := []string{
		"detect",
		"--source", opts.Src,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-git",   // scan files directly, not git history
		"--exit-code", "0",
	}
	if extra, ok := opts.ExtraArgs["gitleaks"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "gitleaks", args...)
	if err != nil {
		return nil, err
	}

	// gitleaks exits 1 when leaks found — stdout contains JSON
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type gitleaksLeak struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Tags        []string `json:"Tags"`
	Match       string `json:"Match"`  // masked by gitleaks
	Commit      string `json:"Commit"`
	Author      string `json:"Author"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var leaks []gitleaksLeak
	if err := json.Unmarshal(data, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(leaks))
	for _, l := range leaks {
		findings = append(findings, scanner.Finding{
			Tool:      "gitleaks",
			Severity:  scanner.SevCritical, // secrets are always CRITICAL
			RuleID:    l.RuleID,
			Message:   l.Description,
			Path:      l.File,
			Line:      l.StartLine,
			CWE:       "CWE-798", // hard-coded credentials
			FixSignal: "rotate secret immediately, then remove from repo history",
			Raw: map[string]any{
				"match":  l.Match, // already masked by gitleaks
				"commit": l.Commit,
				"author": l.Author,
				"tags":   l.Tags,
			},
		})
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_GITLEAKS_GITLEAKS_GO

# ── internal/scanner/grype/grype.go
mkdir -p "internal/scanner/grype"
cat > 'internal/scanner/grype/grype.go' << 'VSPEOFINTERNAL_SCANNER_GRYPE_GRYPE_GO'
package grype

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Grype — vulnerability scanner against SBOM / packages.
// Output: grype [source] -o json
//
//	{ "matches": [ { "vulnerability": { "id": "CVE-...", "severity": "High",
//	                  "description": "...", "fix": { "versions": ["1.2.3"] } },
//	                "artifact": { "name": "pkg", "version": "1.0.0" } } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "grype" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	src := opts.Src
	if src == "" {
		return nil, fmt.Errorf("grype: Src path is required")
	}

	args := []string{
		src,
		"-o", "json",
		"--quiet",
		"--fail-on", "none", // never exit non-zero on findings
	}
	if extra, ok := opts.ExtraArgs["grype"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "grype", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln    `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Fix         grypeFix  `json:"fix"`
	URLs        []string  `json:"urls"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"` // "fixed", "not-fixed", "wont-fix"
}

type grypeArtifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"` // "deb", "go-module", "python", …
	Location string `json:"locations"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out grypeOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("grype: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Matches))
	for _, m := range out.Matches {
		fixSignal := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixSignal = "upgrade to " + m.Vulnerability.Fix.Versions[0]
		} else if m.Vulnerability.Fix.State != "" {
			fixSignal = m.Vulnerability.Fix.State
		}

		pkg := fmt.Sprintf("%s@%s", m.Artifact.Name, m.Artifact.Version)

		findings = append(findings, scanner.Finding{
			Tool:      "grype",
			Severity:  scanner.NormaliseSeverity(m.Vulnerability.Severity),
			RuleID:    m.Vulnerability.ID,
			Message:   m.Vulnerability.Description,
			Path:      pkg,
			CWE:       m.Vulnerability.ID, // CVE/GHSA ID as CWE field
			FixSignal: fixSignal,
			Raw: map[string]any{
				"artifact_type": m.Artifact.Type,
				"urls":          m.Vulnerability.URLs,
				"fix_state":     m.Vulnerability.Fix.State,
			},
		})
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_GRYPE_GRYPE_GO

# ── internal/scanner/kics/kics.go
mkdir -p "internal/scanner/kics"
cat > 'internal/scanner/kics/kics.go' << 'VSPEOFINTERNAL_SCANNER_KICS_KICS_GO'
package kics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs KICS — Infrastructure-as-Code misconfiguration detection.
// kics scan -p [path] -o /tmp --report-formats json --silent
//
// Output shape:
//
//	{ "queries": [ { "query_name": "Missing User Instruction",
//	                 "severity": "HIGH", "query_id": "...",
//	                 "files": [ { "file_name": "Dockerfile",
//	                              "line": 1, "issue_type": "MissingAttribute",
//	                              "search_value": "..." } ] } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "kics" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("kics: Src path is required")
	}

	args := []string{
		"scan",
		"-p", opts.Src,
		"--report-formats", "json",
		"--output-path", "/tmp/kics_out",
		"--silent",
		"--no-progress",
		"--fail-on", "none",
	}
	if extra, ok := opts.ExtraArgs["kics"]; ok {
		args = append(args, extra...)
	}

	if _, err := scanner.Run(ctx, "kics", args...); err != nil {
		return nil, err
	}

	// KICS writes results.json to --output-path
	readArgs := []string{"/tmp/kics_out/results.json"}
	catRes, err := scanner.Run(ctx, "cat", readArgs...)
	if err != nil || len(catRes.Stdout) == 0 {
		return nil, nil // no output = no findings
	}

	return parse(catRes.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type kicsOutput struct {
	Queries []kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName string      `json:"query_name"`
	QueryID   string      `json:"query_id"`
	Severity  string      `json:"severity"`
	Platform  string      `json:"platform"` // Dockerfile, Terraform, …
	CWE       string      `json:"cis_description_id"`
	Files     []kicsFile  `json:"files"`
}

type kicsFile struct {
	FileName    string `json:"file_name"`
	Line        int    `json:"line"`
	IssueType   string `json:"issue_type"`
	SearchValue string `json:"search_value"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out kicsOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("kics: parse JSON: %w", err)
	}

	var findings []scanner.Finding
	for _, q := range out.Queries {
		for _, f := range q.Files {
			findings = append(findings, scanner.Finding{
				Tool:      "kics",
				Severity:  scanner.NormaliseSeverity(q.Severity),
				RuleID:    q.QueryID,
				Message:   q.QueryName,
				Path:      f.FileName,
				Line:      f.Line,
				CWE:       q.CWE,
				FixSignal: "see kics docs for " + q.QueryName,
				Raw: map[string]any{
					"platform":     q.Platform,
					"issue_type":   f.IssueType,
					"search_value": f.SearchValue,
				},
			})
		}
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_KICS_KICS_GO

# ── internal/scanner/nikto/nikto.go
mkdir -p "internal/scanner/nikto"
cat > 'internal/scanner/nikto/nikto.go' << 'VSPEOFINTERNAL_SCANNER_NIKTO_NIKTO_GO'
package nikto

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Nikto — web server misconfiguration and header scanning.
// nikto -h [url] -Format xml -o /dev/stdout -nointeractive
//
// Nikto XML output:
//
//	<niktoscan><scandetails><item id="..." osvdbid="..." method="GET">
//	  <description>...</description><uri>...</uri>
//	  <namelink>...</namelink></item></scandetails></niktoscan>
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "nikto" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	target := opts.URL
	if target == "" {
		target = opts.Src // fallback if URL not specified
	}
	if target == "" {
		return nil, fmt.Errorf("nikto: URL is required for DAST scanning")
	}

	args := []string{
		"-h", target,
		"-Format", "xml",
		"-o", "/dev/stdout",
		"-nointeractive",
		"-maxtime", fmt.Sprintf("%ds", niktoTimeout(opts)),
	}
	if extra, ok := opts.ExtraArgs["nikto"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "nikto", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parseXML(res.Stdout)
}

func niktoTimeout(opts scanner.RunOpts) int {
	if opts.TimeoutSec > 30 {
		return opts.TimeoutSec - 10
	}
	return 240
}

// ── XML Parser ────────────────────────────────────────────────────────────────

type niktoScan struct {
	XMLName     xml.Name       `xml:"niktoscan"`
	ScanDetails []niktoDetails `xml:"scandetails"`
}

type niktoDetails struct {
	Items []niktoItem `xml:"item"`
}

type niktoItem struct {
	ID          string `xml:"id,attr"`
	OSVDBID     string `xml:"osvdbid,attr"`
	Method      string `xml:"method,attr"`
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
}

// osvdbSeverity maps OSVDB ID ranges to rough severity levels.
// Nikto doesn't provide severity natively — we derive from OSVDB category.
func osvdbSeverity(osvdb string) scanner.Severity {
	switch {
	case osvdb == "0":
		return scanner.SevInfo
	default:
		return scanner.SevMedium
	}
}

func parseXML(data []byte) ([]scanner.Finding, error) {
	var out niktoScan
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("nikto: parse XML: %w", err)
	}

	var findings []scanner.Finding
	for _, d := range out.ScanDetails {
		for _, item := range d.Items {
			findings = append(findings, scanner.Finding{
				Tool:      "nikto",
				Severity:  osvdbSeverity(item.OSVDBID),
				RuleID:    "NIKTO-" + item.ID,
				Message:   item.Description,
				Path:      item.URI,
				CWE:       "",
				FixSignal: item.NameLink,
				Raw: map[string]any{
					"osvdb_id": item.OSVDBID,
					"method":   item.Method,
				},
			})
		}
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_NIKTO_NIKTO_GO

# ── internal/scanner/runner.go
mkdir -p "internal/scanner"
cat > 'internal/scanner/runner.go' << 'VSPEOFINTERNAL_SCANNER_RUNNER_GO'
package scanner

import (
	"context"
	"fmt"
	"time"
)

// ── Severity ──────────────────────────────────────────────────────────────────

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
	SevTrace    Severity = "TRACE"
)

var severityRank = map[Severity]int{
	SevCritical: 6,
	SevHigh:     5,
	SevMedium:   4,
	SevLow:      3,
	SevInfo:     2,
	SevTrace:    1,
}

func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return 0
}

// NormaliseSeverity maps arbitrary tool-specific strings to canonical Severity.
func NormaliseSeverity(raw string) Severity {
	switch raw {
	case "critical", "CRITICAL", "error", "ERROR":
		return SevCritical
	case "high", "HIGH":
		return SevHigh
	case "medium", "MEDIUM", "warning", "WARNING", "warn", "WARN":
		return SevMedium
	case "low", "LOW", "note", "NOTE":
		return SevLow
	case "info", "INFO", "informational", "INFORMATIONAL":
		return SevInfo
	default:
		return SevTrace
	}
}

// ── Finding ───────────────────────────────────────────────────────────────────

// Finding is the canonical, tool-agnostic representation of a security finding.
// Every tool adapter MUST normalise its output into this struct.
type Finding struct {
	Tool      string            `json:"tool"`
	Severity  Severity          `json:"severity"`
	RuleID    string            `json:"rule_id"`
	Message   string            `json:"message"`
	Path      string            `json:"path"`       // file path or package name
	Line      int               `json:"line"`       // 0 = not applicable
	CWE       string            `json:"cwe"`        // e.g. "CWE-79", "CVE-2024-1234", "GHSA-xxxx"
	FixSignal string            `json:"fix_signal"` // upgrade hint or remediation note
	Raw       map[string]any    `json:"raw"`        // original tool output for audit
}

// ── RunOpts ───────────────────────────────────────────────────────────────────

// RunOpts carries the parameters for a single tool invocation.
type RunOpts struct {
	// Src is the absolute path to the source directory to scan.
	// Required for SAST, SCA, SECRETS, IAC modes.
	Src string

	// URL is the target URL for DAST scans (nikto, nuclei).
	URL string

	// TimeoutSec is the per-tool timeout. 0 means default (300s).
	TimeoutSec int

	// Mode is the scan mode hint — tools may skip themselves based on mode.
	Mode string // SAST | DAST | SCA | SECRETS | IAC | FULL

	// ExtraArgs passes additional CLI flags per tool.
	// Key = tool name (e.g. "semgrep"), Value = extra args slice.
	ExtraArgs map[string][]string
}

func (o RunOpts) timeout() time.Duration {
	if o.TimeoutSec > 0 {
		return time.Duration(o.TimeoutSec) * time.Second
	}
	return 300 * time.Second
}

// ── Runner interface ──────────────────────────────────────────────────────────

// Runner is implemented by each tool adapter (bandit, semgrep, grype, …).
// Each adapter is responsible for:
//   1. Invoking the tool binary via exec.Command
//   2. Parsing stdout (JSON / SARIF / XML)
//   3. Returning []Finding normalised to canonical fields
//
// Adapters MUST respect ctx cancellation and the timeout in RunOpts.
type Runner interface {
	// Name returns the tool identifier used in Finding.Tool and logs.
	Name() string

	// Run executes the tool and returns findings. Returning an error does NOT
	// fail the whole pipeline — the caller records the error and continues.
	Run(ctx context.Context, opts RunOpts) ([]Finding, error)
}

// ── RunResult ─────────────────────────────────────────────────────────────────

// RunResult captures the outcome of one tool within a pipeline run.
type RunResult struct {
	Tool     string
	Findings []Finding
	Err      error
	Duration time.Duration
}

// ── RunAll ────────────────────────────────────────────────────────────────────

// RunAll executes all runners concurrently under ctx, merges findings, and
// returns per-tool errors without aborting the whole run.
//
// Each runner gets its own child context bounded by opts.timeout() so a
// slow tool cannot block the others indefinitely.
func RunAll(ctx context.Context, runners []Runner, opts RunOpts) ([]Finding, []RunResult) {
	results := make(chan RunResult, len(runners))

	for _, r := range runners {
		r := r // capture
		go func() {
			tctx, cancel := context.WithTimeout(ctx, opts.timeout())
			defer cancel()

			start := time.Now()
			findings, err := r.Run(tctx, opts)
			results <- RunResult{
				Tool:     r.Name(),
				Findings: findings,
				Err:      err,
				Duration: time.Since(start),
			}
		}()
	}

	var all []Finding
	var details []RunResult
	for range runners {
		res := <-results
		details = append(details, res)
		if res.Err == nil {
			all = append(all, res.Findings...)
		}
	}
	return all, details
}

// ── Summary ───────────────────────────────────────────────────────────────────

// Summarise counts findings by severity from a slice.
type Summary struct {
	Critical   int
	High       int
	Medium     int
	Low        int
	Info       int
	Trace      int
	HasSecrets bool // true if any gitleaks finding present
}

func Summarise(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		case SevInfo:
			s.Info++
		default:
			s.Trace++
		}
		if f.Tool == "gitleaks" {
			s.HasSecrets = true
		}
	}
	return s
}

// Total returns the sum of all severity counts.
func (s Summary) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Info + s.Trace
}

// ── ErrToolNotFound ───────────────────────────────────────────────────────────

// ErrToolNotFound is returned when the tool binary is not on PATH.
type ErrToolNotFound struct{ Tool string }

func (e ErrToolNotFound) Error() string {
	return fmt.Sprintf("tool not found on PATH: %s", e.Tool)
}
VSPEOFINTERNAL_SCANNER_RUNNER_GO

# ── internal/scanner/semgrep/semgrep.go
mkdir -p "internal/scanner/semgrep"
cat > 'internal/scanner/semgrep/semgrep.go' << 'VSPEOFINTERNAL_SCANNER_SEMGREP_SEMGREP_GO'
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Semgrep — rule-based SAST.
// We use --json output (simpler than SARIF for semgrep's format).
//
// Output shape:
//
//	{ "results": [ { "check_id": "...", "path": "...", "start": {"line": 1},
//	                 "extra": { "severity": "ERROR", "message": "...",
//	                            "metadata": {"cwe": ["CWE-79"]} } } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("semgrep: Src path is required")
	}

	args := []string{
		"scan",
		"--json",
		"--quiet",
		"--config=auto", // use community rules; override with ExtraArgs
		opts.Src,
	}
	if extra, ok := opts.ExtraArgs["semgrep"]; ok {
		// Allow caller to replace --config=auto with custom ruleset
		args = append(args[:len(args)-2], extra...) // splice before src
		args = append(args, opts.Src)
	}

	res, err := scanner.Run(ctx, "semgrep", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
}

type semgrepExtra struct {
	Severity string            `json:"severity"`
	Message  string            `json:"message"`
	Metadata semgrepMetadata   `json:"metadata"`
	Fix      string            `json:"fix"`
}

type semgrepMetadata struct {
	CWE        []string `json:"cwe"`
	Confidence string   `json:"confidence"`
	References []string `json:"references"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("semgrep: parse JSON: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		cwe := ""
		if len(r.Extra.Metadata.CWE) > 0 {
			cwe = r.Extra.Metadata.CWE[0]
		}

		findings = append(findings, scanner.Finding{
			Tool:      "semgrep",
			Severity:  scanner.NormaliseSeverity(r.Extra.Severity),
			RuleID:    r.CheckID,
			Message:   r.Extra.Message,
			Path:      r.Path,
			Line:      r.Start.Line,
			CWE:       cwe,
			FixSignal: r.Extra.Fix,
			Raw: map[string]any{
				"confidence": r.Extra.Metadata.Confidence,
				"references": r.Extra.Metadata.References,
			},
		})
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_SEMGREP_SEMGREP_GO

# ── internal/scanner/trivy/trivy.go
mkdir -p "internal/scanner/trivy"
cat > 'internal/scanner/trivy/trivy.go' << 'VSPEOFINTERNAL_SCANNER_TRIVY_TRIVY_GO'
package trivy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vsp/platform/internal/scanner"
)

// Adapter runs Trivy — container and dependency vulnerability scanning.
// trivy fs [path] --format json --quiet
//
// Output shape:
//
//	{ "Results": [ { "Target": "requirements.txt", "Type": "pip",
//	                 "Vulnerabilities": [ { "VulnerabilityID": "CVE-...",
//	                   "Severity": "HIGH", "Title": "...",
//	                   "InstalledVersion": "1.0.0",
//	                   "FixedVersion": "1.2.0" } ] } ] }
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "trivy" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if opts.Src == "" {
		return nil, fmt.Errorf("trivy: Src path is required")
	}

	args := []string{
		"fs",
		"--format", "json",
		"--quiet",
		"--exit-code", "0", // never fail on findings
		opts.Src,
	}
	if extra, ok := opts.ExtraArgs["trivy"]; ok {
		args = append(args, extra...)
	}

	res, err := scanner.Run(ctx, "trivy", args...)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) == 0 {
		return nil, nil
	}

	return parse(res.Stdout)
}

// ── Parser ────────────────────────────────────────────────────────────────────

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string        `json:"Target"`
	Type            string        `json:"Type"`
	Vulnerabilities []trivyVuln   `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	CweIDs           []string `json:"CweIDs"`
	References       []string `json:"References"`
}

func parse(data []byte) ([]scanner.Finding, error) {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("trivy: parse JSON: %w", err)
	}

	var findings []scanner.Finding
	for _, r := range out.Results {
		for _, v := range r.Vulnerabilities {
			msg := v.Title
			if msg == "" {
				msg = v.Description
			}

			cwe := v.VulnerabilityID // CVE ID
			if len(v.CweIDs) > 0 {
				cwe = v.CweIDs[0]
			}

			fixSignal := ""
			if v.FixedVersion != "" {
				fixSignal = "upgrade to " + v.FixedVersion
			}

			findings = append(findings, scanner.Finding{
				Tool:      "trivy",
				Severity:  scanner.NormaliseSeverity(v.Severity),
				RuleID:    v.VulnerabilityID,
				Message:   msg,
				Path:      r.Target,
				CWE:       cwe,
				FixSignal: fixSignal,
				Raw: map[string]any{
					"pkg_name":          v.PkgName,
					"installed_version": v.InstalledVersion,
					"target_type":       r.Type,
					"references":        v.References,
				},
			})
		}
	}
	return findings, nil
}
VSPEOFINTERNAL_SCANNER_TRIVY_TRIVY_GO

# ── migrations/001_init.sql
mkdir -p "migrations"
cat > 'migrations/001_init.sql' << 'VSPEOFMIGRATIONS_001_INIT_SQL'
-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE tenants (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       TEXT UNIQUE NOT NULL,
  name       TEXT NOT NULL,
  plan       TEXT NOT NULL DEFAULT 'starter',
  active     BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  pw_hash     TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'analyst',
  mfa_enabled BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login  TIMESTAMPTZ,
  UNIQUE(tenant_id, email)
);

CREATE TABLE api_keys (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL REFERENCES tenants(id),
  label      TEXT NOT NULL,
  prefix     TEXT NOT NULL,
  hash       TEXT NOT NULL,
  role       TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  last_used  TIMESTAMPTZ,
  use_count  INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE runs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rid          TEXT UNIQUE NOT NULL,
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  mode         TEXT NOT NULL,
  profile      TEXT NOT NULL DEFAULT 'FAST',
  src          TEXT,
  target_url   TEXT,
  status       TEXT NOT NULL DEFAULT 'QUEUED',
  gate         TEXT,
  posture      TEXT,
  tools_done   INT NOT NULL DEFAULT 0,
  tools_total  INT NOT NULL DEFAULT 8,
  total_findings INT NOT NULL DEFAULT 0,
  summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_runs_tenant   ON runs(tenant_id, created_at DESC);
CREATE INDEX idx_runs_status   ON runs(tenant_id, status);

CREATE TABLE findings (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id     UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  tenant_id  UUID NOT NULL,
  tool       TEXT NOT NULL,
  severity   TEXT NOT NULL,
  rule_id    TEXT,
  message    TEXT,
  path       TEXT,
  line_num   INT,
  cwe        TEXT,
  fix_signal TEXT,
  raw        JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_run      ON findings(run_id);
CREATE INDEX idx_findings_severity ON findings(tenant_id, severity);
CREATE INDEX idx_findings_tool     ON findings(tenant_id, tool);

CREATE TABLE audit_log (
  seq        BIGSERIAL PRIMARY KEY,
  tenant_id  UUID NOT NULL,
  user_id    UUID,
  action     TEXT NOT NULL,
  resource   TEXT,
  ip         TEXT,
  payload    JSONB,
  hash       TEXT NOT NULL,
  prev_hash  TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON audit_log(tenant_id, seq);

CREATE TABLE siem_webhooks (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  label       TEXT NOT NULL,
  type        TEXT NOT NULL,
  url         TEXT NOT NULL,
  secret_hash TEXT,
  min_sev     TEXT NOT NULL DEFAULT 'HIGH',
  active      BOOLEAN NOT NULL DEFAULT true,
  last_fired  TIMESTAMPTZ,
  fire_count  INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE policy_rules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL REFERENCES tenants(id),
  name           TEXT NOT NULL,
  repo_pattern   TEXT NOT NULL DEFAULT '*',
  fail_on        TEXT NOT NULL DEFAULT 'FAIL',
  min_score      INT DEFAULT 0,
  max_high       INT DEFAULT -1,
  block_secrets  BOOLEAN NOT NULL DEFAULT true,
  block_critical BOOLEAN NOT NULL DEFAULT true,
  active         BOOLEAN NOT NULL DEFAULT true,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default tenant for dev
INSERT INTO tenants (slug, name, plan) VALUES ('default', 'Default Tenant', 'enterprise');

-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS siem_webhooks;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
VSPEOFMIGRATIONS_001_INIT_SQL

echo ""
echo "================================================================"
echo "  Done! $(find . -name "*.go" | wc -l) Go files created."
echo ""
echo "  Buoc tiep theo:"
echo "    1.  go mod tidy"
echo "    2.  docker compose -f docker/compose.dev.yml up -d"
echo "    3.  export DATABASE_URL=postgres://vsp:vsp@localhost:5432/vsp_go"
echo "    4.  make migrate-up"
echo "    5.  make build"
echo "    6.  ./gateway   # port 8920"
echo "    7.  ./scanner   # port 8921 (worker)"
echo "================================================================"
