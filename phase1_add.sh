#!/usr/bin/env bash
# ================================================================
# VSP Go — phase1_add.sh
# Phase 1: Store layer + Auth/Users/APIKeys handlers + wired gateway
# Chay tu ~/Data/GOLANG_VSP
# ================================================================
set -e
echo ">>> Phase 1: Store + Auth handlers"

mkdir -p internal/store/queries
mkdir -p internal/api/handler
mkdir -p internal/api/middleware

# cmd/gateway/main.go
mkdir -p "cmd/gateway"
cat > 'cmd/gateway/main.go' << 'VSPPH1CMD_GATEWAY_MAIN_GO'
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/vsp/platform/internal/api/handler"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetDefault("server.gateway_port", 8920)
	viper.SetDefault("auth.jwt_secret", "dev-secret-change-in-prod")
	viper.SetDefault("auth.jwt_ttl", "24h")
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.SetDefault("log.level", "info")
	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("no config file — using defaults")
	}

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// ── DB ────────────────────────────────────────────────────────
	ctx := context.Background()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil {
		log.Fatal().Err(err).Msg("database connect failed")
	}
	defer db.Close()
	log.Info().Msg("database connected ✓")

	ensureDefaultTenant(ctx, db)
	defaultTID := getDefaultTenantID(ctx, db)

	// ── JWT ───────────────────────────────────────────────────────
	jwtSecret := viper.GetString("auth.jwt_secret")
	jwtTTL, _ := time.ParseDuration(viper.GetString("auth.jwt_ttl"))
	if jwtTTL == 0 {
		jwtTTL = 24 * time.Hour
	}

	// ── Handlers ──────────────────────────────────────────────────
	authH    := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}
	usersH   := &handler.Users{DB: db}
	apiKeysH := &handler.APIKeys{DB: db}
	keyStore := &apiKeyStore{db: db}

	// ── Router ────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(corsMiddleware)

	// Public
	r.Get("/health", healthHandler)
	r.Post("/api/v1/auth/login", authH.Login)

	// Authenticated
	authMw := auth.Middleware(jwtSecret, keyStore)
	r.Group(func(r chi.Router) {
		r.Use(authMw)

		r.Post("/api/v1/auth/logout", authH.Logout)
		r.Post("/api/v1/auth/refresh", authH.Refresh)

		// Admin only
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole("admin"))
			r.Get("/api/v1/admin/users", usersH.List)
			r.Post("/api/v1/admin/users", usersH.Create)
			r.Delete("/api/v1/admin/users/{id}", usersH.Delete)
			r.Get("/api/v1/admin/api-keys", apiKeysH.List)
			r.Post("/api/v1/admin/api-keys", apiKeysH.Create)
			r.Delete("/api/v1/admin/api-keys/{id}", apiKeysH.Delete)
		})

		// Scan / Pipeline
		r.Post("/api/v1/vsp/run", handleNotImpl)
		r.Post("/api/v1/vsp/run/{rid}/cancel", handleNotImpl)
		r.Get("/api/v1/vsp/run/latest", handleNotImpl)
		r.Get("/api/v1/vsp/run/{rid}", handleNotImpl)
		r.Get("/api/v1/vsp/runs", handleNotImpl)
		r.Get("/api/v1/vsp/runs/index", handleNotImpl)
		r.Get("/api/v1/vsp/findings", handleNotImpl)
		r.Get("/api/v1/vsp/findings/summary", handleNotImpl)
		r.Get("/api/v1/vsp/gate/latest", handleNotImpl)
		r.Get("/api/v1/vsp/posture/latest", handleNotImpl)

		// Policy
		r.Post("/api/v1/policy/evaluate", handleNotImpl)
		r.Get("/api/v1/policy/rules", handleNotImpl)
		r.Post("/api/v1/policy/rules", handleNotImpl)
		r.Delete("/api/v1/policy/rules/{id}", handleNotImpl)

		// Audit
		r.Get("/api/v1/audit/log", handleNotImpl)
		r.Post("/api/v1/audit/verify", handleNotImpl)

		// SIEM
		r.Get("/api/v1/siem/webhooks", handleNotImpl)
		r.Post("/api/v1/siem/webhooks", handleNotImpl)
		r.Delete("/api/v1/siem/webhooks/{id}", handleNotImpl)
		r.Post("/api/v1/siem/webhooks/{id}/test", handleNotImpl)

		// Compliance & Governance & SOC (all authenticated)
		notImplGet := []string{
			"/api/v1/compliance/oscal/ar", "/api/v1/compliance/oscal/poam",
			"/api/v1/governance/risk-register", "/api/v1/governance/ownership",
			"/api/v1/governance/evidence", "/api/v1/governance/effectiveness",
			"/api/v1/governance/traceability", "/api/v1/governance/raci",
			"/api/v1/governance/rule-overrides",
			"/api/v1/soc/detection", "/api/v1/soc/incidents",
			"/api/v1/soc/supply-chain", "/api/v1/soc/release-governance",
			"/api/v1/soc/framework-scorecard", "/api/v1/soc/roadmap",
			"/api/v1/soc/zero-trust",
		}
		for _, p := range notImplGet {
			r.Get(p, handleNotImpl)
		}
		r.Post("/api/v1/governance/evidence/{id}/freeze", handleNotImpl)
	})

	// ── Start ─────────────────────────────────────────────────────
	addr := fmt.Sprintf(":%d", viper.GetInt("server.gateway_port"))
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	log.Info().Str("addr", addr).Str("tenant", defaultTID[:8]+"…").
		Msg("VSP Gateway ready — Auth LIVE ✓")

	<-quit
	log.Info().Msg("shutting down…")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(sctx) //nolint:errcheck
	log.Info().Msg("stopped")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"0.1.0","port":%d}`,
		viper.GetInt("server.gateway_port"))
}

func handleNotImpl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, `{"error":"not implemented","path":%q,"method":%q}`,
		r.URL.Path, r.Method)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-API-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── apiKeyStore ───────────────────────────────────────────────────────────────

type apiKeyStore struct{ db *store.DB }

func (s *apiKeyStore) ValidateAPIKey(ctx context.Context, rawKey string) (auth.Claims, error) {
	if len(rawKey) < 12 {
		return auth.Claims{}, fmt.Errorf("key too short")
	}
	prefix := rawKey[:12]

	rows, err := s.db.Pool().Query(ctx,
		`SELECT id, tenant_id, hash, role, expires_at FROM api_keys WHERE prefix = $1`, prefix)
	if err != nil {
		return auth.Claims{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var id, tenantID, hash, role string
		var expiresAt *time.Time
		rows.Scan(&id, &tenantID, &hash, &role, &expiresAt) //nolint:errcheck
		if expiresAt != nil && time.Now().After(*expiresAt) {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawKey)); err != nil {
			continue
		}
		go s.db.TouchAPIKey(ctx, id) //nolint:errcheck
		return auth.Claims{TenantID: tenantID, Role: role, UserID: id}, nil
	}
	return auth.Claims{}, fmt.Errorf("invalid api key")
}

// ── DB bootstrap ─────────────────────────────────────────────────────────────

func ensureDefaultTenant(ctx context.Context, db *store.DB) {
	db.Pool().Exec(ctx, //nolint:errcheck
		`INSERT INTO tenants (slug, name, plan)
		 VALUES ('default','Default Tenant','enterprise')
		 ON CONFLICT (slug) DO NOTHING`)
}

func getDefaultTenantID(ctx context.Context, db *store.DB) string {
	var id string
	db.Pool().QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&id) //nolint:errcheck
	if id == "" {
		log.Fatal().Msg("default tenant not found — run: make migrate-up")
	}
	return id
}
VSPPH1CMD_GATEWAY_MAIN_GO

# internal/api/handler/apikeys.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/apikeys.go' << 'VSPPH1INTERNAL_API_HANDLER_APIKEYS_GO'
package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type APIKeys struct {
	DB *store.DB
}

// GET /api/v1/admin/api-keys
func (h *APIKeys) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	keys, err := h.DB.ListAPIKeys(r.Context(), claims.TenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"keys": keys, "total": len(keys)})
}

// POST /api/v1/admin/api-keys
func (h *APIKeys) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Label     string `json:"label"`
		Role      string `json:"role"`
		ExpiryDays int   `json:"expiry_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Label == "" {
		jsonError(w, "label required", http.StatusBadRequest)
		return
	}
	if req.Role == "" { req.Role = "analyst" }
	if req.ExpiryDays == 0 { req.ExpiryDays = 90 }

	// Generate: 32-byte random → hex → prefix(8) + full(64)
	buf := make([]byte, 32)
	rand.Read(buf)
	fullKey := "vspk_" + hex.EncodeToString(buf) // shown once
	prefix  := fullKey[:12]

	hash, _ := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	expiry := time.Now().AddDate(0, 0, req.ExpiryDays)

	key, err := h.DB.CreateAPIKey(r.Context(), claims.TenantID,
		req.Label, prefix, string(hash), req.Role, &expiry)
	if err != nil {
		jsonError(w, "create failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return full key ONCE — never stored in plain text
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{
		"id":         key.ID,
		"label":      key.Label,
		"prefix":     key.Prefix,
		"role":       key.Role,
		"expires_at": key.ExpiresAt,
		"key":        fullKey, // ← shown ONCE
		"warning":    "Copy this key now — it will not be shown again",
	})
}

// DELETE /api/v1/admin/api-keys/{id}
func (h *APIKeys) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.DB.DeleteAPIKey(r.Context(), claims.TenantID, id); err != nil {
		jsonError(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
VSPPH1INTERNAL_API_HANDLER_APIKEYS_GO

# internal/api/handler/auth.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/auth.go' << 'VSPPH1INTERNAL_API_HANDLER_AUTH_GO'
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/audit"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Auth bundles dependencies for auth handlers.
type Auth struct {
	DB         *store.DB
	JWTSecret  string
	JWTTTL     time.Duration
	DefaultTID string // default tenant for single-tenant dev setup
}

// ── POST /api/v1/auth/login ───────────────────────────────────────────────────

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token    string `json:"token"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	TenantID string `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}

	// Resolve tenant — use default for now; extend with X-Tenant-Slug header later
	tenantID := a.DefaultTID

	// Lookup user
	user, err := a.DB.GetUserByEmail(r.Context(), tenantID, req.Email)
	if err != nil {
		log.Error().Err(err).Str("email", req.Email).Msg("login: db error")
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(req.Password)); err != nil {
		// Log but return same message to prevent user enumeration
		log.Warn().Str("email", req.Email).Msg("login: wrong password")
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Issue JWT
	ttl := a.JWTTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	claims := auth.Claims{
		UserID:   user.ID,
		TenantID: user.TenantID,
		Role:     user.Role,
		Email:    user.Email,
	}
	token, err := auth.IssueJWT(a.JWTSecret, claims, ttl)
	if err != nil {
		log.Error().Err(err).Msg("login: issue jwt")
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update last_login (best-effort)
	go a.DB.UpdateLastLogin(r.Context(), user.ID) //nolint:errcheck

	// Write audit log (best-effort)
	go a.writeAudit(r, tenantID, &user.ID, "LOGIN_OK", "/auth/login")

	jsonOK(w, loginResponse{
		Token:     token,
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TenantID:  user.TenantID,
		ExpiresAt: time.Now().Add(ttl),
	})
}

// ── POST /api/v1/auth/logout ──────────────────────────────────────────────────
// Stateless JWT — logout is client-side token discard.
// We log the event for audit purposes.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if ok {
		go a.writeAudit(r, claims.TenantID, &claims.UserID, "LOGOUT", "/auth/logout")
	}
	jsonOK(w, map[string]string{"message": "logged out"})
}

// ── POST /api/v1/auth/refresh ─────────────────────────────────────────────────
func (a *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ttl := a.JWTTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	token, err := auth.IssueJWT(a.JWTSecret, claims, ttl)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"token":      token,
		"expires_at": time.Now().Add(ttl),
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (a *Auth) writeAudit(r *http.Request, tenantID string, userID *string, action, resource string) {
	prevHash, _ := a.DB.GetLastAuditHash(r.Context(), tenantID)
	e := audit.Entry{
		TenantID: tenantID,
		UserID:   derefStr(userID),
		Action:   action,
		Resource: resource,
		IP:       r.RemoteAddr,
		PrevHash: prevHash,
	}
	e.StoredHash = audit.Hash(e)
	a.DB.InsertAudit(r.Context(), tenantID, userID, action, resource, r.RemoteAddr, nil, e.StoredHash, prevHash) //nolint:errcheck
}

func derefStr(s *string) string {
	if s == nil { return "" }
	return *s
}
VSPPH1INTERNAL_API_HANDLER_AUTH_GO

# internal/api/handler/helpers.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/helpers.go' << 'VSPPH1INTERNAL_API_HANDLER_HELPERS_GO'
package handler

import (
	"encoding/json"
	"net/http"
)

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
VSPPH1INTERNAL_API_HANDLER_HELPERS_GO

# internal/api/handler/users.go
mkdir -p "internal/api/handler"
cat > 'internal/api/handler/users.go' << 'VSPPH1INTERNAL_API_HANDLER_USERS_GO'
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type Users struct {
	DB *store.DB
}

// GET /api/v1/admin/users
func (u *Users) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	limit  := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	users, total, err := u.DB.ListUsers(r.Context(), claims.TenantID, limit, offset)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// POST /api/v1/admin/users
func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "analyst"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	user, err := u.DB.CreateUser(r.Context(), claims.TenantID, req.Email, string(hash), req.Role)
	if err != nil {
		jsonError(w, "create user failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, user)
}

// DELETE /api/v1/admin/users/{id}
func (u *Users) Delete(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := u.DB.DeleteUser(r.Context(), claims.TenantID, id); err != nil {
		jsonError(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" { return def }
	n, err := strconv.Atoi(v)
	if err != nil { return def }
	return n
}
VSPPH1INTERNAL_API_HANDLER_USERS_GO

# internal/store/api_keys.go
mkdir -p "internal/store"
cat > 'internal/store/api_keys.go' << 'VSPPH1INTERNAL_STORE_API_KEYS_GO'
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
VSPPH1INTERNAL_STORE_API_KEYS_GO

# internal/store/audit.go
mkdir -p "internal/store"
cat > 'internal/store/audit.go' << 'VSPPH1INTERNAL_STORE_AUDIT_GO'
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type AuditEntry struct {
	Seq      int64           `json:"seq"`
	TenantID string          `json:"tenant_id"`
	UserID   *string         `json:"user_id"`
	Action   string          `json:"action"`
	Resource string          `json:"resource"`
	IP       string          `json:"ip"`
	Payload  json.RawMessage `json:"payload"`
	Hash     string          `json:"hash"`
	PrevHash string          `json:"prev_hash"`
	CreatedAt time.Time      `json:"created_at"`
}

func (db *DB) InsertAudit(ctx context.Context, tenantID string, userID *string, action, resource, ip string, payload json.RawMessage, hash, prevHash string) (int64, string, error) {
	var seq int64
	var h string
	err := db.pool.QueryRow(ctx,
		`INSERT INTO audit_log (tenant_id, user_id, action, resource, ip, payload, hash, prev_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING seq, hash`,
		tenantID, userID, action, resource, ip, payload, hash, prevHash).Scan(&seq, &h)
	if err != nil {
		return 0, "", fmt.Errorf("insert audit: %w", err)
	}
	return seq, h, nil
}

func (db *DB) GetLastAuditHash(ctx context.Context, tenantID string) (string, error) {
	var hash string
	err := db.pool.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`,
		tenantID).Scan(&hash)
	if err != nil {
		return "", nil // no entries yet — empty string is valid prev_hash for first entry
	}
	return hash, nil
}

func (db *DB) ListAuditPaged(ctx context.Context, tenantID, actionFilter string, limit, offset int) ([]AuditEntry, int64, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
		 FROM audit_log
		 WHERE tenant_id=$1 AND ($2='' OR action=$2)
		 ORDER BY seq DESC LIMIT $3 OFFSET $4`,
		tenantID, actionFilter, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.TenantID, &e.UserID, &e.Action,
			&e.Resource, &e.IP, &e.Hash, &e.PrevHash, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}

	var count int64
	db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log WHERE tenant_id=$1`, tenantID).Scan(&count)
	return entries, count, nil
}

// ListAuditByTenant returns ALL entries in ascending seq order (used by Verify).
func (db *DB) ListAuditByTenant(ctx context.Context, tenantID string) ([]AuditEntry, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
		 FROM audit_log WHERE tenant_id=$1 ORDER BY seq ASC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.TenantID, &e.UserID, &e.Action,
			&e.Resource, &e.IP, &e.Hash, &e.PrevHash, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}
VSPPH1INTERNAL_STORE_AUDIT_GO

# internal/store/db.go
mkdir -p "internal/store"
cat > 'internal/store/db.go' << 'VSPPH1INTERNAL_STORE_DB_GO'
// Package store provides PostgreSQL access using pgx/v5.
// Queries in this file are hand-written; run `sqlc generate` to regenerate
// type-safe wrappers once sqlc is installed.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool and provides all query methods needed by the gateway.
type DB struct {
	pool *pgxpool.Pool
}

// New creates a new DB from the given DSN and verifies connectivity.
func New(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse config: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Close() { db.pool.Close() }

// Pool exposes the raw pool for advanced use (transactions, etc).
func (db *DB) Pool() *pgxpool.Pool { return db.pool }
VSPPH1INTERNAL_STORE_DB_GO

# internal/store/queries/api_keys.sql
mkdir -p "internal/store/queries"
cat > 'internal/store/queries/api_keys.sql' << 'VSPPH1INTERNAL_STORE_QUERIES_API_KEYS_SQL'
-- name: CreateAPIKey :one
INSERT INTO api_keys (tenant_id, label, prefix, hash, role, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAPIKeyByPrefix :one
SELECT * FROM api_keys
WHERE prefix = $1 AND tenant_id = $2
LIMIT 1;

-- name: ListAPIKeys :many
SELECT id, tenant_id, label, prefix, role, expires_at, last_used, use_count, created_at
FROM api_keys
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2;

-- name: TouchAPIKey :exec
UPDATE api_keys
SET last_used = NOW(), use_count = use_count + 1
WHERE id = $1;
VSPPH1INTERNAL_STORE_QUERIES_API_KEYS_SQL

# internal/store/queries/audit.sql
mkdir -p "internal/store/queries"
cat > 'internal/store/queries/audit.sql' << 'VSPPH1INTERNAL_STORE_QUERIES_AUDIT_SQL'
-- name: InsertAudit :one
INSERT INTO audit_log (tenant_id, user_id, action, resource, ip, payload, hash, prev_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING seq, hash;

-- name: ListAuditByTenant :many
SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
FROM audit_log
WHERE tenant_id = $1
ORDER BY seq ASC;

-- name: GetLastAuditHash :one
SELECT hash FROM audit_log
WHERE tenant_id = $1
ORDER BY seq DESC
LIMIT 1;

-- name: ListAuditPaged :many
SELECT seq, tenant_id, user_id, action, resource, ip, hash, prev_hash, created_at
FROM audit_log
WHERE tenant_id = $1
  AND ($2::text = '' OR action = $2)
ORDER BY seq DESC
LIMIT $3 OFFSET $4;

-- name: CountAudit :one
SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1;
VSPPH1INTERNAL_STORE_QUERIES_AUDIT_SQL

# internal/store/queries/runs.sql
mkdir -p "internal/store/queries"
cat > 'internal/store/queries/runs.sql' << 'VSPPH1INTERNAL_STORE_QUERIES_RUNS_SQL'
-- name: CreateRun :one
INSERT INTO runs (rid, tenant_id, mode, profile, src, target_url, tools_total)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetRunByRID :one
SELECT * FROM runs WHERE rid = $1 AND tenant_id = $2 LIMIT 1;

-- name: GetLatestRun :one
SELECT * FROM runs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: ListRuns :many
SELECT * FROM runs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateRunStatus :exec
UPDATE runs
SET status = $3, tools_done = $4, started_at = CASE WHEN $3 = 'RUNNING' THEN NOW() ELSE started_at END,
    finished_at = CASE WHEN $3 IN ('DONE','FAILED','CANCELLED') THEN NOW() ELSE finished_at END
WHERE rid = $1 AND tenant_id = $2;

-- name: UpdateRunResult :exec
UPDATE runs
SET status = 'DONE', gate = $3, posture = $4,
    total_findings = $5, summary = $6,
    tools_done = tools_total, finished_at = NOW()
WHERE rid = $1 AND tenant_id = $2;

-- name: CancelRun :exec
UPDATE runs
SET status = 'CANCELLED', finished_at = NOW()
WHERE rid = $1 AND tenant_id = $2 AND status IN ('QUEUED','RUNNING');
VSPPH1INTERNAL_STORE_QUERIES_RUNS_SQL

# internal/store/queries/users.sql
mkdir -p "internal/store/queries"
cat > 'internal/store/queries/users.sql' << 'VSPPH1INTERNAL_STORE_QUERIES_USERS_SQL'
-- name: GetUserByEmail :one
SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
FROM users
WHERE tenant_id = $1 AND email = $2
LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (tenant_id, email, pw_hash, role)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login;

-- name: ListUsers :many
SELECT id, tenant_id, email, role, mfa_enabled, created_at, last_login
FROM users
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE tenant_id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1 AND tenant_id = $2;

-- name: UpdateLastLogin :exec
UPDATE users SET last_login = NOW() WHERE id = $1;

-- name: GetUserByID :one
SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
FROM users
WHERE id = $1 AND tenant_id = $2
LIMIT 1;
VSPPH1INTERNAL_STORE_QUERIES_USERS_SQL

# internal/store/runs.go
mkdir -p "internal/store"
cat > 'internal/store/runs.go' << 'VSPPH1INTERNAL_STORE_RUNS_GO'
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Run struct {
	ID            string          `json:"id"`
	RID           string          `json:"rid"`
	TenantID      string          `json:"tenant_id"`
	Mode          string          `json:"mode"`
	Profile       string          `json:"profile"`
	Src           string          `json:"src"`
	TargetURL     string          `json:"target_url"`
	Status        string          `json:"status"`
	Gate          string          `json:"gate"`
	Posture       string          `json:"posture"`
	ToolsDone     int             `json:"tools_done"`
	ToolsTotal    int             `json:"tools_total"`
	TotalFindings int             `json:"total_findings"`
	Summary       json.RawMessage `json:"summary"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
	CreatedAt     time.Time       `json:"created_at"`
}

func (db *DB) CreateRun(ctx context.Context, rid, tenantID, mode, profile, src, targetURL string, toolsTotal int) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO runs (rid, tenant_id, mode, profile, src, target_url, tools_total)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id, rid, tenant_id, mode, profile, src, target_url, status,
		           gate, posture, tools_done, tools_total, total_findings,
		           summary, started_at, finished_at, created_at`,
		rid, tenantID, mode, profile, src, targetURL, toolsTotal)
	return scanRun(row)
}

func (db *DB) GetRunByRID(ctx context.Context, tenantID, rid string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, rid, tenant_id, mode, profile, src, target_url, status,
		        gate, posture, tools_done, tools_total, total_findings,
		        summary, started_at, finished_at, created_at
		 FROM runs WHERE rid = $1 AND tenant_id = $2 LIMIT 1`,
		rid, tenantID)
	return scanRun(row)
}

func (db *DB) GetLatestRun(ctx context.Context, tenantID string) (*Run, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, rid, tenant_id, mode, profile, src, target_url, status,
		        gate, posture, tools_done, tools_total, total_findings,
		        summary, started_at, finished_at, created_at
		 FROM runs WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT 1`,
		tenantID)
	return scanRun(row)
}

func (db *DB) ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]Run, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, rid, tenant_id, mode, profile, src, target_url, status,
		        gate, posture, tools_done, tools_total, total_findings,
		        summary, started_at, finished_at, created_at
		 FROM runs WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, *r)
	}
	return runs, nil
}

func (db *DB) UpdateRunStatus(ctx context.Context, tenantID, rid, status string, toolsDone int) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs SET status=$3, tools_done=$4,
		  started_at  = CASE WHEN $3='RUNNING' AND started_at IS NULL THEN NOW() ELSE started_at END,
		  finished_at = CASE WHEN $3 IN ('DONE','FAILED','CANCELLED') THEN NOW() ELSE finished_at END
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, status, toolsDone)
	return err
}

func (db *DB) UpdateRunResult(ctx context.Context, tenantID, rid, gate, posture string, total int, summary json.RawMessage) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE runs
		 SET status='DONE', gate=$3, posture=$4, total_findings=$5,
		     summary=$6, tools_done=tools_total, finished_at=NOW()
		 WHERE rid=$1 AND tenant_id=$2`,
		rid, tenantID, gate, posture, total, summary)
	return err
}

func scanRun(row scanner) (*Run, error) {
	var r Run
	err := row.Scan(
		&r.ID, &r.RID, &r.TenantID, &r.Mode, &r.Profile,
		&r.Src, &r.TargetURL, &r.Status, &r.Gate, &r.Posture,
		&r.ToolsDone, &r.ToolsTotal, &r.TotalFindings,
		&r.Summary, &r.StartedAt, &r.FinishedAt, &r.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan run: %w", err)
	}
	return &r, nil
}
VSPPH1INTERNAL_STORE_RUNS_GO

# internal/store/users.go
mkdir -p "internal/store"
cat > 'internal/store/users.go' << 'VSPPH1INTERNAL_STORE_USERS_GO'
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── User model ───────────────────────────────────────────────────────────────

type User struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Email      string     `json:"email"`
	PwHash     string     `json:"-"`
	Role       string     `json:"role"`
	MFAEnabled bool       `json:"mfa_enabled"`
	CreatedAt  time.Time  `json:"created_at"`
	LastLogin  *time.Time `json:"last_login"`
}

func (db *DB) GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
		 FROM users WHERE tenant_id = $1 AND email = $2 LIMIT 1`,
		tenantID, email)
	return scanUser(row)
}

func (db *DB) GetUserByID(ctx context.Context, tenantID, id string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
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
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
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

// scanUser works for both pgx.Row and pgx.Rows
type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.PwHash,
		&u.Role, &u.MFAEnabled, &u.CreatedAt, &u.LastLogin)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}
VSPPH1INTERNAL_STORE_USERS_GO

# sqlc.yaml
cat > 'sqlc.yaml' << 'VSPPH1SQLC_YAML'
version: "2"
sql:
  - engine: "postgresql"
    queries: "internal/store/queries/"
    schema:  "migrations/"
    gen:
      go:
        package:        "store"
        out:            "internal/store"
        emit_json_tags: true
        emit_db_tags:   true
        emit_pointers_for_null_types: true
VSPPH1SQLC_YAML

echo ">>> go mod tidy..."
go mod tidy

echo ">>> Building gateway..."
go build -buildvcs=false -o gateway ./cmd/gateway/
echo ""
echo "================================================================"
echo "  Phase 1 complete!"
echo "  Restart: pkill gateway 2>/dev/null; ./gateway"
echo "  Then seed admin: go run ./cmd/seed/"
echo "  Then test: curl -X POST http://localhost:8920/api/v1/auth/login"
echo "             -H Content-Type:application/json"
echo "             -d {email:admin@vsp.local,password:admin123}"
echo "================================================================"

# cmd/seed/main.go
mkdir -p "cmd/seed"
cat > 'cmd/seed/main.go' << 'VSPPH1CMDSEED'
// cmd/seed creates a default admin user for development.
// Usage: go run ./cmd/seed/
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.AutomaticEnv()

	dsn := viper.GetString("database.url")
	ctx := context.Background()

	db, err := store.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Get default tenant
	var tenantID string
	db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&tenantID)
	if tenantID == "" {
		fmt.Fprintln(os.Stderr, "default tenant not found — run: make migrate-up")
		os.Exit(1)
	}

	// Users to seed
	seeds := []struct{ email, password, role string }{
		{"admin@vsp.local",   "admin123",   "admin"},
		{"analyst@vsp.local", "analyst123", "analyst"},
		{"dev@vsp.local",     "dev123",     "dev"},
		{"auditor@vsp.local", "auditor123", "auditor"},
	}

	for _, s := range seeds {
		hash, _ := bcrypt.GenerateFromPassword([]byte(s.password), bcrypt.DefaultCost)
		_, err := db.Pool().Exec(ctx,
			`INSERT INTO users (tenant_id, email, pw_hash, role)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, email) DO UPDATE SET pw_hash = $3, role = $4`,
			tenantID, s.email, string(hash), s.role)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seed %s: %v\n", s.email, err)
		} else {
			fmt.Printf("✓ %s  [%s]  pass: %s\n", s.email, s.role, s.password)
		}
	}
	fmt.Println("\nDone. Login: POST /api/v1/auth/login")
}
VSPPH1CMDSEED

echo ">>> Seeding admin users..."
go run -buildvcs=false ./cmd/seed/
