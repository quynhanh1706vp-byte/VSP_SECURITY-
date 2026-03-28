#!/usr/bin/env bash
# ================================================================
# VSP Go — fix.sh  (chay tu ~/Data/GOLANG_VSP)
# Fix: goose, git init, VCS, cmd/gateway, docker postgres
# ================================================================
set -e
ROOT="$(pwd)"
echo ">>> Working in: $ROOT"

# ── 1. git init (fix VCS error) ──────────────────────────────────
if [ ! -d ".git" ]; then
  git init -q
  echo "✓ git init"
else
  echo "✓ git already exists"
fi

# ── 2. Install goose ─────────────────────────────────────────────
if ! command -v goose &>/dev/null; then
  echo ">>> Installing goose..."
  go install github.com/pressly/goose/v3/cmd/goose@latest
  # add GOPATH/bin to PATH for this session
  export PATH="$PATH:$(go env GOPATH)/bin"
  echo "✓ goose installed: $(goose --version)"
else
  echo "✓ goose already installed"
fi

# ── 3. Fix compose.dev.yml — remove version, add retry for postgres ──
cat > docker/compose.dev.yml << 'COMPOSE'
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
COMPOSE
echo "✓ compose.dev.yml updated (removed version:)"

# ── 4. Create cmd/gateway/main.go ────────────────────────────────
mkdir -p cmd/gateway
cat > cmd/gateway/main.go << 'GOEOF'
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
)

func main() {
	// ── Config ────────────────────────────────────────────────────
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetDefault("server.gateway_port", 8920)
	viper.SetDefault("log.level", "info")

	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("no config file — using defaults + env")
	}

	// ── Logger ────────────────────────────────────────────────────
	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	})

	// ── Router ────────────────────────────────────────────────────
	r := chi.NewRouter()

	// Standard middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check — always public
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"0.1.0","port":%d}`,
			viper.GetInt("server.gateway_port"))
	})

	// API v1 — authenticated routes (auth middleware added in Phase 1)
	r.Route("/api/v1", func(r chi.Router) {
		// Auth
		r.Post("/auth/login", handleNotImpl)
		r.Post("/auth/logout", handleNotImpl)
		r.Post("/auth/refresh", handleNotImpl)

		// Admin
		r.Route("/admin", func(r chi.Router) {
			r.Get("/users", handleNotImpl)
			r.Post("/users", handleNotImpl)
			r.Delete("/users/{id}", handleNotImpl)
			r.Get("/api-keys", handleNotImpl)
			r.Post("/api-keys", handleNotImpl)
			r.Delete("/api-keys/{id}", handleNotImpl)
			r.Get("/tenants", handleNotImpl)
			r.Post("/tenants", handleNotImpl)
		})

		// Scan / Pipeline
		r.Route("/vsp", func(r chi.Router) {
			r.Post("/run", handleNotImpl)
			r.Post("/run/{rid}/cancel", handleNotImpl)
			r.Get("/run/latest", handleNotImpl)
			r.Get("/run/{rid}", handleNotImpl)
			r.Get("/runs", handleNotImpl)
			r.Get("/runs/index", handleNotImpl)
			r.Get("/findings", handleNotImpl)
			r.Get("/findings/summary", handleNotImpl)
			r.Get("/gate/latest", handleNotImpl)
			r.Get("/posture/latest", handleNotImpl)
		})

		// Policy
		r.Post("/policy/evaluate", handleNotImpl)
		r.Get("/policy/rules", handleNotImpl)
		r.Post("/policy/rules", handleNotImpl)
		r.Delete("/policy/rules/{id}", handleNotImpl)

		// Audit
		r.Get("/audit/log", handleNotImpl)
		r.Post("/audit/verify", handleNotImpl)

		// SIEM
		r.Get("/siem/webhooks", handleNotImpl)
		r.Post("/siem/webhooks", handleNotImpl)
		r.Delete("/siem/webhooks/{id}", handleNotImpl)
		r.Post("/siem/webhooks/{id}/test", handleNotImpl)

		// Compliance
		r.Get("/compliance/oscal/ar", handleNotImpl)
		r.Get("/compliance/oscal/poam", handleNotImpl)

		// Governance
		r.Get("/governance/risk-register", handleNotImpl)
		r.Get("/governance/ownership", handleNotImpl)
		r.Get("/governance/evidence", handleNotImpl)
		r.Post("/governance/evidence/{id}/freeze", handleNotImpl)
		r.Get("/governance/effectiveness", handleNotImpl)
		r.Get("/governance/traceability", handleNotImpl)
		r.Get("/governance/raci", handleNotImpl)
		r.Get("/governance/rule-overrides", handleNotImpl)

		// SOC
		r.Get("/soc/detection", handleNotImpl)
		r.Get("/soc/incidents", handleNotImpl)
		r.Get("/soc/supply-chain", handleNotImpl)
		r.Get("/soc/release-governance", handleNotImpl)
		r.Get("/soc/framework-scorecard", handleNotImpl)
		r.Get("/soc/roadmap", handleNotImpl)
		r.Get("/soc/zero-trust", handleNotImpl)
	})

	// ── Server ────────────────────────────────────────────────────
	addr := fmt.Sprintf(":%d", viper.GetInt("server.gateway_port"))
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Print registered routes for dev convenience
	log.Info().
		Str("addr", addr).
		Int("routes", countRoutes(r)).
		Msg("VSP Gateway starting")

	// ── Graceful shutdown ─────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	log.Info().Msgf("VSP Gateway listening on http://localhost%s", addr)
	log.Info().Msg("Press Ctrl+C to stop")

	<-quit
	log.Info().Msg("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("graceful shutdown failed")
	}
	log.Info().Msg("server stopped")
}

// handleNotImpl returns 501 with a JSON body listing the endpoint.
// All handlers start here and get replaced incrementally.
func handleNotImpl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, `{"error":"not implemented","path":%q,"method":%q}`,
		r.URL.Path, r.Method)
}

func countRoutes(r *chi.Mux) int {
	count := 0
	chi.Walk(r, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		count++
		return nil
	})
	return count
}
GOEOF
echo "✓ cmd/gateway/main.go created"

# ── 5. Create cmd/soc-shell/main.go ──────────────────────────────
mkdir -p cmd/soc-shell
cat > cmd/soc-shell/main.go << 'GOEOF'
package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func main() {
	viper.SetDefault("server.shell_port", 8922)
	viper.SetDefault("server.gateway_port", 8920)
	viper.SetDefault("log.level", "info")
	viper.AutomaticEnv()

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	shellPort   := viper.GetInt("server.shell_port")
	gatewayPort := viper.GetInt("server.gateway_port")

	// Proxy /api/* → gateway
	gatewayURL, _ := url.Parse(fmt.Sprintf("http://localhost:%d", gatewayPort))
	proxy := httputil.NewSingleHostReverseProxy(gatewayURL)

	mux := http.NewServeMux()

	// Proxy all /api/ calls to gateway
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	// Serve static files from ./static/
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	addr := fmt.Sprintf(":%d", shellPort)
	log.Info().
		Str("addr", addr).
		Int("gateway", gatewayPort).
		Msg("VSP SOC Shell starting")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal().Err(err).Msg("shell server error")
	}
}
GOEOF
echo "✓ cmd/soc-shell/main.go created"

# ── 6. Add TimeoutOrDefault to runner.go ─────────────────────────
# pipeline.go calls opts.TimeoutOrDefault() — add it to RunOpts
if ! grep -q "TimeoutOrDefault" internal/scanner/runner.go; then
  # append method after the closing brace of RunOpts struct
  python3 << 'PYEOF'
import re

with open("internal/scanner/runner.go", "r") as f:
    content = f.read()

# Add TimeoutOrDefault method after RunOpts struct
insert = '''
// TimeoutOrDefault returns timeout duration, defaulting to 300s.
func (o RunOpts) TimeoutOrDefault() time.Duration {
\tif o.TimeoutSec > 0 {
\t\treturn time.Duration(o.TimeoutSec) * time.Second
\t}
\treturn 300 * time.Second
}
'''

# insert before the Runner interface comment
content = content.replace(
    '// Runner is implemented by each tool adapter',
    insert + '\n// Runner is implemented by each tool adapter'
)

with open("internal/scanner/runner.go", "w") as f:
    f.write(content)
print("  patched runner.go: added TimeoutOrDefault()")
PYEOF
else
  echo "✓ TimeoutOrDefault already present"
fi

# ── 7. go mod tidy again after new files ─────────────────────────
echo ">>> go mod tidy..."
go mod tidy
echo "✓ go mod tidy done"

# ── 8. Build (with -buildvcs=false to bypass git issue) ──────────
echo ">>> Building..."
go build -buildvcs=false ./cmd/gateway/...
go build -buildvcs=false ./cmd/scanner/...
go build -buildvcs=false ./cmd/soc-shell/...
echo "✓ Build successful"
ls -lh gateway scanner soc-shell 2>/dev/null || ls -lh ./gateway ./scanner ./soc-shell 2>/dev/null || true

# ── 9. Fix Makefile — add -buildvcs=false ────────────────────────
sed -i 's/go build \.\//go build -buildvcs=false .\//g' Makefile
echo "✓ Makefile patched"

echo ""
echo "================================================================"
echo "  Fix complete!"
echo ""
echo "  Start postgres (neu chua co docker):"
echo "    docker compose -f docker/compose.dev.yml up -d"
echo "    # hoac dung postgres local o port 5432"
echo ""
echo "  Install goose va chay migration:"
echo "    export PATH=\$PATH:\$(go env GOPATH)/bin"
echo "    export DATABASE_URL=postgres://vsp:vsp@localhost:5432/vsp_go"
echo "    goose -dir migrations postgres \"\$DATABASE_URL\" up"
echo ""
echo "  Chay gateway:"
echo "    ./gateway"
echo "    # test: curl http://localhost:8920/health"
echo "================================================================"
