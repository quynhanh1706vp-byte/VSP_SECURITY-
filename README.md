# VSP Security Platform

**Enterprise-grade vulnerability scanning and security operations platform.**

[![CI](https://github.com/vsp/platform/actions/workflows/ci.yml/badge.svg)](https://github.com/vsp/platform/actions)
[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

---

## Overview

VSP (Vulnerability Scanning Platform) is a comprehensive security platform providing:

- **Multi-tool SAST/DAST/SCA scanning** — Bandit, Trivy, Gitleaks, Semgrep, Checkov, KICS, Grype, Nuclei, Nikto, CodeQL
- **Real-time SIEM** — Log ingestion, correlation engine, incident management
- **SOAR** — Automated playbook execution, webhook integrations
- **Compliance** — FedRAMP, CMMC, OSCAL AR/POAM generation
- **Governance** — Risk register, RACI, traceability matrix, zero trust scorecard
- **UEBA** — User and entity behavior analytics, anomaly detection

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     VSP Gateway :8921                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐   │
│  │   Auth   │  │   SIEM   │  │ Pipeline │  │Compliance │   │
│  │  JWT/MFA │  │Correlator│  │ Scanners │  │  OSCAL    │   │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘   │
│         │            │              │               │        │
│  ┌──────▼────────────▼──────────────▼───────────────▼────┐  │
│  │              PostgreSQL + Redis                        │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Go 1.25+
- PostgreSQL 16+
- Redis 7+

### Development

```bash
# Clone and setup
git clone https://github.com/vsp/platform
cd platform
cp .env.example .env
# Edit .env — set JWT_SECRET, POSTGRES_PASSWORD, REDIS_PASSWORD

# Run with make
make run

# Or directly
export JWT_SECRET=$(openssl rand -hex 32)
go run ./cmd/gateway
```

### Docker

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f gateway
```

### API

```bash
# Login
curl -X POST http://localhost:8921/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vsp.local","password":"admin123"}'

# Health check
curl http://localhost:8921/health

# Trigger scan
curl -X POST http://localhost:8921/api/v1/vsp/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"FULL","src":"/path/to/code"}'
```

Full API documentation: see `api/openapi.yaml` or `GET /api/docs`

## Development

### Commands

```bash
make test              # Run unit tests
make test-all          # Run all tests
make test-integration  # Integration tests (requires DB)
make test-coverage     # Tests with HTML coverage report
make test-load         # k6 load test (requires k6)
make lint              # go vet + staticcheck
make vuln              # govulncheck
make build             # Build binary
make docker-build      # Build Docker image
make docker-up         # Start with docker-compose
```

### Testing

```bash
# Unit tests (no dependencies needed)
go test ./internal/auth/... ./internal/gate/... -v

# All tests
go test ./...

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Project Structure

```
.
├── cmd/
│   ├── gateway/        # Main API server
│   └── scanner/        # Scanner worker
├── internal/
│   ├── api/
│   │   ├── handler/    # HTTP handlers
│   │   └── middleware/ # CSP, logging, rate limit
│   ├── auth/           # JWT, MFA/TOTP, blacklist
│   ├── audit/          # Immutable audit log chain
│   ├── cache/          # Redis API cache
│   ├── compliance/     # OSCAL AR/POAM generation
│   ├── gate/           # Security gate evaluation
│   ├── governance/     # Risk register, RACI, scorecard
│   ├── migrate/        # Database migrations (goose)
│   ├── pipeline/       # Scan pipeline orchestration
│   ├── report/         # SARIF, PDF, HTML reports
│   ├── safe/           # Panic-recovering goroutine wrapper
│   ├── scanner/        # Scanner adapters (10 tools)
│   ├── siem/           # SIEM, correlator, UEBA, SOAR
│   └── store/          # PostgreSQL data layer
├── api/
│   └── openapi.yaml    # OpenAPI 3.0 specification
├── config/
│   ├── config.yaml     # Application config
│   └── prometheus_rules.yml  # Alert rules
├── migrations/         # Legacy SQL migrations
├── tests/
│   └── load/           # k6 load test scripts
├── static/             # Frontend SPA
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## Security

- JWT authentication with configurable TTL
- TOTP-based MFA (Google Authenticator compatible)
- Per-user rate limiting (300 req/min after auth)
- CSP nonce-based Content Security Policy
- Refresh token rotation with reuse detection
- Password history (prevent reuse of last 5 passwords)
- Account lockout after 5 failed attempts

## Database Migrations

Migrations run automatically on startup via [goose](https://github.com/pressly/goose):

```
001_init.sql              — Core tables
002_remediations_unique   — Remediation constraints  
003_mfa.sql               — MFA columns
004_password_and_refresh  — Password history + refresh tokens
005_siem_indexes.sql      — SIEM performance indexes
```

## Monitoring

- **Metrics**: `GET /metrics` (Prometheus format)
- **Health**: `GET /health` (DB ping, Redis ping, uptime)
- **Alert rules**: `config/prometheus_rules.yml`

Key metrics:
- `vsp_scans_total` — Scan count by mode/status
- `vsp_findings_current` — Current findings by severity
- `vsp_gate_decisions_total` — Gate pass/warn/fail rate
- `vsp_login_attempts_total` — Auth attempts (brute force detection)
- `vsp_cache_hits_total` — Redis cache hit rate
- `vsp_db_pool_connections` — Connection pool health

## License

Proprietary — VSP Security Team. All rights reserved.
