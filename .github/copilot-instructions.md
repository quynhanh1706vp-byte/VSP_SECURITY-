# VSP Platform — AI Coding Assistant Instructions

## Architecture Overview
VSP is a multi-microservice security scanning platform built in Go 1.25+ with CGO enabled for packet capture. The **gateway** (`cmd/gateway/`) serves as the central API hub, integrating 20+ scanner tools (SAST/SCA/DAST/network) via async queues (asynq/Redis). Data flows: Postgres for persistence, Redis for caching/queues, Prometheus for metrics. Frontend is static HTML/JS panels served from `static/`. Microservices communicate via HTTP APIs and shared database.

Key components:
- `internal/scanner/`: Tool adapters (e.g., `gosec/`, `trivy/`) normalize outputs to `scanner.Finding` with `SourceCategory` (DAST/SAST/SCA/SECRETS/IAC/NETWORK)
- `internal/api/`: Chi router handlers with JWT auth middleware
- `internal/store/`: Pgx database layer with migrations via goose
- Phases: Incremental feature rollouts via `.sh` scripts (e.g., `phase1_final.sh` wires tools to UI)

## Critical Workflows
- **Build**: `make build` (CGO=1 for gopacket), `docker build` (requires NET_RAW/NET_ADMIN caps)
- **Run**: `JWT_SECRET=... ./vsp-gateway` or `make run`
- **Dev**: `air` for hot reload (install via `go install github.com/cosmtrek/air@latest`)
- **Test**: `make test` (unit), `make test-integration` (requires TEST_DATABASE_URL), `make test-load` (k6)
- **Deploy**: Phase scripts (e.g., `install_vsp_pro.sh`) install tools, copy JS patches to `static/`, restart services
- **Migrate**: `go run cmd/migrate/` or `make migrate-status` (goose)
- **Dev Stub**: `go build -tags devstub ./cmd/dev-stub` for development with stub handlers (returns JSON placeholders for unimplemented endpoints)

## Project Conventions
- **Branching**: `type/scope-short-description` (e.g., `feat/siem-playbook-triggers`, `fix/gosec-annotations`)
- **Commits**: Conventional (e.g., `fix(gosec): close 21 HIGH/MED findings via annotation\n\nSprint 3 PR #D. Applies //#nosec at each site.\nRefs: SD-0042`)
- **Pre-commit**: `gofmt`, `go vet`, `gitleaks` (fails if secrets detected)
- **Code Style**: `golangci-lint run`, inline `//nosec` for gosec suppressions with rationale
- **Security Review**: 2-person for `internal/auth/`, `internal/crypto/`, `internal/api/middleware/`
- **Tool Adapters**: Implement `scanner.RunOpts → []scanner.Finding`, normalize severity via `NormaliseSeverity()`, handle JSON parsing robustly
- **Error Handling**: Non-zero tool exits ≠ errors (findings expected); use `scanner.Run()` which distinguishes fatal vs. finding exits
- **Config**: Viper for env vars (e.g., `JWT_SECRET`, `DATABASE_URL`)
- **Logging**: Zerolog structured logs (e.g., `log.Info().Str("tool", "gosec").Int("findings", len(findings)).Msg("scan complete")`)

## Integration Points
- **External Tools**: 20+ CLI scanners (gosec, trivy, nuclei, etc.) — install via `go install` or apt/yum
- **Queues**: Asynq for async scans (e.g., `scheduler.EnqueueScan()`)
- **Frontend**: Patch `static/index.html` with `<script src="/static/vsp_*.js"></script>` for new features
- **Compliance**: OSCAL exports, POA&M management, FedRAMP/Zero Trust dashboards
- **AI Features**: `internal/llm/` for analyst chat, `internal/agentic/` for automated workflows

## Common Patterns
- Handlers use `jsonError(w, msg, status)` for errors, `decodeJSON(w, r, &req)` for parsing
- Database: Pgx with context for queries, migrations via goose
- Async: Asynq/Redis for queues (e.g., `scheduler.EnqueueScan()`)
- Frontend: Static HTML/JS in `static/`, patches via `<script src="/static/vsp_*.js"></script>`, UX via `inject_ux_v1.1.js` (toast notifications)
- Security: JWT auth, Viper config, Zerolog logging, `//nosec` for gosec suppressions

Reference: `CONTRIBUTING.md`, `FEATURE_INVENTORY.md`, `Makefile`</content>
<parameter name="filePath">/home/test/Data/GOLANG_VSP/.github/copilot-instructions.md