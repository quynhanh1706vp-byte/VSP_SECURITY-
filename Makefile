.PHONY: build test test-integration test-load lint clean run dev docker help

# Variables
BINARY    = vsp-gateway
CMD       = ./cmd/gateway
JWT_SECRET ?= $(shell cat .env 2>/dev/null | grep JWT_SECRET | cut -d= -f2)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build binary
	go build -ldflags="-w -s" -o $(BINARY) $(CMD)

run: build ## Build and run server
	JWT_SECRET=$(JWT_SECRET) ./$(BINARY)

dev: ## Run with hot reload (requires air)
	air

test: ## Run unit tests
	go test ./internal/auth/... ./internal/gate/... ./internal/api/handler/... -count=1 -timeout=60s

test-all: ## Run all tests
	go test ./... -count=1 -timeout=60s

test-integration: ## Run integration tests (requires TEST_DATABASE_URL)
	go test ./internal/integration/... -tags=integration -count=1 -timeout=120s -v

test-coverage: ## Run tests with coverage
	go test ./... -coverprofile=coverage.out -timeout=60s
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-load: ## Run k6 load test (requires k6)
	k6 run tests/load/k6_basic.js

test-spike: ## Run k6 spike test (requires k6)
	k6 run tests/load/k6_spike.js

lint: ## Run linters
	go vet ./...
	@which golangci-lint && golangci-lint run || echo "golangci-lint not installed"

vuln: ## Check vulnerabilities
	@which govulncheck && govulncheck ./... || go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...

migrate-status: ## Show migration status
	@echo "Current migration version:"
	@psql "$$DATABASE_URL" -c "SELECT version_id, is_applied, tstamp FROM goose_db_version ORDER BY id DESC LIMIT 5" 2>/dev/null || echo "Set DATABASE_URL first"

docker-build: ## Build Docker image
	docker build -t vsp-platform:latest .

docker-up: ## Start all services with docker-compose
	docker-compose up -d

docker-down: ## Stop all services
	docker-compose down

docker-logs: ## Show container logs
	docker-compose logs -f gateway

clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out coverage.html

fmt: ## Format code
	gofmt -w .

tidy: ## Tidy go modules
	go mod tidy
