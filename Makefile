.PHONY: build dev generate migrate-up migrate-down test test-integration lint docker-up docker-down

build:
	go build -buildvcs=false ./cmd/gateway/...
	go build -buildvcs=false ./cmd/scanner/...
	go build -buildvcs=false ./cmd/soc-shell/...

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
