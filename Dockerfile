# ── Stage 1: Build ───────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o vsp-gateway ./cmd/gateway

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/vsp-gateway /vsp-gateway
COPY --from=builder /app/config /config
COPY --from=builder /app/static /static
COPY --from=builder /app/migrations /migrations

ENV TZ=Asia/Ho_Chi_Minh
EXPOSE 8921
ENTRYPOINT ["/vsp-gateway"]
