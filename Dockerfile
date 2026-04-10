FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata libpcap-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-w -s -extldflags=-static" \
    -trimpath -o vsp-gateway ./cmd/gateway

FROM scratch
LABEL org.opencontainers.image.title="VSP Gateway" \
      org.opencontainers.image.vendor="VSP Security Platform"
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/vsp-gateway /vsp-gateway
COPY --from=builder /app/config /config
COPY --from=builder /app/static /static
COPY --from=builder /app/migrations /migrations
# scratch không có USER command — binary chạy với UID từ runtime
# Set nonroot via docker run --user 65534:65534 hoặc K8s securityContext
EXPOSE 8921
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/vsp-gateway", "-healthcheck"]
ENTRYPOINT ["/vsp-gateway"]
