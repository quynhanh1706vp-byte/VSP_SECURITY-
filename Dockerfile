# syntax=docker/dockerfile:1.7
# VSP Gateway — requires CGO for gopacket/pcap (L2/L3/L4/L7 packet capture)
# Build: docker build -t vsp-gateway .
# Run:   docker run --cap-add=NET_RAW --cap-add=NET_ADMIN -p 8921:8921 vsp-gateway
#
# Why CGO is mandatory:
#   internal/netcap/engine.go imports github.com/google/gopacket/pcap
#   which links to libpcap via CGO. Building with CGO_ENABLED=0 causes
#   "undefined: pcapTPtr, pcapPkthdr ..." because pcap_unix.go has //go:build cgo.
#
# Why NET_RAW + NET_ADMIN:
#   gopacket/pcap uses AF_PACKET sockets (Linux) which need CAP_NET_RAW
#   for raw frame read and CAP_NET_ADMIN for promiscuous mode.

FROM golang:1.25-alpine3.22@sha256:ea77c38bc50df598f22ae02b729b9d37eb0d70ed72d6dd336b8d6c02ae2b8b09 AS builder

# Build deps:
#   git          — go mod download via git
#   gcc musl-dev — CGO compiler (Alpine uses musl, not glibc)
#   libpcap-dev  — headers for gopacket/pcap
#   ca-certificates tzdata — copied into final image
RUN apk add --no-cache \
      git \
      gcc \
      musl-dev \
      libpcap-dev \
      ca-certificates \
      tzdata

WORKDIR /app

# Layer cache: deps before source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=1: link with libpcap
# Dropped -extldflags=-static because libpcap cannot be statically linked
# against musl without patching. Dynamic link is fine — we copy libpcap
# into the runtime image below.
# -trimpath: reproducible builds
# -ldflags="-w -s": strip debug info and symbol table (smaller binary)
RUN CGO_ENABLED=1 GOOS=linux \
    go build \
      -ldflags="-w -s" \
      -trimpath \
      -o vsp-gateway \
      ./cmd/gateway

# Sanity check — fail fast if libpcap linkage is broken.
# (Using `|| true` on grep so the RUN exits 0 when linkage is correct.)
RUN ldd /app/vsp-gateway | grep -q libpcap \
    || (echo "ERROR: vsp-gateway did not link libpcap — CGO build failed silently" && ldd /app/vsp-gateway && exit 1)

# ──────────────────────────────────────────────────────────────
# Runtime stage — alpine (not scratch) because we need libpcap.so
# alpine:3.20 adds ~7MB over scratch. Acceptable trade-off for dynamic linking.
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601

LABEL org.opencontainers.image.title="VSP Gateway" \
      org.opencontainers.image.vendor="VSP Security Platform" \
      org.opencontainers.image.source="https://github.com/quynhanh1706vp-byte/VSP_SECURITY-"

# Runtime deps only — no headers, no compilers
#   libpcap         — dynamic lib for gopacket
#   ca-certificates — TLS verification for outbound HTTPS
#   tzdata          — timezone data (scan report timestamps)
#   wget            — healthcheck against /health endpoint (5 KB, busybox applet)
RUN apk add --no-cache \
      libpcap \
      ca-certificates \
      tzdata \
      wget

COPY --from=builder /app/vsp-gateway /vsp-gateway
COPY --from=builder /app/config      /config
COPY --from=builder /app/static      /static
COPY --from=builder /app/migrations  /migrations

# Non-root by default. NET_RAW capability granted via docker run / K8s
# securityContext, not via setuid. See deploy notes at top.
USER nobody:nobody

EXPOSE 8921

# HTTP healthcheck against /health (handled at cmd/gateway/main.go:257).
# Docker-compose.yml overrides this with an identical command — this HEALTHCHECK
# is kept in the Dockerfile so `docker run` alone is correctly monitored.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8921/health || exit 1

ENTRYPOINT ["/vsp-gateway"]
