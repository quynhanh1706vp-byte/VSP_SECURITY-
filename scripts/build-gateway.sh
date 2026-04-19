#!/bin/bash
# Build VSP gateway binary + apply network capabilities.
#
# Deploy notes:
#   - Requires sudo access (NOPASSWD preferred for CI/CD)
#   - setcap survives file move/chmod but NOT:
#       * File overwrite (rebuild must re-apply)
#       * strip/patch binary
#       * Filesystems without xattr support (some tmpfs variants)
#   - Verify caps after build: getcap ./bin/vsp-gateway
#   - Alternative: run binary as root inside container with CAP_NET_RAW

set -e
cd "$(dirname "$0")/.."
go build -o ./bin/vsp-gateway ./cmd/gateway
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/vsp-gateway
echo "✓ Built + setcap done"
getcap ./bin/vsp-gateway
