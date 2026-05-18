#!/bin/bash
# Refresh test image lên ttl.sh (TTL 1h) và update cosign-api default
set -e
CRANE=/tmp/crane
if [ ! -f $CRANE ]; then
  curl -sL https://github.com/google/go-containerregistry/releases/download/v0.20.2/go-containerregistry_Linux_x86_64.tar.gz \
    | tar xz -C /tmp crane
fi
$CRANE cp alpine:3.19 ttl.sh/vsp-alpine:1h
DIGEST=$($CRANE digest ttl.sh/vsp-alpine:1h)
echo "Pushed: ttl.sh/vsp-alpine@$DIGEST"
# Sign ngay
COSIGN_PASSWORD="" cosign sign --key /etc/vsp/cosign.key \
  --tlog-upload=false --yes "ttl.sh/vsp-alpine@$DIGEST"
echo "Signed OK: ttl.sh/vsp-alpine@$DIGEST"

# Re-apply CAP_NET_RAW sau khi build gateway
if [ -f /home/test/Data/GOLANG_VSP/gateway ]; then
  sudo setcap cap_net_raw+eip /home/test/Data/GOLANG_VSP/gateway 2>/dev/null && \
    echo "CAP_NET_RAW set on gateway binary"
fi
