#!/bin/bash
set -e
cd ~/Data/GOLANG_VSP
go build -o ./gateway ./cmd/gateway/...
sudo setcap cap_net_raw+eip ./gateway
echo "Build OK + CAP_NET_RAW set"
sudo systemctl restart vsp-gateway
echo "Gateway restarted"
