#!/usr/bin/env bash
# ================================================================
# fix_port.sh — đổi VSP Go gateway sang port 8921
# Chay tu ~/Data/GOLANG_VSP
# ================================================================
set -e

# 1. Đổi port trong config
sed -i 's/gateway_port: 8920/gateway_port: 8921/' config/config.yaml
grep "gateway_port" config/config.yaml

# 2. Rebuild với port mới
go build -buildvcs=false -o gateway ./cmd/gateway/
echo "✓ rebuilt"

# 3. Kill gateway cũ nếu còn
pkill -f "./gateway" 2>/dev/null || true
sleep 1

# 4. Start
./gateway &
sleep 2

# 5. Test
echo ""
echo ">>> Testing http://localhost:8921/health"
curl -s http://localhost:8921/health | python3 -m json.tool

echo ""
echo ">>> Testing login"
RESP=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vsp.local","password":"admin123"}')
echo "$RESP" | python3 -m json.tool

TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -n "$TOKEN" ]; then
  echo ""
  echo ">>> Token OK — testing GET /api/v1/admin/users"
  curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:8921/api/v1/admin/users | python3 -m json.tool
  echo ""
  echo "================================================================"
  echo "  SUCCESS! Gateway running on port 8921"
  echo "  Token: ${TOKEN:0:40}..."
  echo ""
  echo "  Dung token nay cho cac request tiep theo:"
  echo "  export TOKEN=\"$TOKEN\""
  echo "================================================================"
else
  echo "Login failed — check output above"
fi
