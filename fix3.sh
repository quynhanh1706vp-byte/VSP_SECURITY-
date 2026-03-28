#!/usr/bin/env bash
# fix3.sh — wire asynq client vào gateway với Redis password
# Chay tu ~/Data/GOLANG_VSP
set -e

pkill scanner 2>/dev/null; pkill gateway 2>/dev/null; sleep 1

# Patch cmd/gateway/main.go — add asynq client wired to Runs handler
python3 << 'PYEOF'
content = open("cmd/gateway/main.go").read()

# 1. Add asynq import
if '"github.com/hibiken/asynq"' not in content:
    content = content.replace(
        '"golang.org/x/crypto/bcrypt"',
        '"golang.org/x/crypto/bcrypt"\n\t"github.com/hibiken/asynq"'
    )

# 2. Add asynq client creation after jwtTTL block
old = '\tauthH     := &handler.Auth{'
new = '''\t// Asynq client — wired to Runs handler for scan job enqueue
\tasynqClient := asynq.NewClient(asynq.RedisClientOpt{
\t\tAddr:     viper.GetString("redis.addr"),
\t\tPassword: viper.GetString("redis.password"),
\t})
\tdefer asynqClient.Close()

\tauthH     := &handler.Auth{'''
content = content.replace(old, new)

# 3. Wire asynq into runsH after it's created
old = '\trunsH     := &handler.Runs{DB: db}'
new = '\trunsH     := &handler.Runs{DB: db}\n\trunsH.SetAsynqClient(asynqClient)'
content = content.replace(old, new)

open("cmd/gateway/main.go", "w").write(content)

# Check
if 'asynqClient' in content and 'SetAsynqClient' in content:
    print("✓ gateway patched")
else:
    print("ERROR: patch may have failed")
    print("asynqClient:", 'asynqClient' in content)
    print("SetAsynqClient:", 'SetAsynqClient' in content)
PYEOF

echo ">>> Rebuilding gateway + scanner..."
go build -buildvcs=false -o gateway ./cmd/gateway/
go build -buildvcs=false -o scanner ./cmd/scanner/
echo "✓ Built"

echo ">>> Starting services..."
./gateway &
sleep 1
./scanner &
sleep 2

echo ">>> Getting token..."
export TOKEN=$(curl -s -X POST http://localhost:8921/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@vsp.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token OK"

echo ""
echo ">>> Trigger SECRETS scan on /home/test/Data/GOLANG_VSP..."
RID=$(curl -s -X POST http://localhost:8921/api/v1/vsp/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"SECRETS","src":"/home/test/Data/GOLANG_VSP"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('rid','ERROR:'+str(d)))")
echo "RID: $RID"

echo ">>> Waiting 15s for scanner to complete..."
sleep 15

echo ""
echo ">>> Poll run status:"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8921/api/v1/vsp/run/$RID" | python3 -m json.tool

echo ""
echo ">>> Findings summary:"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8921/api/v1/vsp/findings/summary" | python3 -m json.tool

echo ""
echo ">>> Policy evaluate:"
curl -s -X POST http://localhost:8921/api/v1/policy/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"repo":"vsp","rid":"'"$RID"'"}' | python3 -m json.tool

echo ""
echo "================================================================"
echo "  fix3.sh complete"
echo "  Dashboard: http://localhost:8922"
echo "================================================================"
