#!/bin/bash
export VAULT_ADDR='http://127.0.0.1:8200'
if ! vault token lookup > /dev/null 2>&1; then
  echo "[vault-env] ERROR: not authenticated" >&2; exit 1
fi
secrets=$(vault kv get -format=json vsp/config 2>/dev/null) || { echo "[vault-env] ERROR: cannot read vsp/config" >&2; exit 1; }
export ANTHROPIC_API_KEY=$(echo "$secrets" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['anthropic_api_key'])")
export JWT_SECRET=$(echo "$secrets" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['jwt_secret'])")
export DATABASE_URL=$(echo "$secrets" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['database_url'])")
export REDIS_URL=$(echo "$secrets" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['redis_url'])")
export P4_API_KEY=$(echo "$secrets" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['p4_api_key'])")
export SERVER_ENV=$(echo "$secrets" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['server_env'])")
echo "[vault-env] ✓ Secrets loaded from Vault vsp/config"
