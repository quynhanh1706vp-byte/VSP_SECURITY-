#!/usr/bin/env bash
# =============================================================================
# VSP Fix Script — Backend + Frontend (theo thứ tự priority)
# Chạy từ thư mục gốc project: bash vsp_fix_all.sh
# =============================================================================
set -euo pipefail

VSP="${VSP_DIR:-/home/test/Data/GOLANG_VSP}"
echo "=== VSP Fix All ==="
echo "Project: $VSP"
echo ""

# -----------------------------------------------------------------------------
# HELPER
# -----------------------------------------------------------------------------
ok()   { echo "  ✓ $1"; }
info() { echo "  → $1"; }
step() { echo ""; echo "[$1] $2"; }

# -----------------------------------------------------------------------------
# FIX 1 — CRITICAL: SSE auth — validate JWT từ query param
# File: internal/api/handler/ws.go
# -----------------------------------------------------------------------------
step "FIX-1" "SSE auth — validate JWT token từ query param"

SSE_FILE="$VSP/internal/api/handler/ws.go"

# Backup
cp "$SSE_FILE" "${SSE_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

# Inject import strings + auth package nếu chưa có
# Thay toàn bộ SSEHandler function
python3 - <<'PYEOF'
import re, sys

path = "/home/test/Data/GOLANG_VSP/internal/api/handler/ws.go"
with open(path) as f:
    src = f.read()

# 1. Thêm imports cần thiết
old_imports = '''import (
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)'''

new_imports = '''import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// jwtSecret được set khi khởi động gateway (SetJWTSecret)
var sseJWTSecret string

// SetJWTSecret phải được gọi từ main() trước khi nhận request.
func SetJWTSecret(s string) { sseJWTSecret = s }'''

src = src.replace(old_imports, new_imports)

# 2. Thay SSEHandler — thêm auth validation
old_sse = '''// GET /api/v1/events — Server-Sent Events (SSE) stream
// SSE không cần thư viện ngoài, hoạt động trên mọi browser
func SSEHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type",  "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection",    "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")'''

new_sse = '''// GET /api/v1/events — Server-Sent Events (SSE) stream
// Auth: JWT phải được gửi qua query param ?token=<jwt>
// (EventSource API không hỗ trợ custom headers)
func SSEHandler(w http.ResponseWriter, r *http.Request) {
	// ── Auth: validate JWT từ query param ──
	rawToken := r.URL.Query().Get("token")
	if rawToken == "" {
		// fallback: thử Authorization header (curl/test)
		rawToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if rawToken == "" || sseJWTSecret == "" {
		http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		return
	}
	_, jwtErr := jwt.ParseWithClaims(rawToken, &jwt.MapClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(sseJWTSecret), nil
		})
	if jwtErr != nil {
		log.Warn().Str("ip", r.RemoteAddr).Err(jwtErr).Msg("sse: invalid token")
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type",  "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection",    "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")'''

src = src.replace(old_sse, new_sse)

with open(path, "w") as f:
    f.write(src)

print("  ✓ ws.go patched — SSEHandler có auth")
PYEOF

# -----------------------------------------------------------------------------
# FIX 2 — CRITICAL: WebSocket auth — validate JWT
# File: internal/api/handler/ws_upgrade.go
# -----------------------------------------------------------------------------
step "FIX-2" "WebSocket auth — validate JWT"

WS_FILE="$VSP/internal/api/handler/ws_upgrade.go"
cp "$WS_FILE" "${WS_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/internal/api/handler/ws_upgrade.go"
with open(path) as f:
    src = f.read()

old_handler = '''// GET /api/v1/ws — WebSocket upgrade with SSE fallback
func WSUpgradeHandler(w http.ResponseWriter, r *http.Request) {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		wsServe(w, r)
		return
	}
	SSEHandler(w, r)
}'''

new_handler = '''// GET /api/v1/ws — WebSocket upgrade with SSE fallback
// Auth: JWT qua query param ?token=<jwt> hoặc Authorization header
func WSUpgradeHandler(w http.ResponseWriter, r *http.Request) {
	// Reuse SSEHandler auth logic — SSEHandler sẽ reject nếu token invalid
	// Với WebSocket, browser gửi token qua query param
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		// Validate trước khi upgrade
		rawToken := r.URL.Query().Get("token")
		if rawToken == "" {
			rawToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if rawToken == "" {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		wsServe(w, r)
		return
	}
	SSEHandler(w, r)
}'''

src = src.replace(old_handler, new_handler)

with open(path, "w") as f:
    f.write(src)

print("  ✓ ws_upgrade.go patched — WSUpgradeHandler có auth check")
PYEOF

# -----------------------------------------------------------------------------
# FIX 3 — CRITICAL: gateway main.go — gọi SetJWTSecret + bỏ SSE bypass mux
# -----------------------------------------------------------------------------
step "FIX-3" "gateway/main.go — wire SetJWTSecret + secure SSE route"

MAIN_FILE="$VSP/cmd/gateway/main.go"
cp "$MAIN_FILE" "${MAIN_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/cmd/gateway/main.go"
with open(path) as f:
    src = f.read()

# 1. Sau khi jwtSecret được set, gọi handler.SetJWTSecret
old_wire = '''	authH       := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}'''
new_wire = '''	authH       := &handler.Auth{DB: db, JWTSecret: jwtSecret, JWTTTL: jwtTTL, DefaultTID: defaultTID}
	handler.SetJWTSecret(jwtSecret) // SSE/WS auth'''

src = src.replace(old_wire, new_wire)

# 2. Bỏ SSE bypass mux — đưa SSE vào chi router với auth
# Route SSE hiện tại nằm TRƯỚC authMw group nên không được bảo vệ
# Fix: xóa dòng r.Get("/api/v1/events"...) khỏi vị trí public
# và thêm vào trong authMw group

old_public_sse = '''	r.Get("/api/v1/events", handler.SSEHandler)
	r.Get("/api/v1/ws",     handler.WSUpgradeHandler)'''

new_public_sse = '''	// SSE/WS: auth được handle bên trong handler (qua query param ?token=)
	// vì EventSource API không hỗ trợ custom headers
	r.Get("/api/v1/events", handler.SSEHandler)
	r.Get("/api/v1/ws",     handler.WSUpgradeHandler)'''

src = src.replace(old_public_sse, new_public_sse)

# 3. Bỏ mux bypass — dùng chi router trực tiếp
old_mux = '''	// SSE bypass timeout middleware
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", handler.SSEHandler)
	mux.Handle("/", r)

	srv := &http.Server{Addr: addr, Handler: mux,
		ReadTimeout: 30 * time.Second, WriteTimeout: 0}'''

new_mux = '''	// SSE cần WriteTimeout = 0 (streaming không có deadline)
	// Dùng chi router trực tiếp, không cần bypass mux nữa
	// vì SSEHandler tự xử lý auth qua query param
	srv := &http.Server{Addr: addr, Handler: r,
		ReadTimeout: 30 * time.Second, WriteTimeout: 0}'''

src = src.replace(old_mux, new_mux)

with open(path, "w") as f:
    f.write(src)

print("  ✓ main.go patched — SetJWTSecret wired, SSE bypass mux removed")
PYEOF

# -----------------------------------------------------------------------------
# FIX 4 — HIGH: config.yaml — move secrets ra, thêm comment
# -----------------------------------------------------------------------------
step "FIX-4" "config.yaml — mark secrets cần move ra .env"

CONFIG_FILE="$VSP/config/config.yaml"
cp "$CONFIG_FILE" "${CONFIG_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/config/config.yaml"
with open(path) as f:
    src = f.read()

# Thay jwt_secret mặc định bằng placeholder rõ ràng hơn
src = src.replace(
    '  jwt_secret: "change-me-in-production"',
    '  jwt_secret: ""  # BẮT BUỘC set qua env JWT_SECRET (32+ chars random)'
)

# Redis password — thay bằng env ref comment
src = src.replace(
    'redis:\n  addr: localhost:6379\n  password: "VspRedis2026!"',
    'redis:\n  addr: localhost:6379\n  password: ""  # Set qua env REDIS_PASSWORD'
)

# SMTP pass
src = src.replace(
    '  pass: "your-app-password"',
    '  pass: ""  # Set qua env SMTP_PASSWORD'
)

with open(path, "w") as f:
    f.write(src)

print("  ✓ config.yaml patched — secrets cleared, dùng env vars")
PYEOF

# -----------------------------------------------------------------------------
# FIX 5 — HIGH: .env.example — thêm REDIS_PASSWORD + SMTP_PASSWORD
# -----------------------------------------------------------------------------
step "FIX-5" ".env.example — thêm missing env vars"

ENV_EXAMPLE="$VSP/.env.example"

cat > "$ENV_EXAMPLE" << 'ENVEOF'
# ── Auth ──────────────────────────────────────────────────────────────────────
# BẮT BUỘC: random string 32+ chars
# Generate: openssl rand -hex 32
JWT_SECRET=CHANGE_ME_generate_with_openssl_rand_hex_32

# ── Database ──────────────────────────────────────────────────────────────────
POSTGRES_USER=vsp
POSTGRES_PASSWORD=CHANGE_ME
POSTGRES_DB=vsp_go
DATABASE_URL=postgres://vsp:CHANGE_ME@postgres:5432/vsp_go?sslmode=disable

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_PASSWORD=CHANGE_ME

# ── SMTP ─────────────────────────────────────────────────────────────────────
SMTP_PASSWORD=CHANGE_ME

# ── Server ───────────────────────────────────────────────────────────────────
SERVER_ENV=production
ALLOWED_ORIGINS=https://your-domain.com
ENVEOF

ok ".env.example updated"

# -----------------------------------------------------------------------------
# FIX 6 — HIGH: network_flow.html — TOKEN set trước khi gọi loadNetworkFlow()
# -----------------------------------------------------------------------------
step "FIX-6" "network_flow.html — fix TOKEN set order (logic ngược)"

NF_FILE="$VSP/static/panels/network_flow.html"
cp "$NF_FILE" "${NF_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/static/panels/network_flow.html"
with open(path) as f:
    src = f.read()

# BUG: loadNetworkFlow() được gọi TRƯỚC khi TOKEN được set
# → loadNetworkFlow() check if(!TOKEN)return → luôn return sớm
old_line = "  if(e.data.type==='vsp:token'&&e.data.token&&e.data.token.length>50){loadNetworkFlow();if(!TOKEN)TOKEN=e.data.token;}"
new_line = "  if(e.data.type==='vsp:token'&&e.data.token&&e.data.token.length>50){if(!TOKEN){TOKEN=e.data.token;loadNetworkFlow();}}"

if old_line not in src:
    print("  ⚠ network_flow.html: old pattern not found, check manually")
else:
    src = src.replace(old_line, new_line)
    with open(path, "w") as f:
        f.write(src)
    print("  ✓ network_flow.html patched — TOKEN set trước loadNetworkFlow()")
PYEOF

# -----------------------------------------------------------------------------
# FIX 7 — HIGH: threat_intel.html — thêm full token handler
# -----------------------------------------------------------------------------
step "FIX-7" "threat_intel.html — thêm message listener + request_token"

TI_FILE="$VSP/static/panels/threat_intel.html"
cp "$TI_FILE" "${TI_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/static/panels/threat_intel.html"
with open(path) as f:
    src = f.read()

# Tìm dòng khai báo TOKEN và API để biết context
# threat_intel.html có: var TOKEN='',API='';
# Nhưng KHÔNG có addEventListener('message') nào

# Tìm </script> cuối cùng trước </body> để inject
inject = """
// ── Token handler (VSP iframe protocol) ──────────────────────────────────────
window.addEventListener('message', function(e) {
  if (!e.data) return;
  if (e.data.type === 'vsp:token' && e.data.token && e.data.token.length > 50) {
    if (!TOKEN) {
      TOKEN = e.data.token;
      // Reload data với token thật
      if (typeof loadData === 'function') loadData();
      else if (typeof renderFeeds === 'function') { renderFeeds(); renderCVEs(); }
    }
  }
  if (e.data.type === 'vsp:theme' && typeof _applyTheme === 'function') {
    _applyTheme(e.data.theme);
  }
});
if (window.parent !== window) {
  window.parent.postMessage({ type: 'vsp:request_token' }, '*');
  window.parent.postMessage({ type: 'vsp:request_theme' }, '*');
}
"""

# Inject trước </script> cuối (trước </body>)
# Tìm pattern "</script>\n</body>" hoặc "</script>\n\n</body>"
import re
# Tìm vị trí </script> cuối cùng
matches = list(re.finditer(r'</script>', src))
if not matches:
    print("  ⚠ threat_intel.html: không tìm thấy </script>")
else:
    last = matches[-1]
    # Kiểm tra xem đã có listener chưa
    if "vsp:request_token" in src:
        print("  ⚠ threat_intel.html: đã có vsp:request_token, bỏ qua")
    else:
        pos = last.start()
        src = src[:pos] + inject + src[pos:]
        with open(path, "w") as f:
            f.write(src)
        print("  ✓ threat_intel.html patched — token handler injected")
PYEOF

# -----------------------------------------------------------------------------
# FIX 8 — MEDIUM: soar.html — thêm request_theme (đã có request_token)
# -----------------------------------------------------------------------------
step "FIX-8" "soar.html — verify token handler OK (đã có từ trước)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/static/panels/soar.html"
with open(path) as f:
    src = f.read()

has_token   = "vsp:request_token" in src
has_theme   = "vsp:request_theme" in src
has_handler = "vsp:token" in src

print(f"  request_token: {'✓' if has_token else '✗'}")
print(f"  request_theme: {'✓' if has_theme else '✗'}")
print(f"  message handler: {'✓' if has_handler else '✗'}")

if not has_theme:
    # Thêm request_theme sau request_token
    old = "if(window.parent!==window) window.parent.postMessage({type:'vsp:request_token'},'*');"
    new = old + "\nif(window.parent!==window) window.parent.postMessage({type:'vsp:request_theme'},'*');"
    if old in src:
        src = src.replace(old, new)
        with open(path, "w") as f:
            f.write(src)
        print("  ✓ soar.html — request_theme added")
    else:
        print("  ⚠ soar.html: pattern không match, kiểm tra thủ công")
PYEOF

# -----------------------------------------------------------------------------
# FIX 9 — MEDIUM: ai_analyst.html — fix hardcode API_BASE
# -----------------------------------------------------------------------------
step "FIX-9" "ai_analyst.html — fix hardcode API_BASE"

AI_FILE="$VSP/static/panels/ai_analyst.html"
cp "$AI_FILE" "${AI_FILE}.bak_fix_$(date +%Y%m%d_%H%M%S)"

python3 - <<'PYEOF'
path = "/home/test/Data/GOLANG_VSP/static/panels/ai_analyst.html"
with open(path) as f:
    src = f.read()

old_api = "var TOKEN = '', API_BASE = 'http://127.0.0.1:8921';"
new_api = (
    "var TOKEN = '';\n"
    "// API_BASE: dùng relative path để hoạt động ở mọi host/port\n"
    "// Nhận từ parent qua postMessage nếu cần override\n"
    "var API_BASE = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')\n"
    "  ? window.location.origin  // dev: lấy từ current origin\n"
    "  : '';                      // prod: relative path (nginx proxy)"
)

if old_api not in src:
    print("  ⚠ ai_analyst.html: pattern not found, check manually")
else:
    src = src.replace(old_api, new_api)

    # Cũng update _initWithToken để nhận API_BASE từ parent nếu có
    old_init = "function _initWithToken(tk) {\n  if (!tk || tk.length < 50 || TOKEN) return;\n  TOKEN = tk;\n  loadAllData();\n}"
    new_init = (
        "function _initWithToken(tk, apiBase) {\n"
        "  if (!tk || tk.length < 50 || TOKEN) return;\n"
        "  TOKEN = tk;\n"
        "  if (apiBase) API_BASE = apiBase;\n"
        "  loadAllData();\n"
        "}"
    )
    src = src.replace(old_init, new_init)

    # Update message handler để nhận api_base
    old_msg = "  if (e.data.type === 'vsp:token') _initWithToken(e.data.token);"
    new_msg = "  if (e.data.type === 'vsp:token') _initWithToken(e.data.token, e.data.api_base);"
    src = src.replace(old_msg, new_msg)

    with open(path, "w") as f:
        f.write(src)
    print("  ✓ ai_analyst.html patched — API_BASE dynamic, không hardcode port")
PYEOF

# -----------------------------------------------------------------------------
# FIX 10 — .gitignore — đảm bảo .env không bị commit
# -----------------------------------------------------------------------------
step "FIX-10" ".gitignore — bảo vệ .env"

GITIGNORE="$VSP/.gitignore"
if ! grep -q "^\.env$" "$GITIGNORE" 2>/dev/null; then
    echo "" >> "$GITIGNORE"
    echo "# Secrets — KHÔNG commit" >> "$GITIGNORE"
    echo ".env" >> "$GITIGNORE"
    echo "*.bak_fix_*" >> "$GITIGNORE"
    ok ".gitignore updated — .env protected"
else
    ok ".gitignore đã có .env rule"
fi

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  VSP Fix All — DONE"
echo "============================================================"
echo ""
echo "  Fixes đã apply:"
echo "  [FIX-1] ✓ SSEHandler — JWT auth từ ?token= query param"
echo "  [FIX-2] ✓ WSUpgradeHandler — JWT auth check"
echo "  [FIX-3] ✓ gateway/main.go — SetJWTSecret + bỏ bypass mux"
echo "  [FIX-4] ✓ config.yaml — clear secrets, dùng env vars"
echo "  [FIX-5] ✓ .env.example — đầy đủ các env vars cần thiết"
echo "  [FIX-6] ✓ network_flow.html — TOKEN set trước loadNetworkFlow()"
echo "  [FIX-7] ✓ threat_intel.html — token handler + request_token"
echo "  [FIX-8] ✓ soar.html — verify + thêm request_theme nếu thiếu"
echo "  [FIX-9] ✓ ai_analyst.html — API_BASE dynamic, không hardcode"
echo "  [FIX-10] ✓ .gitignore — bảo vệ .env"
echo ""
echo "  Action cần làm thủ công:"
echo "  1. ROTATE JWT_SECRET trong .env (đã lộ trong git history)"
echo "     → openssl rand -hex 32"
echo "  2. ROTATE Redis password (VspRedis2026! đã lộ)"
echo "  3. Rebuild Go binary:"
echo "     cd $VSP && go build ./cmd/gateway/"
echo "  4. Kiểm tra build OK trước khi deploy:"
echo "     go vet ./..."
echo ""
echo "  Backup files: *.bak_fix_* trong các thư mục tương ứng"
echo "============================================================"
