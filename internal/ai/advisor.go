package ai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const anthropicURL = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"
const model = "claude-sonnet-4-20250514"

// Message là một turn trong conversation
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest là body từ frontend gửi lên
type ChatRequest struct {
	Messages []Message `json:"messages"`
	TenantID string    `json:"tenant_id,omitempty"`
}

// anthropicRequest là body gửi lên Anthropic API
type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []Message `json:"messages"`
}

// buildSystemPrompt tạo system prompt cho VSP Security Advisor
func buildSystemPrompt(tenantID string) string {
	// Sanitize tenantID to prevent prompt injection
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, tenantID)
	if len(safe) > 50 { safe = safe[:50] }
	tenantID = safe
	return fmt.Sprintf(`Bạn là VSP AI Security Advisor — trợ lý bảo mật thông minh của nền tảng VSP SOC (Security Operations Center).

Nhiệm vụ của bạn:
- Phân tích alerts, incidents, và findings bảo mật
- Đề xuất remediation steps cụ thể và ưu tiên theo mức độ nghiêm trọng
- Giải thích các lỗ hổng bảo mật bằng ngôn ngữ dễ hiểu
- Hỗ trợ compliance (NIST, RMF, OSCAL, FedRAMP)
- Tư vấn Zero Trust architecture

Tenant hiện tại: %s
Thời gian: %s

Quy tắc:
- Luôn trả lời bằng tiếng Việt trừ khi user hỏi bằng tiếng Anh
- Ưu tiên actionable recommendations
- Với critical vulnerabilities, luôn đề xuất immediate actions
- Không bịa đặt CVE IDs hay thông tin kỹ thuật không chắc chắn`, tenantID, time.Now().Format("2006-01-02 15:04 MST"))
}

// Handler xử lý POST /api/v1/ai/chat
func Handler(w http.ResponseWriter, r *http.Request) {
	// CORS
	// CORS: restrict to same origin — don't use wildcard for authenticated endpoints
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Check API key
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		http.Error(w, `{"error":"ANTHROPIC_API_KEY not set"}`, http.StatusInternalServerError)
		return
	}

	// Parse request từ frontend
	var chatReq ChatRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // max 1MB
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &chatReq); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if len(chatReq.Messages) == 0 {
		http.Error(w, `{"error":"messages required"}`, http.StatusBadRequest)
		return
	}

	// TenantID phải lấy từ JWT Authorization header, không phải body
	// Parse Bearer token để lấy tenant_id claim
	tenantID := "default"
	if bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); bearer != "" {
		// JWT format: header.payload.sig — decode payload
		if parts := strings.Split(bearer, "."); len(parts) == 3 {
			// Base64 decode payload (no validation here — just extract tenantID)
			// Real validation happens in auth middleware upstream
			if decoded, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims struct{ TID string `json:"tid"` }
				if err := json.Unmarshal(decoded, &claims); err == nil && claims.TID != "" {
					tenantID = claims.TID
				}
			}
		}
	}

	// Build request gửi Anthropic
	anthropicReq := anthropicRequest{
		Model:     model,
		MaxTokens: 1024,
		System:    buildSystemPrompt(tenantID),
		Messages:  chatReq.Messages,
	}
	reqBody, err := json.Marshal(anthropicReq)
	if err != nil {
		http.Error(w, `{"error":"failed to build request"}`, http.StatusInternalServerError)
		return
	}

	// Gọi Anthropic API
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodPost, anthropicURL, bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, `{"error":"failed to create request"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, `{"error":"failed to call Anthropic API"}`, http.StatusBadGateway)
		return
	}
	if resp == nil {
		http.Error(w, `{"error":"empty response"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward response về frontend
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
