package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// ValidateWebhookURL chặn SSRF — chỉ cho phép HTTPS đến external hosts.
//
// Threat model: tenant operator can configure arbitrary webhook URLs in
// the SIEM panel. Without these checks they could pivot the gateway to
// attack internal services (169.254.169.254 cloud metadata, RFC1918
// admin UIs, localhost ports).
//
// Defense layers (each layer alone has a bypass; together they close it):
//  1. Scheme must be https.
//  2. Reject hostnames that are well-known internal aliases (localhost,
//     *.internal, *.local, metadata.*) — case-insensitive.
//  3. If the host parses as a literal IP, check it directly against the
//     RFC1918 / loopback / link-local / CGN ruleset.
//  4. If the host is a name, resolve via LookupIP and check EVERY A/AAAA
//     answer. **Fail closed on resolution failure** (pre-fix it returned
//     nil — an attacker-controlled name that NXDOMAIN'd at validation
//     time and resolved at send time passed the check).
//
// Residual risk: DNS rebinding across the validate→send window. The
// caller (send()) re-validates on every send, narrowing the window to
// the time between the second validate and net/http's own dial. Closing
// it fully requires a Dialer that pins the validated IP — tracked
// separately.
func ValidateWebhookURL(rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL host is empty")
	}

	lh := strings.ToLower(host)
	if lh == "localhost" || lh == "ip6-localhost" || lh == "ip6-loopback" ||
		strings.HasSuffix(lh, ".internal") || strings.HasSuffix(lh, ".local") ||
		strings.HasSuffix(lh, ".localhost") ||
		strings.HasPrefix(lh, "metadata.") {
		return fmt.Errorf("URL host %q is not allowed (internal alias)", host)
	}

	// Host is a literal IP? Check directly (DNS doesn't apply).
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL host IP %s is private/loopback/link-local", ip)
		}
		return nil
	}

	// Host is a name. Resolve and check every answer. Fail CLOSED on
	// resolution failure — pre-fix returned nil which let attacker-
	// controlled NXDOMAIN-then-resolve flips through.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("URL host %q failed DNS resolution: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("URL host %q has no DNS answers", host)
	}
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL host %q resolves to private IP %s — blocked", host, ip)
		}
	}
	return nil
}

// isPrivateIP — RFC1918 + loopback + link-local + CGN + IPv6 ULA.
// Mirrors the soar/http_client.go ruleset; kept duplicated to avoid an
// internal/siem ↔ internal/soar import cycle.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	if len(ip) == 16 && (ip[0] == 0xfc || ip[0] == 0xfd) {
		return true
	}
	return false
}

// WebhookType defines the payload format.
type WebhookType string

const (
	TypeGeneric  WebhookType = "generic"
	TypeSlack    WebhookType = "slack"
	TypeSplunk   WebhookType = "splunk_hec"
	TypeSentinel WebhookType = "sentinel"
	TypeDatadog  WebhookType = "datadog"
	TypeCEF      WebhookType = "cef"
)

// Event is the internal representation sent to all webhooks.
type Event struct {
	RID       string    `json:"rid"`
	TenantID  string    `json:"tenant_id"`
	Gate      string    `json:"gate"`
	Posture   string    `json:"posture"`
	Score     int       `json:"score"`
	Findings  int       `json:"total_findings"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Timestamp time.Time `json:"timestamp"`
	Src       string    `json:"src"`
}

// Deliver sends event to all active webhooks for a tenant.
// Errors are logged but do not fail the caller.
func Deliver(ctx context.Context, db store.WebhookStore, event Event) {
	hooks, err := db.ListSIEMWebhooks(ctx, event.TenantID)
	if err != nil {
		log.Error().Err(err).Msg("siem: list webhooks failed")
		return
	}
	for _, hook := range hooks {
		if !hook.Active {
			continue
		}
		// Severity filter
		if !SeverityMeetsMin(event, hook.MinSev) {
			continue
		}
		go deliverOne(ctx, db, hook, event) //#nosec G118 -- ctx is passed as argument, not context.Background
	}
}

func deliverOne(ctx context.Context, db store.WebhookStore, hook store.SIEMWebhook, event Event) {
	payload, err := buildPayload(WebhookType(hook.Type), hook, event)
	if err != nil {
		log.Error().Err(err).Str("hook", hook.ID).Msg("siem: build payload failed")
		return
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := send(ctx, hook, payload); err != nil {
			lastErr = err
			backoff := time.Duration(attempt*attempt) * time.Second
			log.Warn().Err(err).Int("attempt", attempt).
				Str("hook", hook.Label).Msgf("siem: retry in %s", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		log.Info().Str("hook", hook.Label).Str("rid", event.RID).Msg("siem: delivered")
		// Update last_fired (best-effort)
		_ = db.TouchSIEMWebhook(context.Background(), hook.ID)
		return
	}
	log.Error().Err(lastErr).Str("hook", hook.Label).Msg("siem: delivery failed after 3 attempts")
}

func send(ctx context.Context, hook store.SIEMWebhook, payload []byte) error {
	// Validate URL mỗi lần gửi — chặn SSRF
	if err := ValidateWebhookURL(hook.URL); err != nil {
		return fmt.Errorf("webhook URL blocked: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", hook.URL,
		bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VSP-Platform/0.2")

	// HMAC signature if secret configured
	if hook.SecretHash != "" {
		mac := hmac.New(sha256.New, []byte(hook.SecretHash))
		mac.Write(payload)
		req.Header.Set("X-VSP-Signature",
			fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

func buildPayload(t WebhookType, hook store.SIEMWebhook, e Event) ([]byte, error) {
	switch t {
	case TypeSlack:
		color := map[string]string{"PASS": "#36a64f", "WARN": "#ffcc00", "FAIL": "#ff0000"}[e.Gate]
		return json.Marshal(map[string]any{
			"attachments": []map[string]any{{
				"color": color,
				"title": fmt.Sprintf("VSP Scan: %s — %s", e.Gate, e.RID),
				"fields": []map[string]any{
					{"title": "Gate", "value": e.Gate, "short": true},
					{"title": "Posture", "value": e.Posture, "short": true},
					{"title": "Score", "value": e.Score, "short": true},
					{"title": "Critical", "value": e.Critical, "short": true},
					{"title": "High", "value": e.High, "short": true},
					{"title": "Source", "value": e.Src, "short": false},
				},
				"footer": "VSP Security Platform",
				"ts":     e.Timestamp.Unix(),
			}},
		})
	case TypeSplunk:
		return json.Marshal(map[string]any{
			"time":       e.Timestamp.Unix(),
			"sourcetype": "vsp:scan",
			"event":      e,
		})
	case TypeDatadog:
		return json.Marshal(map[string]any{
			"title":      "VSP Scan Complete: " + e.Gate,
			"text":       fmt.Sprintf("RID: %s\nFindings: %d (C:%d H:%d M:%d L:%d)", e.RID, e.Findings, e.Critical, e.High, e.Medium, e.Low),
			"alert_type": map[string]string{"PASS": "success", "WARN": "warning", "FAIL": "error"}[e.Gate],
			"tags":       []string{"source:vsp", "gate:" + e.Gate},
		})
	default: // generic
		return json.Marshal(e)
	}
}

func SeverityMeetsMin(e Event, minSev string) bool {
	switch minSev {
	case "CRITICAL":
		return e.Critical > 0
	case "HIGH":
		return e.Critical > 0 || e.High > 0
	case "MEDIUM":
		return e.Critical > 0 || e.High > 0 || e.Medium > 0
	default:
		return true
	}
}
