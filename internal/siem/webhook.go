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

// validateWebhookURL chặn SSRF — chỉ cho phép HTTPS đến external hosts
func ValidateWebhookURL(rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https")
	}
	host := u.Hostname()
	// Chặn localhost và private ranges
	blocked := []string{"localhost", "127.", "0.0.0.0", "::1",
		"169.254.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "metadata.google", "metadata.aws"}
	for _, b := range blocked {
		if strings.HasPrefix(host, b) || host == strings.TrimSuffix(b, ".") {
			return fmt.Errorf("URL host %q is not allowed (private/internal)", host)
		}
	}
	// Resolve DNS và check IP
	ips, err := net.LookupHost(host)
	if err != nil { return nil } // nếu không resolve được thì skip check này
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil { continue }
		if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
			return fmt.Errorf("URL resolves to private IP %s — blocked", ip)
		}
	}
	return nil
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
	RID        string    `json:"rid"`
	TenantID   string    `json:"tenant_id"`
	Gate       string    `json:"gate"`
	Posture    string    `json:"posture"`
	Score      int       `json:"score"`
	Findings   int       `json:"total_findings"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Medium     int       `json:"medium"`
	Low        int       `json:"low"`
	Timestamp  time.Time `json:"timestamp"`
	Src        string    `json:"src"`
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
					{"title": "Gate",     "value": e.Gate,               "short": true},
					{"title": "Posture",  "value": e.Posture,            "short": true},
					{"title": "Score",    "value": e.Score,              "short": true},
					{"title": "Critical", "value": e.Critical,           "short": true},
					{"title": "High",     "value": e.High,               "short": true},
					{"title": "Source",   "value": e.Src,                "short": false},
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
			"title": "VSP Scan Complete: " + e.Gate,
			"text":  fmt.Sprintf("RID: %s\nFindings: %d (C:%d H:%d M:%d L:%d)", e.RID, e.Findings, e.Critical, e.High, e.Medium, e.Low),
			"alert_type": map[string]string{"PASS": "success", "WARN": "warning", "FAIL": "error"}[e.Gate],
			"tags": []string{"source:vsp", "gate:" + e.Gate},
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
