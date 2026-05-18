// Package notify provides a multi-provider implementation of soar.Notifier.
//
// Supported channels (case-insensitive):
//
//	slack    — Slack incoming webhook URL (provided via "to" or default config)
//	discord  — Discord webhook URL (Slack-compatible payload)
//	teams    — Microsoft Teams incoming webhook (MessageCard format)
//	webhook  — Generic JSON POST (fallback)
//
// The "to" parameter is treated as the destination URL (preferred) or the
// channel/recipient name when a default webhook for the provider is configured
// via Config. If neither a URL nor a default is available the call returns a
// soft error so playbooks remain useful in test environments.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Config carries optional default webhook URLs per provider. Any field may be
// empty — in that case the corresponding provider only works when the caller
// passes a full URL via the "to" argument.
type Config struct {
	SlackDefaultWebhook   string // optional: used when "to" is a channel name like "#soc"
	DiscordDefaultWebhook string
	TeamsDefaultWebhook   string

	// HTTPTimeout per request. Defaults to 15s.
	HTTPTimeout time.Duration

	// AllowPrivateIPs disables SSRF protection. ONLY for tests.
	AllowPrivateIPs bool
}

// MultiNotifier dispatches Send calls to the right provider based on
// the channel argument. Implements soar.Notifier.
type MultiNotifier struct {
	cfg    Config
	client *http.Client
}

// New constructs a MultiNotifier with the given config.
func New(cfg Config) *MultiNotifier {
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	return &MultiNotifier{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.HTTPTimeout},
	}
}

// Send routes the message to the correct provider. Errors are returned to
// the caller; the SOAR engine decides whether to fail the step or proceed.
func (m *MultiNotifier) Send(ctx context.Context, channel, to, message, template string, params map[string]interface{}) error {
	channel = strings.ToLower(strings.TrimSpace(channel))
	to = strings.TrimSpace(to)

	switch channel {
	case "slack":
		return m.sendSlack(ctx, to, message, params)
	case "discord":
		return m.sendDiscord(ctx, to, message, params)
	case "teams":
		return m.sendTeams(ctx, to, message, params)
	case "webhook", "generic":
		return m.sendGeneric(ctx, to, message, params)
	case "email":
		// Email kept as no-op for v1 — wire SMTP separately.
		log.Warn().Str("to", to).Msg("notify: email channel not implemented yet")
		return nil
	default:
		return fmt.Errorf("notify: unsupported channel %q", channel)
	}
}

// ── Slack ─────────────────────────────────────────────────────────────────

func (m *MultiNotifier) sendSlack(ctx context.Context, to, message string, params map[string]interface{}) error {
	url := m.resolveURL(to, m.cfg.SlackDefaultWebhook)
	if url == "" {
		return fmt.Errorf("notify[slack]: webhook URL required")
	}
	payload := map[string]interface{}{"text": message}
	if ch, ok := params["channel"].(string); ok && ch != "" {
		payload["channel"] = ch
	}
	if user, ok := params["username"].(string); ok && user != "" {
		payload["username"] = user
	}
	return m.postJSON(ctx, url, payload, "slack")
}

// ── Discord ───────────────────────────────────────────────────────────────

func (m *MultiNotifier) sendDiscord(ctx context.Context, to, message string, params map[string]interface{}) error {
	url := m.resolveURL(to, m.cfg.DiscordDefaultWebhook)
	if url == "" {
		return fmt.Errorf("notify[discord]: webhook URL required")
	}
	// Discord accepts {"content": "..."} for plain messages.
	payload := map[string]interface{}{"content": message}
	if user, ok := params["username"].(string); ok && user != "" {
		payload["username"] = user
	}
	return m.postJSON(ctx, url, payload, "discord")
}

// ── Microsoft Teams ───────────────────────────────────────────────────────

func (m *MultiNotifier) sendTeams(ctx context.Context, to, message string, params map[string]interface{}) error {
	url := m.resolveURL(to, m.cfg.TeamsDefaultWebhook)
	if url == "" {
		return fmt.Errorf("notify[teams]: webhook URL required")
	}
	// MessageCard schema (legacy connector — still supported).
	payload := map[string]interface{}{
		"@type":    "MessageCard",
		"@context": "http://schema.org/extensions",
		"text":     message,
	}
	if title, ok := params["title"].(string); ok && title != "" {
		payload["title"] = title
	}
	return m.postJSON(ctx, url, payload, "teams")
}

// ── Generic webhook ───────────────────────────────────────────────────────

func (m *MultiNotifier) sendGeneric(ctx context.Context, to, message string, params map[string]interface{}) error {
	if to == "" {
		return fmt.Errorf("notify[webhook]: URL required in 'to'")
	}
	payload := map[string]interface{}{
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range params {
		payload[k] = v
	}
	return m.postJSON(ctx, to, payload, "webhook")
}

// ── Helpers ───────────────────────────────────────────────────────────────

// resolveURL returns "to" if it looks like a URL, otherwise the default.
func (m *MultiNotifier) resolveURL(to, fallback string) string {
	if strings.HasPrefix(to, "http://") || strings.HasPrefix(to, "https://") {
		return to
	}
	return fallback
}

func (m *MultiNotifier) postJSON(ctx context.Context, rawURL string, payload interface{}, provider string) error {
	if !m.cfg.AllowPrivateIPs {
		if err := guardSSRF(rawURL); err != nil {
			return fmt.Errorf("notify[%s]: %w", provider, err)
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify[%s]: marshal: %w", provider, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify[%s]: build request: %w", provider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VSP-SOAR-Notifier/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify[%s]: post: %w", provider, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify[%s]: http %d from %s", provider, resp.StatusCode, rawURL)
	}
	log.Info().Str("provider", provider).Int("status", resp.StatusCode).Msg("notify: sent")
	return nil
}

// guardSSRF rejects URLs that resolve to private/loopback ranges.
func guardSSRF(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https allowed, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host in URL")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// DNS failure is not necessarily SSRF; let the HTTP client surface it.
		return nil //nolint:nilerr
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("URL resolves to private/loopback IP %s — blocked", ip)
		}
	}
	return nil
}
