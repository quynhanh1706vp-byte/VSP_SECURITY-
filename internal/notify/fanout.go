// Package notify implements the outbound notification fan-out worker.
//
// Stamping events into the notification_log table is what every PRO panel
// already does (see the Configure → Notifications form). This worker drains
// rows whose status_code is still 0 (i.e. not delivered yet) and POSTs the
// payload to the tenant's configured webhook URL — Slack, MS Teams, generic.
// The result code (or transport error) is written back to the same row so
// ops can review delivery from the Notifications log panel.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// Fanout owns the worker loop. Spawn one instance at gateway startup.
type Fanout struct {
	pool       *pgxpool.Pool
	tick       time.Duration
	client     *http.Client
	pins       *PinSet
	signingKey []byte // HMAC-SHA256 secret for X-VSP-Signature; empty = no signing
}

// NewFanout returns a worker. tick = how often to scan notification_log.
// 5 s is a good default — small enough for low-latency alerts, big enough
// not to hammer Postgres on idle gateways.
//
// The HTTP client uses a pinning transport: when a tenant has registered
// SPKI pins for a webhook host (siem_webhooks.pinned_pubkey_sha256),
// outbound requests fail-closed if the peer cert doesn't match. Tenants
// without pins continue to get vanilla TLS.
func NewFanout(pool *pgxpool.Pool, tick time.Duration) *Fanout {
	if tick <= 0 {
		tick = 5 * time.Second
	}
	pins := NewPinSet()
	return &Fanout{
		pool: pool,
		tick: tick,
		pins: pins,
		// Each outbound POST gets 8 s — webhooks like Slack reliably respond
		// in <1 s; a long-lived hang would back-pressure the loop.
		client: &http.Client{
			Timeout:   8 * time.Second,
			Transport: NewPinningTransport(pins),
		},
	}
}

// WithSigningKey sets the HMAC secret used to sign outbound webhook
// bodies. Calling with an empty string disables signing. Safe to call
// once at startup before Run; not concurrency-safe.
func (f *Fanout) WithSigningKey(key string) *Fanout {
	f.signingKey = []byte(key)
	return f
}

// Run blocks until ctx is cancelled. Spawn in a goroutine.
func (f *Fanout) Run(ctx context.Context) {
	log.Info().Dur("tick", f.tick).Msg("notification fan-out worker started")
	t := time.NewTicker(f.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("notification fan-out worker stopped")
			return
		case <-t.C:
			f.refreshPins(ctx)
			f.drainOnce(ctx)
		}
	}
}

// drainOnce pulls a small batch of due rows and dispatches them. Includes:
//   • New rows (status_code=0, attempts=0)
//   • Transient failures within max_attempts whose next_retry_at has elapsed
// Permanent 4xx failures and DLQ rows (status_code=-1) are skipped.
//
// SELECT ... FOR UPDATE SKIP LOCKED lets multiple gateway replicas share the
// queue without double-delivery. Batch size 16 keeps a slow upstream from
// stalling newer events.
func (f *Fanout) drainOnce(ctx context.Context) {
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // committed on success path

	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, channel, event_type, payload, attempts, max_attempts
		   FROM notification_log
		  WHERE (
		         status_code = 0
		         OR (attempts > 0 AND attempts < max_attempts AND status_code != -1
		             AND (status_code >= 500 OR status_code = 408 OR status_code = 429 OR error != ''))
		        )
		    AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		  ORDER BY COALESCE(next_retry_at, sent_at) ASC
		  LIMIT 16
		 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return
	}
	type job struct {
		ID          int64
		TenantID    string
		Channel     string
		EventType   string
		Payload     string
		Attempts    int
		MaxAttempts int
	}
	var batch []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.ID, &j.TenantID, &j.Channel, &j.EventType, &j.Payload, &j.Attempts, &j.MaxAttempts); err != nil {
			continue
		}
		batch = append(batch, j)
	}
	rows.Close()
	if len(batch) == 0 {
		return
	}

	for _, j := range batch {
		status, errMsg := f.deliver(ctx, j.TenantID, j.Channel, j.EventType, j.Payload)
		newAttempts := j.Attempts + 1

		// Decide retry policy
		isTransient := status >= 500 || status == 408 || status == 429 || (status == 0 && errMsg != "")
		if isTransient && newAttempts >= j.MaxAttempts {
			// Exhausted retries — mark as DLQ
			_, _ = tx.Exec(ctx,
				`UPDATE notification_log
				    SET status_code = -1, error = $1, attempts = $2, last_attempt_at = NOW(), next_retry_at = NULL
				  WHERE id = $3`,
				"DLQ after "+itoa(newAttempts)+" attempts: "+errMsg, newAttempts, j.ID)
			continue
		}
		if isTransient {
			// Schedule next retry with exponential backoff: 1m, 5m, 15m, 1h, 6h
			backoff := []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute, 1 * time.Hour, 6 * time.Hour}
			delay := 1 * time.Minute
			if newAttempts-1 < len(backoff) {
				delay = backoff[newAttempts-1]
			} else {
				delay = backoff[len(backoff)-1]
			}
			_, _ = tx.Exec(ctx,
				`UPDATE notification_log
				    SET status_code = $1, error = $2, attempts = $3, last_attempt_at = NOW(),
				        next_retry_at = NOW() + ($4 || ' seconds')::interval
				  WHERE id = $5`,
				status, errMsg, newAttempts, int(delay.Seconds()), j.ID)
			continue
		}
		// Terminal: 2xx success OR 4xx (won't retry)
		_, _ = tx.Exec(ctx,
			`UPDATE notification_log
			    SET status_code = $1, error = $2, attempts = $3, last_attempt_at = NOW(), next_retry_at = NULL, sent_at = NOW()
			  WHERE id = $4`,
			status, errMsg, newAttempts, j.ID)
	}
	_ = tx.Commit(ctx)
}

// itoa is a tiny stdlib-free int-to-string for use inside hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// deliver dispatches one event to one channel. Returns the HTTP status code
// (or 0) and an error message string. Both are persisted to the audit row.
func (f *Fanout) deliver(ctx context.Context, tenantID, channel, eventType, payload string) (int, string) {
	url, errLookup := f.lookupChannelURL(ctx, tenantID, channel)
	if errLookup != "" {
		return 0, errLookup
	}
	if url == "" {
		// Channel not configured — mark as 404 so the row isn't retried.
		return 404, "channel not configured"
	}

	body := f.formatPayload(channel, eventType, payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vsp-gateway/notify")
	// Sign outbound webhook with HMAC-SHA256 so receivers can verify
	// origin. Header format: X-VSP-Signature: t=<unix>,v1=<hex(hmac)>.
	// Receiver computes HMAC over "<unix>." + body and compares.
	if len(f.signingKey) > 0 {
		ts := time.Now().Unix()
		mac := hmac.New(sha256.New, f.signingKey)
		fmt.Fprintf(mac, "%d.", ts)
		mac.Write(body)
		req.Header.Set("X-VSP-Signature",
			"t="+strconv.FormatInt(ts, 10)+",v1="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	return resp.StatusCode, ""
}

// lookupChannelURL pulls the destination URL for one channel from the
// tenant's notification_config row. Email + PagerDuty are routed differently
// in production — for the MVP they share the generic_webhook column.
func (f *Fanout) lookupChannelURL(ctx context.Context, tenantID, channel string) (string, string) {
	var slack, teams, generic, pagerduty, email string
	err := f.pool.QueryRow(ctx,
		`SELECT slack_webhook, teams_webhook, generic_webhook, pagerduty_key, email_recipients
		   FROM notification_config
		  WHERE tenant_id = $1`,
		tenantID,
	).Scan(&slack, &teams, &generic, &pagerduty, &email)
	if err != nil {
		// No row → treat as channel not configured.
		return "", ""
	}
	switch channel {
	case "slack":
		return slack, ""
	case "teams":
		return teams, ""
	case "generic":
		return generic, ""
	case "pagerduty":
		// PagerDuty Events API v2 — the key is the routing_key in the body,
		// not part of the URL.
		if pagerduty == "" {
			return "", ""
		}
		return "https://events.pagerduty.com/v2/enqueue", ""
	case "email":
		// Email needs SMTP — out of scope for the HTTP-only fan-out.
		// Mark as configured-but-unsupported so ops sees the row.
		if email == "" {
			return "", ""
		}
		return "", "email channel requires SMTP worker (not implemented)"
	}
	return "", "unknown channel: " + channel
}

// formatPayload massages the inbound JSON event into the shape each provider
// expects. Slack and Teams take a {text:"..."} body; generic webhooks get
// the raw payload; PagerDuty needs an Events-API v2 envelope.
func (f *Fanout) formatPayload(channel, eventType, payload string) []byte {
	if payload == "" {
		payload = "{}"
	}
	switch channel {
	case "slack", "teams":
		// Both providers accept {text:"..."} as the simplest body.
		// Wrap the raw payload string for readability.
		body, _ := json.Marshal(map[string]string{
			"text": "[VSP " + strings.ToUpper(eventType) + "] " + payload,
		})
		return body
	case "pagerduty":
		// payload is expected to already include routing_key in production;
		// for MVP we just envelope the text.
		body, _ := json.Marshal(map[string]any{
			"event_action": "trigger",
			"payload": map[string]any{
				"summary":  "[VSP " + eventType + "] " + payload,
				"source":   "vsp-gateway",
				"severity": "info",
			},
		})
		return body
	}
	// generic / unknown — pass through.
	return []byte(payload)
}

// refreshPins reloads SPKI pins from siem_webhooks + notification_config
// into the in-memory PinSet. Called once per drain tick — pins change
// rarely (key rotation), so a short cache delay is acceptable.
func (f *Fanout) refreshPins(ctx context.Context) {
	if f.pins == nil {
		return
	}
	// siem_webhooks: per-row pin keyed by URL host.
	rows, err := f.pool.Query(ctx,
		`SELECT url, pinned_pubkey_sha256
		   FROM siem_webhooks
		  WHERE active = true AND pinned_pubkey_sha256 <> ''`)
	if err == nil {
		for rows.Next() {
			var rawURL, pinCSV string
			if err := rows.Scan(&rawURL, &pinCSV); err != nil {
				continue
			}
			host := hostFromURL(rawURL)
			if host == "" {
				continue
			}
			f.pins.Set(host, splitCSV(pinCSV))
		}
		rows.Close()
	}
	// notification_config.generic_webhook + its pin column.
	rows2, err := f.pool.Query(ctx,
		`SELECT generic_webhook, generic_webhook_pin
		   FROM notification_config
		  WHERE generic_webhook_pin <> ''`)
	if err == nil {
		for rows2.Next() {
			var rawURL, pinCSV string
			if err := rows2.Scan(&rawURL, &pinCSV); err != nil {
				continue
			}
			host := hostFromURL(rawURL)
			if host == "" {
				continue
			}
			f.pins.Set(host, splitCSV(pinCSV))
		}
		rows2.Close()
	}
}

func hostFromURL(raw string) string {
	// Cheap parse — avoid pulling net/url here for hot path; we only need
	// the host segment between "://" and the next "/" or ":".
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if k := strings.LastIndexByte(rest, ':'); k >= 0 {
		rest = rest[:k]
	}
	return strings.ToLower(rest)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
