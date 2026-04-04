package siem

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/store"
)

// AlertEmail sends HTML email for critical/high incidents.
type AlertEmail struct {
	Host    string
	Port    int
	User    string
	Pass    string
	From    string
	To      []string
	Enabled bool
}

func NewAlerter() *AlertEmail {
	return &AlertEmail{
		Host:    viper.GetString("smtp.host"),
		Port:    viper.GetInt("smtp.port"),
		User:    viper.GetString("smtp.user"),
		Pass:    viper.GetString("smtp.pass"),
		From:    viper.GetString("smtp.from"),
		To:      viper.GetStringSlice("smtp.to"),
		Enabled: viper.GetBool("smtp.enabled"),
	}
}

var incidentTpl = template.Must(template.New("inc").Parse(`<!DOCTYPE html>
<html>
<head><style>
body{font-family:sans-serif;background:#0a0c10;color:#e8eaf0;margin:0;padding:0}
.wrap{max-width:600px;margin:0 auto;padding:24px}
.header{background:#111318;border-bottom:2px solid #ef4444;padding:16px 24px;border-radius:8px 8px 0 0}
.title{font-size:20px;font-weight:700;color:#fff;margin:0}
.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;margin-left:8px}
.CRITICAL{background:rgba(239,68,68,.2);color:#ef4444}
.HIGH{background:rgba(245,158,11,.2);color:#f59e0b}
.body{background:#111318;padding:20px 24px;border-radius:0 0 8px 8px;margin-top:1px}
.row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.07);font-size:13px}
.lbl{color:#5a6278}
.val{color:#e8eaf0;font-weight:500}
.mono{font-family:monospace;font-size:12px;color:#06b6d4}
.footer{margin-top:16px;font-size:11px;color:#5a6278;text-align:center}
.btn{display:inline-block;background:#3b82f6;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600;margin-top:16px}
</style></head>
<body><div class="wrap">
<div class="header">
  <div class="title">
    🔴 VSP Security Alert
    <span class="badge {{.Severity}}">{{.Severity}}</span>
  </div>
</div>
<div class="body">
  <div class="row"><span class="lbl">Incident</span><span class="val mono">{{.ID}}</span></div>
  <div class="row"><span class="lbl">Title</span><span class="val">{{.Title}}</span></div>
  <div class="row"><span class="lbl">Severity</span><span class="val">{{.Severity}}</span></div>
  <div class="row"><span class="lbl">Status</span><span class="val">{{.Status}}</span></div>
  <div class="row"><span class="lbl">Detected</span><span class="val mono">{{.DetectedAt}}</span></div>
  <div class="row"><span class="lbl">Rule</span><span class="val">{{.RuleName}}</span></div>
  <p style="margin-top:16px;color:#9aa3b8;font-size:13px">
    This incident was automatically detected by the VSP Correlation Engine.
    Immediate investigation is recommended.
  </p>
  <a href="http://localhost:8922" class="btn">Open VSP Dashboard →</a>
</div>
<div class="footer">
  VSP Security Platform v0.10.0 · UNCLASSIFIED // FOR OFFICIAL USE ONLY<br>
  ITAR/EAR Controlled · Do not forward outside authorized channels
</div>
</div></body></html>`))

type IncidentAlert struct {
	ID         string
	Title      string
	Severity   string
	Status     string
	DetectedAt string
	RuleName   string
	TenantID   string
}

// SendIncidentAlert sends email for a critical/high incident.
func (a *AlertEmail) SendIncidentAlert(inc IncidentAlert) error {
	if !a.Enabled {
		log.Info().
			Str("incident", inc.ID).
			Str("severity", inc.Severity).
			Msg("email: alert (smtp disabled, logged only)")
		return nil
	}
	if len(a.To) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	var body bytes.Buffer
	if err := incidentTpl.Execute(&body, inc); err != nil {
		return fmt.Errorf("template: %w", err)
	}

	subject := fmt.Sprintf("[VSP ALERT] %s Incident: %s", inc.Severity, inc.Title)
	msg := "From: " + a.From + "\r\n" +
		"To: " + strings.Join(a.To, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		body.String()

	addr := fmt.Sprintf("%s:%d", a.Host, a.Port)
	auth := smtp.PlainAuth("", a.User, a.Pass, a.Host)
	if err := smtp.SendMail(addr, auth, a.User, a.To, []byte(msg)); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	log.Info().
		Str("incident", inc.ID).
		Strs("to", a.To).
		Msg("email: alert sent")
	return nil
}

// WatchIncidents polls for new critical incidents and sends alerts.
func WatchIncidents(ctx context.Context, db *store.DB) {
	alerter := NewAlerter()
	ticker  := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// Track by created_at — UUID comparison unreliable
	lastSeen := time.Now()
	for {
		select {
		case <-ticker.C:
			since := lastSeen
			lastSeen = time.Now()
			rows, err := db.Pool().Query(ctx, `
				SELECT i.id, i.title, i.severity, i.status,
				       i.created_at,
				       COALESCE(r.name, 'manual') as rule_name,
				       i.tenant_id
				FROM   incidents i
				LEFT   JOIN correlation_rules r ON r.id = i.rule_id
				WHERE  i.severity IN ('CRITICAL', 'HIGH')
				  AND  i.status = 'open'
				  AND  i.created_at > $1
				ORDER  BY i.created_at ASC
				LIMIT  10`, since)
			if err != nil { continue }
			for rows.Next() {
				var inc IncidentAlert
				var createdAt time.Time
				if err := rows.Scan(&inc.ID, &inc.Title, &inc.Severity,
					&inc.Status, &createdAt, &inc.RuleName, &inc.TenantID); err != nil {
					continue
				}
				inc.DetectedAt = createdAt.Format("2006-01-02 15:04:05 UTC")
				log.Info().Str("incident", inc.ID).Str("severity", inc.Severity).
					Str("title", inc.Title).Msg("emailer: new incident")
				go func(i IncidentAlert) {
					if err := alerter.SendIncidentAlert(i); err != nil {
						log.Debug().Err(err).Msg("email: SMTP not configured")
					}
				}(inc)
			}
			rows.Close()
		case <-ctx.Done():
			return
		}
	}
}
