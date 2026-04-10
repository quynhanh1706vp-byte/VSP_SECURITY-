// internal/siem/syslog_recv.go
// UDP/TCP Syslog receiver — parse RFC3164/5424/CEF → store events
package siem

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

// ParsedEvent is a normalized log event from any source.
type ParsedEvent struct {
	Timestamp time.Time         `json:"ts"`
	Host      string            `json:"host"`
	Process   string            `json:"process"`
	PID       int               `json:"pid,omitempty"`
	Severity  string            `json:"severity"`
	Facility  string            `json:"facility"`
	Message   string            `json:"message"`
	SourceIP  string            `json:"source_ip"`
	Format    string            `json:"format"`
	Raw       string            `json:"raw"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// SyslogReceiver listens on UDP + TCP and parses incoming log events.
type SyslogReceiver struct {
	udpAddr  string
	tcpAddr  string
	db       *store.DB
	tenantID string
	buf      chan ParsedEvent
	mu       sync.Mutex
	stats    ReceiverStats
}

type ReceiverStats struct {
	Received   int64
	Parsed     int64
	Errors     int64
	LastEvent  time.Time
}

func NewSyslogReceiver(udpAddr, tcpAddr string, db *store.DB, tenantID string) *SyslogReceiver {
	return &SyslogReceiver{
		udpAddr:  udpAddr,
		tcpAddr:  tcpAddr,
		db:       db,
		tenantID: tenantID,
		buf:      make(chan ParsedEvent, 10000), // bounded buffer — drops when full (rate limiting)
	}
}

// Start launches UDP + TCP listeners and the event processor.
func (r *SyslogReceiver) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	// UDP listener
	go func() {
		if err := r.listenUDP(ctx); err != nil {
			errCh <- fmt.Errorf("udp: %w", err)
		}
	}()

	// TCP listener
	go func() {
		if err := r.listenTCP(ctx); err != nil {
			errCh <- fmt.Errorf("tcp: %w", err)
		}
	}()

	// Event processor (batch write to DB every 5s)
	go r.processEvents(ctx)

	log.Info().
		Str("udp", r.udpAddr).
		Str("tcp", r.tcpAddr).
		Msg("siem: syslog receiver started")

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

// Stats returns current receiver statistics.
func (r *SyslogReceiver) Stats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// ── UDP ───────────────────────────────────────────────────────

func (r *SyslogReceiver) listenUDP(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", r.udpAddr)
	if err != nil { return err }
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { return err }
	defer conn.Close()

	go func() { <-ctx.Done(); conn.Close() }()

	buf := make([]byte, 65536)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil { return nil }
			continue
		}
		raw := string(buf[:n])
		r.mu.Lock(); r.stats.Received++; r.mu.Unlock()
		ev, err := ParseSyslog(raw, src.IP.String())
		if err != nil {
			r.mu.Lock(); r.stats.Errors++; r.mu.Unlock()
			continue
		}
		r.mu.Lock(); r.stats.Parsed++; r.stats.LastEvent = time.Now(); r.mu.Unlock()
		select {
		case r.buf <- ev:
		default: // drop if buffer full
		}
	}
}

// ── TCP ───────────────────────────────────────────────────────

func (r *SyslogReceiver) listenTCP(ctx context.Context) error {
	ln, err := net.Listen("tcp", r.tcpAddr)
	if err != nil { return err }
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil { return nil }
			continue
		}
		go r.handleTCPConn(ctx, conn)
	}
}

func (r *SyslogReceiver) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 65536), 65536)
	for sc.Scan() {
		raw := sc.Text()
		if raw == "" { continue }
		r.mu.Lock(); r.stats.Received++; r.mu.Unlock()
		ev, err := ParseSyslog(raw, srcIP)
		if err != nil {
			r.mu.Lock(); r.stats.Errors++; r.mu.Unlock()
			continue
		}
		r.mu.Lock(); r.stats.Parsed++; r.stats.LastEvent = time.Now(); r.mu.Unlock()
		select {
		case r.buf <- ev:
		default:
		}
	}
}

// ── Event processor ───────────────────────────────────────────

func (r *SyslogReceiver) processEvents(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var batch []ParsedEvent
	flush := func() {
		if len(batch) == 0 { return }
		r.writeBatch(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case ev := <-r.buf:
			batch = append(batch, ev)
			if len(batch) >= 500 { flush() }
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

func (r *SyslogReceiver) writeBatch(ctx context.Context, events []ParsedEvent) {
	if len(events) == 0 { return }
	// Write to log_events table (create if not exists inline)
	r.db.Pool().Exec(ctx, `
		CREATE TABLE IF NOT EXISTS log_events (
			id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id  UUID        NOT NULL,
			ts         TIMESTAMPTZ NOT NULL,
			host       TEXT,
			process    TEXT,
			severity   TEXT,
			facility   TEXT,
			message    TEXT,
			source_ip  TEXT,
			format     TEXT,
			raw        TEXT,
			fields     JSONB       DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_log_events_tenant_ts
			ON log_events(tenant_id, ts DESC);
	`) //nolint:errcheck

	for _, ev := range events {
		r.db.Pool().Exec(ctx, `
			INSERT INTO log_events
				(tenant_id, ts, host, process, severity,
				 facility, message, source_ip, format, raw)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			r.tenantID, ev.Timestamp, ev.Host, ev.Process, ev.Severity,
			ev.Facility, ev.Message, ev.SourceIP, ev.Format, ev.Raw,
		) //nolint:errcheck
	}
	log.Debug().Int("count", len(events)).Msg("siem: log batch written")
}

// ── Parsers ───────────────────────────────────────────────────

var (
	// RFC3164: <PRI>TIMESTAMP HOST PROCESS[PID]: MSG
	re3164 = regexp.MustCompile(`^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)
	// RFC5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
	re5424 = regexp.MustCompile(`^<(\d+)>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(?:\[[^\]]*\]\s*)?(\S.*)$`)
	// CEF: CEF:0|vendor|product|version|sigid|name|severity|ext
	reCEF  = regexp.MustCompile(`^CEF:(\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(\d+)\|(.*)$`)
)

// ParseSyslog auto-detects format and returns a normalized ParsedEvent.
func ParseSyslog(raw, srcIP string) (ParsedEvent, error) {
	// Cap message size to prevent OOM from malformed/malicious syslog
	const maxMsgSize = 64 * 1024 // 64KB
	if len(raw) > maxMsgSize {
		raw = raw[:maxMsgSize]
	}
	ev := ParsedEvent{Raw: raw, SourceIP: srcIP, Timestamp: time.Now()}

	// Try CEF first
	if m := reCEF.FindStringSubmatch(raw); len(m) > 0 {
		ev.Format = "cef"
		ev.Process = m[3]
		ev.Message = m[6]
		sev, _ := strconv.Atoi(m[7])
		ev.Severity = cefSeverity(sev)
		ev.Fields = parseCEFExtension(m[8])
		if h, ok := ev.Fields["dhost"]; ok { ev.Host = h }
		if h, ok := ev.Fields["src"];   ok { ev.SourceIP = h }
		return ev, nil
	}

	// Try RFC5424
	if m := re5424.FindStringSubmatch(raw); len(m) > 0 {
		ev.Format = "rfc5424"
		pri, _ := strconv.Atoi(m[1])
		ev.Facility, ev.Severity = decodePRI(pri)
		ev.Timestamp, _ = time.Parse(time.RFC3339, m[2])
		ev.Host    = m[3]
		ev.Process = m[4]
		ev.PID, _  = strconv.Atoi(m[5])
		ev.Message = m[6]
		return ev, nil
	}

	// Try RFC3164
	if m := re3164.FindStringSubmatch(raw); len(m) > 0 {
		ev.Format = "rfc3164"
		pri, _ := strconv.Atoi(m[1])
		ev.Facility, ev.Severity = decodePRI(pri)
		t, err := time.Parse("Jan  2 15:04:05", m[2])
		if err == nil {
			ev.Timestamp = t.AddDate(time.Now().Year(), 0, 0)
		}
		ev.Host    = m[3]
		ev.Process = strings.TrimSuffix(m[4], ":")
		ev.PID, _  = strconv.Atoi(m[5])
		ev.Message = m[6]
		return ev, nil
	}

	// Fallback: raw line
	ev.Format   = "raw"
	ev.Message  = raw
	ev.Severity = "INFO"
	return ev, nil
}

func decodePRI(pri int) (facility, severity string) {
	fac := pri >> 3
	sev := pri & 0x7
	facilities := []string{"kern","user","mail","daemon","auth","syslog","lpr","news","uucp","cron","authpriv","ftp","ntp","audit","alert","clock","local0","local1","local2","local3","local4","local5","local6","local7"}
	severities := []string{"CRITICAL","CRITICAL","CRITICAL","ERROR","WARNING","INFO","INFO","DEBUG"}
	if fac < len(facilities) { facility = facilities[fac] } else { facility = "unknown" }
	if sev < len(severities) { severity = severities[sev] } else { severity = "INFO" }
	return
}

func cefSeverity(n int) string {
	switch {
	case n >= 9: return "CRITICAL"
	case n >= 7: return "HIGH"
	case n >= 4: return "MEDIUM"
	default:     return "LOW"
	}
}

func parseCEFExtension(ext string) map[string]string {
	out := make(map[string]string)
	parts := strings.Split(ext, " ")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 { out[kv[0]] = kv[1] }
	}
	return out
}
