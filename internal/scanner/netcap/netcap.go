package netcap

import (
	"strings"
	"context"
	"fmt"

	"github.com/vsp/platform/internal/netcap"
	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{ Engine *netcap.Engine }
func New(e *netcap.Engine) *Adapter { return &Adapter{Engine: e} }
func (a *Adapter) Name() string { return "netcap" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	if a.Engine == nil || !a.Engine.IsRunning() {
		return nil, fmt.Errorf("netcap: engine not running")
	}
	var findings []scanner.Finding

	for _, anom := range a.Engine.GetAnomalies(500) {
		sev := strings.ToUpper(anom.Severity)
		findings = append(findings, scanner.Finding{
			Tool: "netcap", Severity: scanner.Severity(sev),
			RuleID: anom.MITRE, CWE: mitreACWE(anom.MITRE),
			Message: fmt.Sprintf("[%s/%s] %s — %s (src:%s)", anom.Layer, anom.Proto, anom.Type, anom.Detail, anom.SrcIP),
			Path: fmt.Sprintf("network://%s->%s:%d", anom.SrcIP, anom.DstIP, anom.DstPort),
			FixSignal: mitigationFor(anom.Type),
		})
	}

	for _, q := range a.Engine.GetDNSQueries(200) {
		if q.Flag == "" { continue }
		findings = append(findings, scanner.Finding{
			Tool: "netcap", Severity: "HIGH",
			RuleID: "T1071.004", CWE: "CWE-201",
			Message: fmt.Sprintf("[L7/DNS] %s query: %s (entropy=%.2f) from %s", q.Flag, q.Query, q.Entropy, q.SrcIP),
			Path: "network://dns/" + q.Query,
			FixSignal: "Block DNS TXT queries with high entropy. Use DNS firewall.",
		})
	}

	for _, t := range a.Engine.GetTLSSessions(200) {
		if t.Risk == "ok" { continue }
		sev := "MEDIUM"
		if t.KnownBad { sev = "CRITICAL" }
		findings = append(findings, scanner.Finding{
			Tool: "netcap", Severity: scanner.Severity(sev),
			RuleID: "T1071.001", CWE: "CWE-326",
			Message: fmt.Sprintf("[L5/TLS] Risk=%s version=%s SNI=%s JA3=%s from %s", t.Risk, t.Version, t.SNI, t.JA3, t.ClientIP),
			Path: "network://tls/" + t.SNI,
			FixSignal: "Enforce TLS 1.2+. Disable weak ciphers. Enable HSTS.",
		})
	}
	return findings, nil
}

func mitreACWE(m string) string {
	cwe := map[string]string{
		"T1046":"CWE-200","T1110":"CWE-307","T1071.004":"CWE-201",
		"T1071.001":"CWE-326","T1190":"CWE-89","T1557":"CWE-300",
	}
	if v, ok := cwe[m]; ok { return v }
	return "CWE-200"
}

func mitigationFor(t string) string {
	m := map[string]string{
		"Port Scan": "Block src IP. Enable IDS/IPS port scan detection.",
		"SSH Brute Force": "Enable fail2ban. Key-only SSH auth.",
		"ARP Spoofing": "Enable Dynamic ARP Inspection on switches.",
		"DNS Tunneling": "Block TXT queries. Monitor high-entropy subdomains.",
		"SQL Injection": "Use parameterized queries. Enable WAF.",
	}
	if v, ok := m[t]; ok { return v }
	return "Investigate event. Apply network segmentation."
}
