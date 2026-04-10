package sslscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/vsp/platform/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "sslscan" }

func (a *Adapter) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	target := opts.URL
	if target == "" {
		return nil, nil
	}
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	res, err := scanner.Run(ctx, "sslscan", "--no-colour", "--no-failed", target)
	if err != nil {
		return nil, nil
	}
	return parseSSLScan(res.Stdout, target)
}

func parseSSLScan(output []byte, target string) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	sc := bufio.NewScanner(bytes.NewReader(output))

	// ── Regex ─────────────────────────────────────────────────────────────────
	// Weak cipher pattern
	weakRe := regexp.MustCompile(`(?i)(RC4|DES|3DES|EXPORT|NULL|ANON|MD5|ADH|AECDH|eNULL|aNULL)`)

	// sslscan --no-colour cipher line format:
	//   Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256
	//   Accepted  TLSv1.0   56 bits  DES-CBC3-SHA
	// Fields: [0]=Accepted/Rejected [1]=TLSv1.x [2]=bits_num [3]="bits" [4]=CIPHER_NAME
	cipherLineRe := regexp.MustCompile(`(?i)^(\s*)(Accepted|Rejected)\s+(\S+)\s+(\d+)\s+bits\s+(\S+)`)

	var hasSSL2, hasSSL3, hasTLS10, hasTLS11 bool

	// weakCipherInfo stores {name, tlsVersion, bits} for rich message
	type cipherInfo struct {
		name       string
		tlsVersion string
		bits       string
	}
	var weakCiphers []cipherInfo

	for sc.Scan() {
		line := sc.Text()

		// ── Protocol detection ──────────────────────────────────────────────
		if strings.Contains(line, "SSLv2") && strings.Contains(line, "enabled") {
			hasSSL2 = true
		}
		if strings.Contains(line, "SSLv3") && strings.Contains(line, "enabled") {
			hasSSL3 = true
		}
		if strings.Contains(line, "TLSv1.0") && strings.Contains(line, "enabled") {
			hasTLS10 = true
		}
		if strings.Contains(line, "TLSv1.1") && strings.Contains(line, "enabled") {
			hasTLS11 = true
		}

		// ── Cipher detection — extract actual cipher name ────────────────────
		// Only process "Accepted" lines (skip "Rejected")
		if !strings.Contains(strings.ToLower(line), "accepted") {
			continue
		}
		if !weakRe.MatchString(line) {
			continue
		}

		// Try structured parse first
		if m := cipherLineRe.FindStringSubmatch(line); len(m) >= 6 {
			// m[3]=TLSversion m[4]=bits m[5]=CipherName
			weakCiphers = append(weakCiphers, cipherInfo{
				name:       m[5],
				tlsVersion: m[3],
				bits:       m[4],
			})
			continue
		}

		// Fallback: take last non-empty field as cipher name
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			cipherName := fields[len(fields)-1]
			tlsVer := ""
			if len(fields) >= 3 {
				tlsVer = fields[1]
			}
			weakCiphers = append(weakCiphers, cipherInfo{
				name:       cipherName,
				tlsVersion: tlsVer,
			})
		}
	}

	// ── Build findings ────────────────────────────────────────────────────────
	add := func(sev, rule, cwe, msg, fix string) {
		findings = append(findings, scanner.Finding{
			Tool:      "sslscan",
			Severity:  scanner.Severity(sev),
			RuleID:    rule,
			CWE:       cwe,
			Message:   fmt.Sprintf("[%s] %s — target: %s", rule, msg, target),
			Path:      "network://tls/" + target,
			FixSignal: fix,
		})
	}

	if hasSSL2 {
		add("CRITICAL", "SSL-001", "CWE-326",
			"SSLv2 enabled — DROWN attack possible",
			"Disable SSLv2. Use TLSv1.2+")
	}
	if hasSSL3 {
		add("CRITICAL", "SSL-002", "CWE-326",
			"SSLv3 enabled — POODLE attack (CVE-2014-3566)",
			"Disable SSLv3. Use TLSv1.2+")
	}
	if hasTLS10 {
		add("HIGH", "SSL-003", "CWE-326",
			"TLSv1.0 enabled — deprecated per RFC 8996",
			"Disable TLSv1.0. Minimum TLSv1.2")
	}
	if hasTLS11 {
		add("MEDIUM", "SSL-004", "CWE-326",
			"TLSv1.1 enabled — deprecated per RFC 8996",
			"Disable TLSv1.1. Minimum TLSv1.2")
	}

	if len(weakCiphers) > 0 {
		// Build rich cipher list: "RC4-SHA (TLSv1.0, 128bit), DES-CBC3-SHA (TLSv1.1, 56bit)"
		parts := make([]string, 0, len(weakCiphers))
		for _, c := range weakCiphers {
			if c.tlsVersion != "" && c.bits != "" {
				parts = append(parts, fmt.Sprintf("%s (%s, %sbit)", c.name, c.tlsVersion, c.bits))
			} else if c.tlsVersion != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", c.name, c.tlsVersion))
			} else {
				parts = append(parts, c.name)
			}
		}
		add("HIGH", "SSL-005", "CWE-327",
			fmt.Sprintf("%d weak cipher(s): %s", len(weakCiphers), strings.Join(parts, ", ")),
			"Remove RC4/DES/3DES/EXPORT ciphers. Use ECDHE+AES-GCM only")
	}

	return findings, nil
}
