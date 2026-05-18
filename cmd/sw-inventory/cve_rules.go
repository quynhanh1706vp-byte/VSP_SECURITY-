// cmd/sw-inventory/cve_rules.go
//
// Curated vulnerability rules. Match a package by name substring + version
// prefix. Designed to catch the famous 2014–2024 wave of supply chain CVEs
// without needing a network call to NVD/Trivy DB on every host report.
//
// Format: package name substring (lowercased), version prefix to match,
//
//	severity, CVE id, fixed-in version, CVSS score, short title.
//
// Matching uses strings.Contains on the lowercased package name and
// strings.HasPrefix on the raw version. This is intentionally fuzzy —
// a single rule can match (e.g.) "openssl", "libssl1.1", "openssl3".
package main

import "strings"

type vulnRule struct {
	pkgSubstr string
	verPrefix string
	severity  string
	cve       string
	fixedIn   string
	cvss      float64
	title     string
}

var vulnRules = []vulnRule{
	// ── Famous CVEs ────────────────────────────────────────────────────
	{"openssl", "1.0.1", "CRITICAL", "CVE-2014-0160", "1.0.1g", 7.5, "OpenSSL Heartbleed"},
	{"bash", "4.", "CRITICAL", "CVE-2014-6271", "4.3", 9.8, "Bash Shellshock"},
	{"glibc", "2.18", "CRITICAL", "CVE-2015-7547", "2.23", 9.8, "glibc getaddrinfo stack overflow (GHOST)"},
	{"glibc", "2.21", "CRITICAL", "CVE-2015-7547", "2.23", 9.8, "glibc getaddrinfo stack overflow (GHOST)"},
	{"log4j-core", "2.0", "CRITICAL", "CVE-2021-44228", "2.17.0", 10.0, "Apache Log4Shell"},
	{"log4j-core", "2.1", "CRITICAL", "CVE-2021-44228", "2.17.0", 10.0, "Apache Log4Shell"},
	{"log4j", "2.0", "CRITICAL", "CVE-2021-44228", "2.17.0", 10.0, "Apache Log4Shell"},
	{"log4j", "2.1", "CRITICAL", "CVE-2021-44228", "2.17.0", 10.0, "Apache Log4Shell"},
	{"polkit", "0.105", "HIGH", "CVE-2021-4034", "0.121", 7.8, "PwnKit (polkit pkexec)"},
	{"polkit", "0.11", "HIGH", "CVE-2021-4034", "0.121", 7.8, "PwnKit (polkit pkexec)"},
	{"sudo", "1.8.", "HIGH", "CVE-2021-3156", "1.9.5p2", 7.8, "Sudo Baron Samedit"},
	{"sudo", "1.9.0", "HIGH", "CVE-2021-3156", "1.9.5p2", 7.8, "Sudo Baron Samedit"},
	{"sudo", "1.9.1", "HIGH", "CVE-2021-3156", "1.9.5p2", 7.8, "Sudo Baron Samedit"},

	// ── Network / TLS ──────────────────────────────────────────────────
	{"openssl", "1.1.0", "HIGH", "CVE-2016-2107", "1.1.0", 5.9, "OpenSSL padding-oracle (CBC)"},
	{"openssl", "3.0.", "MEDIUM", "CVE-2023-0286", "3.0.8", 7.4, "OpenSSL X.400 GeneralName type confusion"},
	{"openssl", "3.1.", "MEDIUM", "CVE-2023-2650", "3.1.1", 5.5, "OpenSSL OBJ_obj2txt resource exhaustion"},
	{"curl", "7.6", "MEDIUM", "CVE-2022-22576", "7.83.0", 8.1, "curl OAUTH2 connection reuse"},
	{"curl", "7.7", "MEDIUM", "CVE-2023-23914", "8.0.0", 9.1, "curl HSTS bypass"},
	{"curl", "8.0", "HIGH", "CVE-2023-38545", "8.4.0", 8.4, "curl SOCKS5 heap overflow"},
	{"curl", "8.1", "HIGH", "CVE-2023-38545", "8.4.0", 8.4, "curl SOCKS5 heap overflow"},
	{"curl", "8.2", "HIGH", "CVE-2023-38545", "8.4.0", 8.4, "curl SOCKS5 heap overflow"},
	{"curl", "8.3", "HIGH", "CVE-2023-38545", "8.4.0", 8.4, "curl SOCKS5 heap overflow"},

	// ── Compression / parsing ──────────────────────────────────────────
	{"zlib", "1.2.11", "HIGH", "CVE-2018-25032", "1.2.12", 7.5, "zlib memory corruption in deflate"},
	{"libxml2", "2.9.", "MEDIUM", "CVE-2022-29824", "2.9.14", 6.5, "libxml2 integer overflow in xmlBuf"},
	{"libxml2", "2.10.", "MEDIUM", "CVE-2023-29469", "2.10.4", 6.5, "libxml2 hashing logic"},
	{"expat", "2.4.", "HIGH", "CVE-2022-25315", "2.4.5", 9.8, "Expat integer overflow in storeRawNames"},

	// ── Containers / runtimes ──────────────────────────────────────────
	{"runc", "1.0.", "HIGH", "CVE-2024-21626", "1.1.12", 8.6, "runc fd leak Leaky Vessels"},
	{"runc", "1.1.0", "HIGH", "CVE-2024-21626", "1.1.12", 8.6, "runc fd leak Leaky Vessels"},
	{"runc", "1.1.1", "HIGH", "CVE-2024-21626", "1.1.12", 8.6, "runc fd leak Leaky Vessels"},
	{"docker.io", "20.10", "MEDIUM", "CVE-2023-28842", "23.0.3", 6.8, "Docker swarm encrypted overlay bypass"},
	{"containerd", "1.6.", "HIGH", "CVE-2024-21626", "1.6.28", 8.6, "containerd shim Leaky Vessels"},

	// ── Dev-time toolchains ────────────────────────────────────────────
	{"git", "2.30", "HIGH", "CVE-2022-23521", "2.39.1", 9.8, "git gitattributes parsing"},
	{"git", "2.31", "HIGH", "CVE-2022-23521", "2.39.1", 9.8, "git gitattributes parsing"},
	{"git", "2.35", "HIGH", "CVE-2023-22490", "2.39.2", 5.5, "git smart-clone exfiltration"},
	{"openssh", "8.5", "HIGH", "CVE-2023-38408", "9.3p2", 9.8, "OpenSSH agent forwarding RCE"},
	{"openssh", "8.9", "HIGH", "CVE-2023-38408", "9.3p2", 9.8, "OpenSSH agent forwarding RCE"},
	{"openssh", "9.0", "HIGH", "CVE-2023-38408", "9.3p2", 9.8, "OpenSSH agent forwarding RCE"},
	{"openssh", "9.1", "HIGH", "CVE-2023-38408", "9.3p2", 9.8, "OpenSSH agent forwarding RCE"},
	{"openssh", "9.2", "HIGH", "CVE-2023-38408", "9.3p2", 9.8, "OpenSSH agent forwarding RCE"},
	{"openssh", "8.", "HIGH", "CVE-2024-6387", "9.8", 8.1, "OpenSSH regreSSHion (sshd race)"},
	{"openssh", "9.0", "HIGH", "CVE-2024-6387", "9.8", 8.1, "OpenSSH regreSSHion (sshd race)"},
	{"openssh", "9.1", "HIGH", "CVE-2024-6387", "9.8", 8.1, "OpenSSH regreSSHion (sshd race)"},
	{"openssh", "9.7", "HIGH", "CVE-2024-6387", "9.8", 8.1, "OpenSSH regreSSHion (sshd race)"},

	// ── Languages / package managers ───────────────────────────────────
	{"go", "1.20.", "HIGH", "CVE-2023-29402", "1.20.5", 9.8, "Go cgo arg injection"},
	{"go", "1.21.", "MEDIUM", "CVE-2024-24784", "1.21.8", 7.5, "Go net/mail address parsing"},
	{"node", "16.", "MEDIUM", "CVE-2023-30589", "20.3.1", 7.5, "Node llhttp HTTP smuggling"},
	{"node", "18.", "MEDIUM", "CVE-2023-30589", "20.3.1", 7.5, "Node llhttp HTTP smuggling"},
	{"python3", "3.8", "MEDIUM", "CVE-2023-24329", "3.11.4", 7.5, "Python urllib.parse blanklisted-scheme bypass"},
	{"python3", "3.9", "MEDIUM", "CVE-2023-24329", "3.11.4", 7.5, "Python urllib.parse blanklisted-scheme bypass"},
	{"python3", "3.10", "MEDIUM", "CVE-2023-24329", "3.11.4", 7.5, "Python urllib.parse blanklisted-scheme bypass"},

	// ── Kernels (Linux) ────────────────────────────────────────────────
	{"linux-image", "5.4", "HIGH", "CVE-2022-0185", "5.16.2", 8.4, "Linux fs context heap overflow"},
	{"linux-image", "5.10", "HIGH", "CVE-2023-32233", "6.4", 7.8, "Linux netfilter use-after-free"},
	{"linux-image", "5.15", "HIGH", "CVE-2023-32233", "6.4", 7.8, "Linux netfilter use-after-free"},
	{"linux-image", "6.0", "HIGH", "CVE-2024-1086", "6.7.5", 7.8, "Linux nf_tables use-after-free (n-day)"},
	{"linux-image", "6.1", "HIGH", "CVE-2024-1086", "6.7.5", 7.8, "Linux nf_tables use-after-free (n-day)"},

	// ── Web servers / app runtimes ─────────────────────────────────────
	{"nginx", "1.20", "HIGH", "CVE-2021-23017", "1.21.0", 9.4, "nginx resolver off-by-one"},
	{"nginx", "1.18", "HIGH", "CVE-2021-23017", "1.21.0", 9.4, "nginx resolver off-by-one"},
	{"apache2", "2.4.4", "HIGH", "CVE-2022-31813", "2.4.54", 9.8, "Apache mod_proxy_ajp request smuggling"},
	{"apache2", "2.4.5", "HIGH", "CVE-2022-31813", "2.4.54", 9.8, "Apache mod_proxy_ajp request smuggling"},
	{"redis", "6.0", "HIGH", "CVE-2023-28425", "7.0.10", 7.5, "Redis MSETNX denial of service"},
	{"redis", "6.2", "HIGH", "CVE-2023-28425", "7.0.10", 7.5, "Redis MSETNX denial of service"},
	{"redis", "7.0", "HIGH", "CVE-2023-28425", "7.0.10", 7.5, "Redis MSETNX denial of service"},
	{"postgresql-1", "13", "MEDIUM", "CVE-2023-5869", "16.1", 8.8, "PostgreSQL array modification overflow"},
}

// matchCVEsForHost runs the rule engine over a host's package list.
func matchCVEsForHost(h *Host) []CVEMatch {
	out := make([]CVEMatch, 0, 8)
	seen := map[string]bool{} // dedup by cve+pkg
	for _, p := range h.Packages {
		nlow := strings.ToLower(p.Name)
		for _, rule := range vulnRules {
			if !strings.Contains(nlow, rule.pkgSubstr) {
				continue
			}
			if rule.verPrefix != "" && !strings.HasPrefix(p.Version, rule.verPrefix) {
				continue
			}
			key := rule.cve + "|" + p.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, CVEMatch{
				CVE:      rule.cve,
				Severity: rule.severity,
				Package:  p.Name,
				Version:  p.Version,
				FixedIn:  rule.fixedIn,
				CVSS:     rule.cvss,
				Title:    rule.title,
			})
		}
	}
	return out
}
