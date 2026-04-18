package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vsp/platform/internal/scanner"
)

type Finding struct {
	Host        string
	Port        int
	Protocol    string
	State       string
	Service     string
	Version     string
	CPE         string
	Severity    string
	Description string
}

type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}
type Host struct {
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Ports     Ports     `xml:"ports"`
	OS        OS        `xml:"os"`
}
type Status struct {
	State string `xml:"state,attr"`
}
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type Ports struct {
	Ports []Port `xml:"port"`
}
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}
type State struct {
	State string `xml:"state,attr"`
}
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	CPE     []CPE  `xml:"cpe"`
}
type CPE struct {
	Value string `xml:",chardata"`
}
type OS struct {
	Matches []OSMatch `xml:"osmatch"`
}
type OSMatch struct {
	Name string `xml:"name,attr"`
}

var riskyPorts = map[int]string{
	21:    "FTP plaintext auth — anonymous access risk",
	22:    "SSH — check version, brute force target",
	23:    "Telnet — plaintext, no encryption, REPLACE IMMEDIATELY",
	25:    "SMTP — check open relay",
	53:    "DNS — check zone transfer",
	80:    "HTTP — unencrypted web service",
	135:   "RPC — Windows attack surface",
	139:   "NetBIOS — lateral movement risk",
	443:   "HTTPS — check TLS version",
	445:   "SMB — EternalBlue ransomware vector",
	1433:  "MSSQL — database exposed to network",
	1521:  "Oracle DB — database exposed",
	3306:  "MySQL — database exposed",
	3389:  "RDP — brute force / BlueKeep target",
	5432:  "PostgreSQL — database exposed",
	5900:  "VNC — often no authentication",
	6379:  "Redis — often no auth, RCE risk",
	8080:  "HTTP-alt — dev server exposed",
	8443:  "HTTPS-alt — check TLS config",
	9200:  "Elasticsearch — often no auth, data exposure",
	27017: "MongoDB — often no auth, data exposure",
}

func portSeverity(port int) string {
	switch port {
	case 23, 445, 3389, 5900, 6379, 9200, 27017:
		return "CRITICAL"
	case 21, 135, 139, 1433, 1521, 3306, 5432:
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

type Scanner struct {
	Timeout time.Duration
}

func New() *Scanner {
	return &Scanner{Timeout: 5 * time.Minute}
}

func (s *Scanner) Name() string { return "nmap" }

func (s *Scanner) Run(ctx context.Context, opts scanner.RunOpts) ([]scanner.Finding, error) {
	target := opts.URL
	if target == "" {
		// fallback to localhost scan
		target = "127.0.0.1"
		target = "127.0.0.1"
	}
	findings, err := s.scan(ctx, target)
	if err != nil {
		return nil, err
	}
	var out []scanner.Finding
	for _, f := range findings {
		ruleID := fmt.Sprintf("NMAP-%d-%s", f.Port, strings.ToUpper(f.Protocol))
		msg := fmt.Sprintf("[%s:%d/%s] %s", f.Host, f.Port, f.Protocol, f.Description)
		if f.Version != "" {
			msg += " — Version: " + f.Version
		}
		out = append(out, scanner.Finding{
			Tool:     "nmap",
			Severity: scanner.NormaliseSeverity(f.Severity),
			RuleID:   ruleID,
			Message:  msg,
			Path:     fmt.Sprintf("%s:%d", f.Host, f.Port),
		})
	}
	return out, nil
}

func (s *Scanner) scan(ctx context.Context, target string) ([]Finding, error) {
	if _, err := exec.LookPath("nmap"); err != nil {
		return s.fallbackScan(ctx, target)
	}
	ctx2, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "nmap",
		"-sV", "--top-ports", "1000", "-T4", "--open", "-oX", "-", target)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return s.fallbackScan(ctx, target)
	}
	return parseNmapXML(out.Bytes())
}

func parseNmapXML(data []byte) ([]Finding, error) {
	var run NmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap XML: %v", err)
	}
	var findings []Finding
	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}
		var ip string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ip = addr.Addr
			}
		}
		osName := ""
		if len(host.OS.Matches) > 0 {
			osName = host.OS.Matches[0].Name
		}
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			desc := riskyPorts[port.PortID]
			if desc == "" {
				desc = fmt.Sprintf("Port %d/%s open — %s %s",
					port.PortID, port.Protocol,
					port.Service.Product, port.Service.Version)
			}
			var cpes []string
			for _, c := range port.Service.CPE {
				cpes = append(cpes, c.Value)
			}
			_ = osName
			findings = append(findings, Finding{
				Host:        ip,
				Port:        port.PortID,
				Protocol:    port.Protocol,
				State:       port.State.State,
				Service:     port.Service.Name,
				Version:     strings.TrimSpace(port.Service.Product + " " + port.Service.Version),
				CPE:         strings.Join(cpes, ","),
				Severity:    portSeverity(port.PortID),
				Description: desc,
			})
		}
	}
	return findings, nil
}

func (s *Scanner) fallbackScan(ctx context.Context, target string) ([]Finding, error) {
	ports := []int{21, 22, 23, 25, 53, 80, 135, 139, 443, 445,
		1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}
	var findings []Finding
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		conn.Close()
		findings = append(findings, Finding{
			Host:        target,
			Port:        port,
			Protocol:    "tcp",
			State:       "open",
			Service:     strconv.Itoa(port),
			Severity:    portSeverity(port),
			Description: riskyPorts[port],
		})
	}
	return findings, nil
}
