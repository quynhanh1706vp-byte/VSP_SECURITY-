// cmd/sw-agent/main.go
//
// VSP Software Inventory Agent
// ────────────────────────────────────────────────────────────────────
// Lightweight cross-platform agent that enumerates installed packages
// and pushes them to the SW Inventory microservice.
//
// Supports:
//   - dpkg     (Debian, Ubuntu, Mint, ...)
//   - rpm      (RHEL, CentOS, Fedora, openSUSE, Amazon Linux)
//   - apk      (Alpine)
//   - pacman   (Arch — best-effort)
//
// Run:
//   ./vsp-sw-agent -api http://VSP_HOST:8094 -key $(cat /etc/vsp/sw-agent.key)
//   ./vsp-sw-agent -once   # single submission then exit (cron-friendly)
//   ./vsp-sw-agent         # daemon mode, every 30 min
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const agentVersion = "1.0.0"

var (
	apiURL   = flag.String("api", "http://127.0.0.1:8094", "SW Inventory API base URL")
	apiKey   = flag.String("key", "", "X-Agent-Key (default: read /etc/vsp/sw-agent.key)")
	keyFile  = flag.String("key-file", "/etc/vsp/sw-agent.key", "fallback key file if -key not given")
	once     = flag.Bool("once", false, "submit once and exit")
	interval = flag.Duration("interval", 30*time.Minute, "report interval in daemon mode")
	hostname = flag.String("hostname", "", "override hostname")
	verbose  = flag.Bool("v", false, "verbose")
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Arch    string `json:"arch,omitempty"`
}

type Report struct {
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	Kernel       string    `json:"kernel"`
	IPAddress    string    `json:"ip_address"`
	AgentVersion string    `json:"agent_version"`
	Packages     []Package `json:"packages"`
	CollectedAt  time.Time `json:"collected_at"`
}

func main() {
	flag.Parse()

	if *apiKey == "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("[boot] no -key given and cannot read %s: %v", *keyFile, err)
		}
		*apiKey = strings.TrimSpace(string(b))
	}

	if *once {
		runOnce()
		return
	}
	for {
		runOnce()
		time.Sleep(*interval)
	}
}

func runOnce() {
	rep := collect()
	if *verbose {
		log.Printf("collected: host=%s os=%s pkgs=%d", rep.Hostname, rep.OS, len(rep.Packages))
	}
	if err := submit(rep); err != nil {
		log.Printf("[err] submit: %v", err)
		return
	}
	log.Printf("[ok] submitted: host=%s pkgs=%d", rep.Hostname, len(rep.Packages))
}

func collect() Report {
	host := *hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	osName, osVer := detectOS()
	rep := Report{
		Hostname:     host,
		OS:           osName,
		OSVersion:    osVer,
		Kernel:       detectKernel(),
		IPAddress:    detectIP(),
		AgentVersion: agentVersion,
		CollectedAt:  time.Now().UTC(),
	}
	rep.Packages = enumeratePackages()
	return rep
}

// ── OS detection ──────────────────────────────────────────────────────

func detectOS() (string, string) {
	if runtime.GOOS != "linux" {
		return runtime.GOOS, runtime.GOARCH
	}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux", "unknown"
	}
	name, ver := "linux", ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			ver = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return name, ver
}

func detectKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func detectIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			if ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}

// ── package enumeration ───────────────────────────────────────────────

func enumeratePackages() []Package {
	if pkgs := tryDpkg(); len(pkgs) > 0 {
		return pkgs
	}
	if pkgs := tryRpm(); len(pkgs) > 0 {
		return pkgs
	}
	if pkgs := tryApk(); len(pkgs) > 0 {
		return pkgs
	}
	if pkgs := tryPacman(); len(pkgs) > 0 {
		return pkgs
	}
	return nil
}

func tryDpkg() []Package {
	out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\n").Output()
	if err != nil {
		return nil
	}
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		p := Package{Name: parts[0], Version: parts[1], Source: "dpkg"}
		if len(parts) >= 3 {
			p.Arch = parts[2]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func tryRpm() []Package {
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n").Output()
	if err != nil {
		return nil
	}
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		p := Package{Name: parts[0], Version: parts[1], Source: "rpm"}
		if len(parts) >= 3 {
			p.Arch = parts[2]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func tryApk() []Package {
	out, err := exec.Command("apk", "info", "-v").Output()
	if err != nil {
		return nil
	}
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "name-version-rN" → split on last '-' where rest is a version
		idx := strings.LastIndex(line, "-")
		if idx < 0 {
			continue
		}
		name, ver := line[:idx], line[idx+1:]
		// some forms: name-1.2.3-r4 → split twice
		if idx2 := strings.LastIndex(name, "-"); idx2 >= 0 && len(name[idx2+1:]) > 0 && (name[idx2+1] >= '0' && name[idx2+1] <= '9') {
			ver = name[idx2+1:] + "-" + ver
			name = name[:idx2]
		}
		pkgs = append(pkgs, Package{Name: name, Version: ver, Source: "apk"})
	}
	return pkgs
}

func tryPacman() []Package {
	out, err := exec.Command("pacman", "-Q").Output()
	if err != nil {
		return nil
	}
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		pkgs = append(pkgs, Package{Name: parts[0], Version: parts[1], Source: "pacman"})
	}
	return pkgs
}

// ── submit ────────────────────────────────────────────────────────────

func submit(rep Report) error {
	url := strings.TrimRight(*apiURL, "/") + "/agent/report"
	body, _ := json.Marshal(rep)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", *apiKey)
	req.Header.Set("User-Agent", "vsp-sw-agent/"+agentVersion)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	if *verbose {
		log.Printf("server response: %s", string(respBody))
	}
	return nil
}
