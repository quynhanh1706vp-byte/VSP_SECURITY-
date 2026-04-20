package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const version = "0.1.0"

type SoftwareAsset struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor"`
	InstallPath string `json:"install_path"`
	Source      string `json:"source"`
}

type AgentReport struct {
	Hostname  string          `json:"hostname"`
	OS        string          `json:"os"`
	Arch      string          `json:"arch"`
	Timestamp time.Time       `json:"timestamp"`
	Assets    []SoftwareAsset `json:"assets"`
	AgentVer  string          `json:"agent_version"`
}

func collectLinux() []SoftwareAsset {
	var assets []SoftwareAsset
	hostname, _ := os.Hostname()
	osStr := runtime.GOOS + "/" + runtime.GOARCH

	// dpkg
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 2 && parts[0] != "" {
				assets = append(assets, SoftwareAsset{
					Hostname: hostname, OS: osStr,
					Name: parts[0], Version: parts[1],
					Vendor: func() string {
						if len(parts) > 2 {
							return parts[2]
						}
						return ""
					}(),
					Source: "dpkg",
				})
			}
		}
	}

	// rpm fallback
	if len(assets) == 0 {
		out, err = exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.Split(line, "\t")
				if len(parts) >= 2 && parts[0] != "" {
					assets = append(assets, SoftwareAsset{
						Hostname: hostname, OS: osStr,
						Name: parts[0], Version: parts[1],
						Vendor: func() string {
							if len(parts) > 2 {
								return parts[2]
							}
							return ""
						}(),
						Source: "rpm",
					})
				}
			}
		}
	}

	return assets
}

func collectWindows() []SoftwareAsset {
	var assets []SoftwareAsset
	hostname, _ := os.Hostname()
	osStr := "windows/" + runtime.GOARCH

	// PowerShell Get-Package
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-Package | Select-Object Name,Version,ProviderName | ConvertTo-Json").Output()
	if err == nil {
		var pkgs []map[string]interface{}
		if json.Unmarshal(out, &pkgs) == nil {
			for _, p := range pkgs {
				name, _ := p["Name"].(string)
				ver, _ := p["Version"].(string)
				prov, _ := p["ProviderName"].(string)
				if name != "" {
					assets = append(assets, SoftwareAsset{
						Hostname: hostname, OS: osStr,
						Name: name, Version: ver, Source: prov,
					})
				}
			}
		}
	}
	return assets
}

func main() {
	server := flag.String("server", "http://localhost:8921", "VSP server URL")
	token := flag.String("token", "", "Agent token")
	dryRun := flag.Bool("dry-run", false, "Print collected data without sending")
	flag.Parse()

	hostname, _ := os.Hostname()

	var assets []SoftwareAsset
	if runtime.GOOS == "windows" {
		assets = collectWindows()
	} else {
		assets = collectLinux()
	}

	report := AgentReport{
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Timestamp: time.Now(),
		Assets:    assets,
		AgentVer:  version,
	}

	fmt.Printf("[VSP Agent v%s] Collected %d packages from %s (%s/%s)\n",
		version, len(assets), hostname, runtime.GOOS, runtime.GOARCH)

	if *dryRun {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	if *token == "" {
		fmt.Fprintln(os.Stderr, "Error: --token required")
		os.Exit(1)
	}

	data, _ := json.Marshal(report)

	// TLS verification: defaults to strict verify.
	// Opt-out via VSP_AGENT_ALLOW_INSECURE_TLS=true (dev/self-signed gateway only).
	allowInsecure := os.Getenv("VSP_AGENT_ALLOW_INSECURE_TLS") == "true"
	if allowInsecure {
		fmt.Fprintln(os.Stderr,
			"WARNING: TLS verification DISABLED via VSP_AGENT_ALLOW_INSECURE_TLS. Not for production.")
	}
	// #nosec G402 -- InsecureSkipVerify gated by VSP_AGENT_ALLOW_INSECURE_TLS env var (dev only)
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: allowInsecure,
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	req, _ := http.NewRequest("POST",
		*server+"/api/v1/software-inventory/report", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+*token)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending report: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("[VSP Agent] Report sent: HTTP %d\n", resp.StatusCode)
}
