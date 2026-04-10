package license

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type LicensePolicy struct {
	Allowed    []string
	Restricted []string
	Forbidden  []string
}

var DefaultPolicy = LicensePolicy{
	Allowed:    []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"},
	Restricted: []string{"LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"},
	Forbidden:  []string{"GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"},
}

type Component struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	License       string `json:"license"`
	Type          string `json:"type"`
	PolicyStatus  string `json:"policy_status"`
	RiskLevel     string `json:"risk_level"`
	NTIACompliant bool   `json:"ntia_compliant"`
}

type ScanResult struct {
	Components []Component `json:"components"`
	Total      int         `json:"total"`
	Allowed    int         `json:"allowed"`
	Restricted int         `json:"restricted"`
	Forbidden  int         `json:"forbidden"`
	Unknown    int         `json:"unknown"`
	NTIAScore  float64     `json:"ntia_score"`
}

type Scanner struct{ policy LicensePolicy }

func NewScanner(policy LicensePolicy) *Scanner { return &Scanner{policy: policy} }

func (s *Scanner) Scan(projectPath string) (*ScanResult, error) {
	var components []Component
	if goComps, err := s.scanGoModules(projectPath); err == nil {
		components = append(components, goComps...)
	}
	if _, err := os.Stat(filepath.Join(projectPath, "package.json")); err == nil {
		if npmComps, err := s.scanNPM(projectPath); err == nil {
			components = append(components, npmComps...)
		}
	}
	result := &ScanResult{Components: components, Total: len(components)}
	ntia := 0
	for i := range components {
		components[i].PolicyStatus = s.checkPolicy(components[i].License)
		components[i].RiskLevel = policyToRisk(components[i].PolicyStatus)
		components[i].NTIACompliant = components[i].License != "" && components[i].License != "UNKNOWN"
		if components[i].NTIACompliant {
			ntia++
		}
		switch components[i].PolicyStatus {
		case "allowed":
			result.Allowed++
		case "restricted":
			result.Restricted++
		case "forbidden":
			result.Forbidden++
		default:
			result.Unknown++
		}
	}
	if result.Total > 0 {
		result.NTIAScore = float64(ntia) / float64(result.Total) * 100
	}
	return result, nil
}

func (s *Scanner) scanGoModules(projectPath string) ([]Component, error) {
	f, err := os.Open(filepath.Join(projectPath, "go.mod"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var comps []Component
	sc := bufio.NewScanner(f)
	inReq := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "require (" {
			inReq = true
			continue
		}
		if line == ")" {
			inReq = false
			continue
		}
		if !inReq && !strings.HasPrefix(line, "require ") {
			continue
		}
		line = strings.TrimPrefix(line, "require ")
		parts := strings.Fields(line)
		if len(parts) < 2 || strings.HasPrefix(parts[0], "//") {
			continue
		}
		ver := strings.TrimSuffix(parts[1], "// indirect")
		comps = append(comps, Component{
			Name: parts[0], Version: strings.TrimSpace(ver),
			License: guessGoLicense(parts[0]), Type: "go",
		})
	}
	return comps, nil
}

func (s *Scanner) scanNPM(projectPath string) ([]Component, error) {
	f, err := os.Open(filepath.Join(projectPath, "package.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.NewDecoder(f).Decode(&pkg); err != nil {
		return nil, err
	}
	var comps []Component
	for name, ver := range pkg.Dependencies {
		comps = append(comps, Component{Name: name, Version: ver, License: "UNKNOWN", Type: "npm"})
	}
	return comps, nil
}

func (s *Scanner) checkPolicy(license string) string {
	if license == "" || license == "UNKNOWN" {
		return "unknown"
	}
	up := strings.ToUpper(license)
	for _, f := range s.policy.Forbidden {
		if strings.Contains(up, strings.ToUpper(f)) {
			return "forbidden"
		}
	}
	for _, r := range s.policy.Restricted {
		if strings.Contains(up, strings.ToUpper(r)) {
			return "restricted"
		}
	}
	for _, a := range s.policy.Allowed {
		if strings.Contains(up, strings.ToUpper(a)) {
			return "allowed"
		}
	}
	return "unknown"
}

func policyToRisk(status string) string {
	switch status {
	case "forbidden":
		return "CRITICAL"
	case "restricted":
		return "MEDIUM"
	case "allowed":
		return "LOW"
	default:
		return "INFO"
	}
}

func guessGoLicense(module string) string {
	known := map[string]string{
		"github.com/go-chi/chi":        "MIT",
		"github.com/rs/zerolog":        "MIT",
		"github.com/jackc/pgx":         "MIT",
		"github.com/golang-jwt/jwt":    "MIT",
		"github.com/spf13/viper":       "MIT",
		"github.com/stripe/stripe-go":  "Apache-2.0",
		"golang.org/x/crypto":          "BSD-3-Clause",
		"golang.org/x/net":             "BSD-3-Clause",
		"github.com/prometheus/client": "Apache-2.0",
	}
	for prefix, lic := range known {
		if strings.HasPrefix(module, prefix) {
			return lic
		}
	}
	return "UNKNOWN"
}
