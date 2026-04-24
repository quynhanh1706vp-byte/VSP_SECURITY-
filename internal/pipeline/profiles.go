package pipeline

import "github.com/vsp/platform/internal/scanner"

type ProfileConfig struct {
	TimeoutSec  int
	Description string
}

var Profiles = map[Profile]ProfileConfig{
	ProfileFast:    {TimeoutSec: 120, Description: "Fast — core tools, 2min"},
	ProfileExt:     {TimeoutSec: 360, Description: "Extended — all tools, 6min"},
	ProfileAggr:    {TimeoutSec: 600, Description: "Aggressive — fail on any HIGH"},
	ProfilePremium: {TimeoutSec: 900, Description: "Premium — deep scan 15min"},
	ProfileFull:    {TimeoutSec: 1200, Description: "Full — all tools 20min"},
	ProfileFullSOC: {TimeoutSec: 1800, Description: "Full SOC — max depth"},
}

var fastTools = map[string]bool{
	"kics": true, "checkov": true, "hadolint": true,
	"bandit": true, "trivy": true, "gitleaks": true, "nikto": true,
}

var extTools = map[string]bool{
	"kics": true, "checkov": true, "hadolint": true,
	"bandit": true, "semgrep": true,
	"trivy": true, "grype": true,
	"gitleaks": true, "secretcheck": true,
	"nikto": true, "sslscan": true,
}

var aggrTools = map[string]bool{
	"kics": true, "checkov": true, "hadolint": true,
	"bandit": true, "semgrep": true, "codeql": true,
	"trivy": true, "grype": true, "license": true,
	"gitleaks": true, "secretcheck": true,
	"nikto": true, "nuclei": true, "sslscan": true,
	"gosec": true,
	"trufflehog": true,
	"nmap": true,
	"syft": true,
	"govulncheck": true,
	"osv-scanner": true,
	"cosign": true,
	"retire-js": true,
}

func filterRunners(runners []scanner.Runner, allowed map[string]bool) []scanner.Runner {
	out := make([]scanner.Runner, 0, len(runners))
	for _, r := range runners {
		if allowed[r.Name()] {
			out = append(out, r)
		}
	}
	return out
}

func RunnersForProfile(mode Mode, profile Profile) []scanner.Runner {
	all := RunnersFor(mode)
	switch profile {
	case ProfileFast:
		return filterRunners(all, fastTools)
	case ProfileExt:
		return filterRunners(all, extTools)
	case ProfileAggr:
		return filterRunners(all, aggrTools)
	case ProfilePremium, ProfileFull, ProfileFullSOC:
		return all
	default:
		return filterRunners(all, fastTools)
	}
}

func TimeoutForProfile(profile Profile) int {
	if cfg, ok := Profiles[profile]; ok {
		return cfg.TimeoutSec
	}
	return 120
}

func ToolNamesForMode(mode Mode) []string {
	switch mode {
	case ModeSAST:
		return []string{"bandit", "semgrep", "codeql", "gosec"}
	case ModeSCA:
		return []string{"trivy", "grype", "license", "syft", "govulncheck", "osv-scanner", "retire-js"}
	case ModeSecrets:
		return []string{"gitleaks", "secretcheck", "trufflehog"}
	case ModeIAC:
		return []string{"kics", "checkov", "hadolint"}
	case ModeDAST:
		return []string{"nikto", "nuclei", "sslscan"}
	case ModeNetwork:
		return []string{"sslscan", "nmap", "netcap"}
	case ModeFull, ModeFullSOC:
		return []string{
			"kics", "checkov", "hadolint",
			"bandit", "semgrep", "codeql", "gosec",
			"trivy", "grype", "license", "syft", "govulncheck",
			"gitleaks", "secretcheck", "trufflehog",
			"nikto", "nuclei", "sslscan",
			"nmap", "netcap",
			"osv-scanner", "cosign", "retire-js",
		}
	default:
		return []string{"bandit", "semgrep", "trivy", "grype", "gitleaks", "secretcheck"}
	}
}
