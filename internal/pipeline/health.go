package pipeline

import (
	"os/exec"

	"github.com/rs/zerolog/log"
)

// scannerBinaries maps each runner Name() to the OS binary it shells out
// to. Used by ProbeScannerBinaries at gateway boot so operators see a
// clear "X tools dispatchable / 26 expected" line in the log instead of
// discovering missing binaries only when a FULL_SOC run produces partial
// results.
//
// netcap has no external binary (it's the gopacket Engine pointer set
// via SetNetcapEngine) — it's checked separately and reported by the
// "netcap_engine_registered" line in the probe output.
//
// codeql / cosign / syft / govulncheck install in CI runners but may
// be absent on bare developer laptops — that's fine, they just won't
// dispatch. The probe is informational, not fatal.
var scannerBinaries = map[string]string{
	"bandit":      "bandit",
	"semgrep":     "semgrep",
	"codeql":      "codeql",
	"gosec":       "gosec",
	"trivy":       "trivy",
	"grype":       "grype",
	"license":     "license_finder", // ruby gem
	"osv-scanner": "osv-scanner",
	"cosign":      "cosign",
	"retire-js":   "retire",
	"syft":        "syft",
	"govulncheck": "govulncheck",
	"gitleaks":    "gitleaks",
	"secretcheck": "trufflehog", // shares trufflehog binary
	"trufflehog":  "trufflehog",
	"kics":        "kics",
	"checkov":     "checkov",
	"hadolint":    "hadolint",
	"nikto":       "nikto",
	"nuclei":      "nuclei",
	"sslscan":     "sslscan",
	"nmap":        "nmap",
	"apisec":      "", // built-in Go scanner — always present
	"gofuzz":      "go",
	"racedetect":  "go",
}

// ScannerHealth is the per-tool health payload returned by the
// /api/v1/scanners/health endpoint.
type ScannerHealth struct {
	Tool        string `json:"tool"`
	Binary      string `json:"binary,omitempty"`
	Available   bool   `json:"available"`
	BuiltIn     bool   `json:"built_in,omitempty"`
	NetcapEngine bool  `json:"netcap_engine,omitempty"`
}

// HealthSnapshot returns the current scanner availability map. Cheap
// (does an exec.LookPath per tool) — safe to call on every health-probe.
// Used by /api/v1/scanners/health to drive the FE "X / 26 ready" badge.
func HealthSnapshot() (available int, results []ScannerHealth) {
	results = make([]ScannerHealth, 0, len(scannerBinaries)+1)
	for tool, binary := range scannerBinaries {
		h := ScannerHealth{Tool: tool, Binary: binary}
		if binary == "" {
			h.Available = true
			h.BuiltIn = true
			available++
		} else if _, err := exec.LookPath(binary); err == nil {
			h.Available = true
			available++
		}
		results = append(results, h)
	}
	netcap := ScannerHealth{Tool: "netcap", NetcapEngine: true, Available: netcapEngine != nil}
	if netcapEngine != nil {
		available++
	}
	results = append(results, netcap)
	return
}

// ProbeScannerBinaries inspects $PATH for each scanner binary and logs
// a per-tool status. Call from main() right after pipeline.SetNetcapEngine.
//
// Returns the count of tools whose binary was located. With a fully
// provisioned image this should match len(scannerBinaries) (=24 + 2
// built-ins + netcap = 26).
func ProbeScannerBinaries() int {
	available := 0
	missing := []string{}
	for tool, binary := range scannerBinaries {
		if binary == "" {
			// Built-in Go scanner — counts as present.
			available++
			continue
		}
		if _, err := exec.LookPath(binary); err == nil {
			available++
		} else {
			missing = append(missing, tool+"("+binary+")")
		}
	}
	netcapStatus := "absent"
	if netcapEngine != nil {
		netcapStatus = "registered"
		available++
	}
	log.Info().
		Int("available", available).
		Int("expected_full_soc", 26).
		Int("missing_count", len(missing)).
		Strs("missing_tools", missing).
		Str("netcap_engine", netcapStatus).
		Msg("scanner pre-flight probe")
	if len(missing) > 0 {
		log.Warn().
			Strs("install", missing).
			Msg("scanner binaries missing — FULL_SOC runs will dispatch the runner but record ErrToolNotFound; install these for full coverage")
	}
	return available
}
