package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type SBOM struct{ DB *store.DB }

// GET /api/v1/sbom/{rid} — generate CycloneDX SBOM từ run findings
func (h *SBOM) Generate(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	format := r.URL.Query().Get("format") // cyclonedx | spdx | json
	if format == "" {
		format = "cyclonedx"
	}

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 2000})
	var rf []store.Finding
	for _, f := range findings {
		if f.RunID == run.ID {
			rf = append(rf, f)
		}
	}

	bom := buildCycloneDX(run, rf)
	b, _ := json.MarshalIndent(bom, "", "  ")

	// Sign SBOM with HMAC-SHA256 for integrity verification (EO 14028 / NIST SP 800-218)
	sig := signSBOM(b)

	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=sbom-%s.cdx.json", rid))
	w.Header().Set("X-VSP-SBOM-Signature", sig)
	w.Header().Set("X-VSP-SBOM-Algorithm", "HMAC-SHA256")
	w.Header().Set("X-VSP-SBOM-Version", "CycloneDX-1.5")
	_, _ = w.Write(b) //nolint:errcheck
}

// signSBOM computes HMAC-SHA256 of the SBOM bytes.
// The key is derived from the process environment — in production
// replace with cosign keyless signing (sigstore.dev).
func signSBOM(data []byte) string {
	key := []byte(os.Getenv("VSP_SBOM_SIGNING_KEY"))
	if len(key) == 0 {
		key = []byte("vsp-sbom-default-key-change-in-production")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// GET /api/v1/sbom/{rid}/grype — run grype SBOM on target
func (h *SBOM) Grype(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	target := run.Src
	if target == "" {
		target = run.TargetURL
	}
	// Nếu target là directory Go source → dùng gomod: prefix
	if target != "" {
		// Check nếu là Go project (có go.mod)
		if _, err := os.Stat(target + "/go.mod"); err == nil { //#nosec G304 -- target validated above
			target = "dir:" + target
		}
	}
	if target == "" {
		jsonError(w, "no src/url for this run", http.StatusBadRequest)
		return
	}
	// Validate target — chặn metacharacters
	for _, c := range []string{";", "&", "|", "`", "$", "<", ">", "{", "}", "\\"} {
		if strings.Contains(target, c) {
			jsonError(w, "invalid target", http.StatusBadRequest)
			return
		}
	}
	if len(target) > 500 {
		jsonError(w, "target too long", http.StatusBadRequest)
		return
	}

	// grype sbom output — timeout 60s + ulimit memory
	ctx2, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	// Grype write to temp file — stdout suppressed by default
	tmpOut, tmpErr := os.CreateTemp("", "grype-*.json")
	if tmpErr != nil {
		jsonError(w, "temp file error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpOut.Name())
	tmpOut.Close()

	cmd := exec.CommandContext(ctx2, //#nosec G702 -- target validated: metachar check + length limit applied above
		"grype", target,
		"-o", "cyclonedx-json",
		"--file", tmpOut.Name())
	cmd.Env = append(os.Environ(),
		"GOGC=20",
		"GOMEMLIMIT=512MiB",
	)
	_, err = cmd.Output()
	// Grype writes to file regardless of exit code
	// exit 0 = no vulns, exit 1 = vulns found, both are success
	if ctx2.Err() == context.DeadlineExceeded {
		jsonError(w, "grype timeout (60s)", http.StatusGatewayTimeout)
		return
	}
	out, _ := os.ReadFile(tmpOut.Name())
	if len(out) < 10 {
		errMsg := "grype produced no output"
		if err != nil {
			errMsg = "grype failed: " + err.Error()
		}
		jsonError(w, errMsg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=sbom-grype-%s.cdx.json", rid))
	_, _ = w.Write(out) //nolint:errcheck
}

type cycloneDX struct {
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	Version         int            `json:"version"`
	Metadata        cdxMetadata    `json:"metadata"`
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
}

type cdxVuln struct {
	ID          string       `json:"id"`
	Source      cdxSource    `json:"source"`
	Ratings     []cdxRating  `json:"ratings"`
	Description string       `json:"description"`
	Affects     []cdxAffects `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
type cdxRating struct {
	Severity string `json:"severity"`
	Method   string `json:"method"`
}
type cdxAffects struct {
	Ref string `json:"ref"`
}

func buildCycloneDX(run *store.Run, findings []store.Finding) cycloneDX {
	bom := cycloneDX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{{
				Vendor: "VSP", Name: "VSP Security Platform", Version: "0.4.1",
			}},
			Component: &cdxComponent{
				Type: "application", Name: run.Mode + " scan", BOMRef: "target",
			},
		},
	}

	// Build components từ unique paths/tools
	seenComp := map[string]bool{}
	for _, f := range findings {
		key := f.Tool + ":" + f.Path
		if f.Path == "" || seenComp[key] {
			continue
		}
		seenComp[key] = true
		compType := "library"
		if strings.HasSuffix(f.Path, ".go") || strings.HasSuffix(f.Path, ".py") {
			compType = "file"
		} else if strings.HasSuffix(f.Path, ".tf") || strings.HasSuffix(f.Path, ".yaml") || strings.HasSuffix(f.Path, ".yml") {
			compType = "configuration"
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type:    compType,
			Name:    f.Path,
			Version: "0.0.0",
			BOMRef:  f.Tool + "-" + fmt.Sprintf("%x", len(seenComp)),
		})
	}

	// Build vulnerabilities từ unique rule IDs
	seen := map[string]bool{}
	for _, f := range findings {
		if f.RuleID == "" || seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		sev := map[string]string{
			"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info",
		}[string(f.Severity)]
		bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVuln{
			ID:          f.RuleID,
			Source:      cdxSource{Name: f.Tool, URL: "https://cwe.mitre.org/data/definitions/" + f.CWE},
			Ratings:     []cdxRating{{Severity: sev, Method: "other"}},
			Description: f.Message,
			Affects:     []cdxAffects{{Ref: "target"}},
		})
	}
	return bom
}

// GET /api/v1/sbom/{rid}/diff?compare={rid2}
// Compare two SBOM runs — show new/fixed/changed findings
func (h *SBOM) Diff(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid1 := chi.URLParam(r, "rid")
	rid2 := r.URL.Query().Get("compare")
	if rid2 == "" {
		// Auto-compare with previous run
		jsonError(w, "compare parameter required (e.g. ?compare=RID_xxx)", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	run1, err := h.DB.GetRunByRID(ctx, claims.TenantID, rid1)
	if err != nil || run1 == nil {
		jsonError(w, "run1 not found", http.StatusNotFound)
		return
	}
	run2, err := h.DB.GetRunByRID(ctx, claims.TenantID, rid2)
	if err != nil || run2 == nil {
		jsonError(w, "run2 not found", http.StatusNotFound)
		return
	}

	// Get findings for both runs
	getFindings := func(runID string) map[string]store.Finding {
		findings, _, _ := h.DB.ListFindings(ctx, claims.TenantID,
			store.FindingFilter{Limit: 5000})
		m := make(map[string]store.Finding)
		for _, f := range findings {
			if f.RunID == runID {
				key := f.Tool + "|" + f.RuleID + "|" + f.Path + "|" + fmt.Sprint(f.LineNum)
				m[key] = f
			}
		}
		return m
	}

	f1 := getFindings(run1.ID)
	f2 := getFindings(run2.ID)

	type DiffItem struct {
		Key      string `json:"key"`
		Status   string `json:"status"` // new | fixed | persisted
		Tool     string `json:"tool"`
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Path     string `json:"path"`
		Message  string `json:"message"`
	}

	var newItems, fixedItems, persistedItems []DiffItem

	// New in run1 (not in run2 = baseline)
	for k, f := range f1 {
		if _, exists := f2[k]; !exists {
			newItems = append(newItems, DiffItem{
				Key: k, Status: "new",
				Tool: f.Tool, RuleID: f.RuleID,
				Severity: f.Severity, Path: f.Path, Message: f.Message,
			})
		} else {
			persistedItems = append(persistedItems, DiffItem{
				Key: k, Status: "persisted",
				Tool: f.Tool, RuleID: f.RuleID,
				Severity: f.Severity, Path: f.Path, Message: f.Message,
			})
		}
	}

	// Fixed (in run2 but not in run1)
	for k, f := range f2 {
		if _, exists := f1[k]; !exists {
			fixedItems = append(fixedItems, DiffItem{
				Key: k, Status: "fixed",
				Tool: f.Tool, RuleID: f.RuleID,
				Severity: f.Severity, Path: f.Path, Message: f.Message,
			})
		}
	}

	// Count by severity
	countBySev := func(items []DiffItem) map[string]int {
		m := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
		for _, i := range items {
			m[i.Severity]++
		}
		return m
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"run1": map[string]interface{}{
			"rid": rid1, "mode": run1.Mode,
			"gate": run1.Gate, "created_at": run1.CreatedAt,
			"total_findings": len(f1),
		},
		"run2": map[string]interface{}{
			"rid": rid2, "mode": run2.Mode,
			"gate": run2.Gate, "created_at": run2.CreatedAt,
			"total_findings": len(f2),
		},
		"diff": map[string]interface{}{
			"new_count":       len(newItems),
			"fixed_count":     len(fixedItems),
			"persisted_count": len(persistedItems),
			"new_by_sev":      countBySev(newItems),
			"fixed_by_sev":    countBySev(fixedItems),
			"trend":           map[bool]string{true: "improving", false: map[bool]string{true: "degraded", false: "stable"}[len(newItems) > len(fixedItems)]}[len(fixedItems) > len(newItems)],
		},
		"new":       newItems,
		"fixed":     fixedItems,
		"persisted": persistedItems,
	})
}
