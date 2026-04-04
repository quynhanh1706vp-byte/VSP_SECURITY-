package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"os/exec"
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
	if format == "" { format = "cyclonedx" }

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound); return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 2000})
	var rf []store.Finding
	for _, f := range findings {
		if f.RunID == run.ID { rf = append(rf, f) }
	}

	bom := buildCycloneDX(run, rf)
	b, _ := json.MarshalIndent(bom, "", "  ")

	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=sbom-%s.cdx.json", rid))
	w.Write(b) //nolint:errcheck
}

// GET /api/v1/sbom/{rid}/grype — run grype SBOM on target
func (h *SBOM) Grype(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound); return
	}

	target := run.Src
	if target == "" { target = run.TargetURL }
	if target == "" {
		jsonError(w, "no src/url for this run", http.StatusBadRequest); return
	}
	// Validate target — chặn metacharacters
	for _, c := range []string{";", "&", "|", "`", "$", "<", ">", "{", "}", "\\"} {
		if strings.Contains(target, c) {
			jsonError(w, "invalid target", http.StatusBadRequest); return
		}
	}
	if len(target) > 500 {
		jsonError(w, "target too long", http.StatusBadRequest); return
	}

	// grype sbom output
	out, err := exec.CommandContext(r.Context(),
		"grype", target, "-o", "cyclonedx-json", "--quiet").Output()
	if err != nil {
		jsonError(w, "grype failed: "+err.Error(), http.StatusInternalServerError); return
	}

	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=sbom-grype-%s.cdx.json", rid))
	w.Write(out) //nolint:errcheck
}

type cycloneDX struct {
	BOMFormat   string        `json:"bomFormat"`
	SpecVersion string        `json:"specVersion"`
	Version     int           `json:"version"`
	Metadata    cdxMetadata   `json:"metadata"`
	Components  []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string         `json:"timestamp"`
	Tools     []cdxTool      `json:"tools"`
	Component *cdxComponent  `json:"component,omitempty"`
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
	ID          string     `json:"id"`
	Source      cdxSource  `json:"source"`
	Ratings     []cdxRating `json:"ratings"`
	Description string     `json:"description"`
	Affects     []cdxAffects `json:"affects"`
}

type cdxSource  struct { Name string `json:"name"`; URL string `json:"url"` }
type cdxRating  struct { Severity string `json:"severity"`; Method string `json:"method"` }
type cdxAffects struct { Ref string `json:"ref"` }

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

	seen := map[string]bool{}
	for _, f := range findings {
		if f.RuleID == "" || seen[f.RuleID] { continue }
		seen[f.RuleID] = true
		sev := map[string]string{
			"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"info",
		}[string(f.Severity)]
		bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVuln{
			ID: f.RuleID,
			Source: cdxSource{Name: f.Tool, URL: f.FixSignal},
			Ratings: []cdxRating{{Severity: sev, Method: "other"}},
			Description: f.Message,
			Affects: []cdxAffects{{Ref: "target"}},
		})
	}
	return bom
}
