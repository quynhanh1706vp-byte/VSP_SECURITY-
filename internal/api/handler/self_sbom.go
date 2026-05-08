// Package handler — self-SBOM endpoint (Sprint 10.5).
//
// VSP scans customer code for dependencies but for a long time did
// not publicly expose its own SBOM. Customers running supply-chain
// risk reviews (Wiz CDR, Phylum, Endor) want to ingest VSP's own
// CycloneDX / SPDX. This endpoint reads the SBOM produced at build
// time (Dockerfile-time `syft scan dir:. -o cyclonedx-json` writes
// the file under /app/sbom/) and serves it anonymously.
//
// Endpoints:
//   GET /sbom.cyclonedx.json   — anonymous, cache 1h
//   GET /sbom.spdx.json        — anonymous, cache 1h
//
// Why the path is unversioned: convention. Tools auto-discover
// `/sbom.cyclonedx.json` per the OpenSSF Scorecard "SBOM published"
// check.
package handler

import (
	"net/http"
	"os"
)

const (
	defaultSBOMCycloneDXPath = "/app/sbom/vsp.cyclonedx.json"
	defaultSBOMSPDXPath      = "/app/sbom/vsp.spdx.json"
)

// SelfSBOM serves the platform's own SBOM. Path can be overridden
// via VSP_SBOM_DIR for local dev / non-Docker deployments.
type SelfSBOM struct {
	cycloneDXPath string
	spdxPath      string
}

func NewSelfSBOM() *SelfSBOM {
	cdx := defaultSBOMCycloneDXPath
	spdx := defaultSBOMSPDXPath
	if dir := os.Getenv("VSP_SBOM_DIR"); dir != "" {
		cdx = dir + "/vsp.cyclonedx.json"
		spdx = dir + "/vsp.spdx.json"
	}
	return &SelfSBOM{cycloneDXPath: cdx, spdxPath: spdx}
}

// CycloneDX serves the CycloneDX-format SBOM. Falls back to a
// minimal placeholder if the file is missing — that's better than
// 404 because consumers with auto-discovery (OpenSSF Scorecard,
// Phylum) will retry.
func (h *SelfSBOM) CycloneDX(w http.ResponseWriter, r *http.Request) {
	h.serveOrPlaceholder(w, r, h.cycloneDXPath, "cyclonedx")
}

// SPDX serves the SPDX-format SBOM (alternative format).
func (h *SelfSBOM) SPDX(w http.ResponseWriter, r *http.Request) {
	h.serveOrPlaceholder(w, r, h.spdxPath, "spdx")
}

func (h *SelfSBOM) serveOrPlaceholder(w http.ResponseWriter, r *http.Request, path, format string) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if data, err := os.ReadFile(path); err == nil { //#nosec G304 — path comes from env, not user input
		_, _ = w.Write(data)
		return
	}

	// Placeholder so external scanners get a parseable, honest
	// document rather than a 404. The placeholder names VSP itself
	// and explicitly states the file is missing — auditors will see
	// "missing" and ask why rather than "stale" and trust.
	if format == "spdx" {
		_, _ = w.Write([]byte(`{
  "spdxVersion":      "SPDX-2.3",
  "dataLicense":      "CC0-1.0",
  "SPDXID":           "SPDXRef-DOCUMENT",
  "name":             "VSP — Vietnam Security Platform (placeholder)",
  "documentNamespace": "https://vsp.vn/sbom/placeholder",
  "creationInfo":     { "created": "2026-05-08T00:00:00Z", "creators": ["Tool: vsp-gateway"] },
  "comment":          "Placeholder document — production deployments build the real SBOM via syft at container-build time and mount it at /app/sbom/. See deploy/helm/templates/deployment.yaml volumeMounts."
}`))
		return
	}
	_, _ = w.Write([]byte(`{
  "bomFormat":   "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
  "version":     1,
  "metadata": {
    "timestamp": "2026-05-08T00:00:00Z",
    "tools": [{ "vendor": "VSP", "name": "vsp-gateway", "version": "placeholder" }],
    "component": { "type": "application", "name": "vsp-platform", "version": "placeholder" }
  },
  "components": [],
  "comment": "Placeholder document — production deployments build the real SBOM via syft at container-build time and mount it at /app/sbom/. See deploy/helm/templates/deployment.yaml volumeMounts."
}`))
}
