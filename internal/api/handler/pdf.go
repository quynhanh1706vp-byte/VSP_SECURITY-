package handler

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// GET /api/v1/vsp/run_report_pdf/{rid}
// Renders HTML report to PDF using wkhtmltopdf or weasyprint
func (h *Report) PDF(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID,
		store.FindingFilter{Limit: 1000})
	var rf []store.Finding
	for _, f := range findings {
		if f.RunID == run.ID {
			rf = append(rf, f)
		}
	}

	// Build HTML content
	data := buildReportData(run, rf)

	// Write HTML to temp file
	tmpHTML, err := os.CreateTemp("", "vsp-report-*.html")
	if err != nil {
		jsonError(w, "temp file error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpHTML.Name())

	if err := reportTmpl.Execute(tmpHTML, data); err != nil {
		jsonError(w, "template error", http.StatusInternalServerError)
		return
	}
	tmpHTML.Close()

	// Try wkhtmltopdf first, then weasyprint, then fallback to HTML
	// Sanitize rid — chặn path traversal
	ridSafe := regexp.MustCompile(`[^a-zA-Z0-9_\-]`).ReplaceAllString(rid, "")
	if ridSafe == "" { ridSafe = "unknown" }
	rid = ridSafe
	pdfPath := filepath.Join(os.TempDir(), "vsp-report-"+rid+".pdf")
	defer os.Remove(pdfPath)

	var pdfErr error
	for _, converter := range [][]string{
		{"wkhtmltopdf", "--quiet", "--page-size", "A4",
			"--margin-top", "15mm", "--margin-bottom", "15mm",
			"--margin-left", "15mm", "--margin-right", "15mm",
			"--enable-local-file-access",
			tmpHTML.Name(), pdfPath},
		{"weasyprint", tmpHTML.Name(), pdfPath},
		{"chromium-browser", "--headless", "--no-sandbox",
			"--print-to-pdf=" + pdfPath, "file://" + tmpHTML.Name()},
		{"google-chrome", "--headless", "--no-sandbox",
			"--print-to-pdf=" + pdfPath, "file://" + tmpHTML.Name()},
	} {
		if _, err := exec.LookPath(converter[0]); err != nil {
			continue
		}
		cmd := exec.CommandContext(r.Context(), converter[0], converter[1:]...)
		pdfErr = cmd.Run()
		if pdfErr == nil {
			break
		}
	}

	if pdfErr != nil || !fileExists(pdfPath) {
		// Fallback: return HTML with PDF-like headers
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=vsp-%s.html", rid))
		w.Header().Set("X-PDF-Fallback", "true")
		reportTmpl.Execute(w, data) //nolint:errcheck
		return
	}

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		jsonError(w, "pdf read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-%s.pdf", rid))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdfBytes)))
	w.Write(pdfBytes) //nolint:errcheck
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// buildReportData is shared between HTML and PDF
func buildReportData(run *store.Run, rf []store.Finding) reportData {
	data := reportData{Run: run, Findings: rf}
	for _, f := range rf {
		switch f.Severity {
		case "CRITICAL": data.Summary.Critical++
		case "HIGH":     data.Summary.High++
		case "MEDIUM":   data.Summary.Medium++
		case "LOW":      data.Summary.Low++
		}
	}
	return data
}
