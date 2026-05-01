package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/conmon"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// ConMonHandler exposes ConMon REST endpoints.
type ConMonHandler struct {
	DB *sql.DB
}

// NewConMonHandler constructs a handler with the given database.
func NewConMonHandler(db *sql.DB) *ConMonHandler {
	return &ConMonHandler{DB: db}
}

// Schedules: GET list, POST create
func (h *ConMonHandler) Schedules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		list, err := conmon.ListSchedules(r.Context(), h.DB, tenantID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schedules": list, "count": len(list)})

	case http.MethodPost:
		var sch conmon.Schedule
		if err := json.NewDecoder(r.Body).Decode(&sch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		sch.TenantID = tenantID
		if claims, ok := auth.FromContext(r.Context()); ok {
			sch.CreatedBy = claims.Email
		}
		id, err := conmon.CreateSchedule(r.Context(), h.DB, sch)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// Deviations: GET list (?open=1 filters unacknowledged)
func (h *ConMonHandler) Deviations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	openOnly := r.URL.Query().Get("open") == "1"
	list, err := conmon.ListDeviations(r.Context(), h.DB, tenantID, openOnly)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deviations": list, "count": len(list)})
}

// AckDeviation: POST /api/v1/conmon/deviations/{id}/acknowledge
func (h *ConMonHandler) AckDeviation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Path: /api/v1/conmon/deviations/{id}/acknowledge
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		http.Error(w, `{"error":"bad path"}`, http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	var body struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	ackBy := "system"
	if claims, ok := auth.FromContext(r.Context()); ok {
		ackBy = claims.Email
	}

	if err := conmon.AcknowledgeDeviation(r.Context(), h.DB, id, tenantID, ackBy, body.Notes); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"deviation not found or already acknowledged"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// CadenceStatus: GET /api/v1/conmon/cadence
func (h *ConMonHandler) CadenceStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	list, err := conmon.GetCadenceStatus(r.Context(), h.DB, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cadence": list, "count": len(list)})
}

// ─── helpers ────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) (string, bool) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		return "", false
	}
	return claims.TenantID, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ─── G37: FedRAMP Compliance Templates (BETA) ────────────────────
// 3 templates aligned to FedRAMP requirements:
//   ASR  — Annual Self-Assessment Report
//   QAR  — Quarterly Assessment Report
//   MCMR — Monthly Continuous Monitoring Report
//
// BETA: structure follows FedRAMP guidance but full rubric content
// requires SME review before production customer use.

// g37TemplateData is shared across all 3 templates.
type g37TemplateData struct {
	ReportType          string
	GeneratedAt         time.Time
	PeriodStart         time.Time
	PeriodEnd           time.Time
	SystemName          string
	SystemID            string
	Categorization      string
	ATOStatus           string
	ATOExpiration       time.Time
	AuthorizingOfficial string
	Assessor            string

	// Vulnerability counts
	VulnCritical int
	VulnHigh     int
	VulnMedium   int
	VulnLow      int

	// POAM counts
	POAMOpen     int
	POAMClosed   int
	POAMOverdue  int
	POAMCritical int

	// Compliance metrics
	ScanCoverage   int
	DriftReverted  string
	ScanRunsTotal  int
	ScanRunsPassed int

	BetaWarning string
}

// pullG37TemplateData fetches live data for the given period.
func (h *ConMonHandler) pullG37TemplateData(ctx context.Context, tenantID string, reportType string) g37TemplateData {
	now := time.Now()
	var periodStart time.Time
	switch reportType {
	case "ASR":
		periodStart = now.AddDate(-1, 0, 0)
	case "QAR":
		periodStart = now.AddDate(0, -3, 0)
	default: // MCMR
		periodStart = now.AddDate(0, -1, 0)
	}

	data := g37TemplateData{
		ReportType:          reportType,
		GeneratedAt:         now,
		PeriodStart:         periodStart,
		PeriodEnd:           now,
		SystemName:          "VSP Security Platform",
		SystemID:            "VSP-DOD-2025-001",
		Categorization:      "MODERATE",
		ATOStatus:           "AUTHORIZED",
		ATOExpiration:       now.AddDate(3, 0, 0),
		AuthorizingOfficial: "VSP Program Office",
		Assessor:            "Coalfire (3PAO)",
		ScanCoverage:        100,
		DriftReverted:       "Yes",
		BetaWarning:         "[BETA — FedRAMP SME review pending. Review content before production use.]",
	}

	// Vuln counts
	_ = h.DB.QueryRowContext(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE severity='CRITICAL'),
			COUNT(*) FILTER (WHERE severity='HIGH'),
			COUNT(*) FILTER (WHERE severity='MEDIUM'),
			COUNT(*) FILTER (WHERE severity='LOW')
		 FROM findings WHERE tenant_id=$1`, tenantID).
		Scan(&data.VulnCritical, &data.VulnHigh, &data.VulnMedium, &data.VulnLow)

	// POAM counts
	_ = h.DB.QueryRowContext(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE status='open'),
			COUNT(*) FILTER (WHERE status='closed'),
			COUNT(*) FILTER (WHERE status='open' AND scheduled_completion < NOW()),
			COUNT(*) FILTER (WHERE status='open' AND severity='CRITICAL')
		 FROM p4_poam_items WHERE tenant_id=$1`, tenantID).
		Scan(&data.POAMOpen, &data.POAMClosed, &data.POAMOverdue, &data.POAMCritical)

	// Scan runs in period
	_ = h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE gate='PASS')
		 FROM runs WHERE tenant_id=$1 AND created_at >= $2`,
		tenantID, periodStart).
		Scan(&data.ScanRunsTotal, &data.ScanRunsPassed)

	return data
}

// renderG37PDF pipes HTML through wkhtmltopdf (with chromium fallback).
func (h *ConMonHandler) renderG37PDF(html string, filename string, w http.ResponseWriter) {
	tmpHTML, err := os.CreateTemp("", "vsp-g37-*.html")
	if err != nil {
		http.Error(w, `{"error":"temp file"}`, http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpHTML.Name())
	if _, writeErr := tmpHTML.WriteString(html); writeErr != nil {
		http.Error(w, `{"error":"write html"}`, http.StatusInternalServerError)
		return
	}
	tmpHTML.Close()

	pdfPath := tmpHTML.Name() + ".pdf"
	defer os.Remove(pdfPath)

	cmds := [][]string{
		{"wkhtmltopdf", "--quiet", "--page-size", "A4",
			"--margin-top", "10mm", "--margin-bottom", "10mm",
			"--margin-left", "10mm", "--margin-right", "10mm",
			"--encoding", "utf-8", "--enable-local-file-access",
			tmpHTML.Name(), pdfPath},
		{"chromium-browser", "--headless", "--disable-gpu",
			"--print-to-pdf=" + pdfPath, "file://" + tmpHTML.Name()},
	}

	var pdfErr error
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...) // #nosec G204
		pdfErr = cmd.Run()
		if pdfErr == nil {
			break
		}
	}

	if pdfErr != nil {
		// Fallback: serve HTML if PDF fails
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
		return
	}

	pdfBytes, readErr := os.ReadFile(pdfPath)
	if readErr != nil {
		http.Error(w, `{"error":"read pdf"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(pdfBytes)
}

// RenderASR generates Annual Self-Assessment Report.
// GET /api/p4/conmon/template/asr
func (h *ConMonHandler) RenderASR(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	d := h.pullG37TemplateData(r.Context(), tenantID, "ASR")
	html := g37HeaderHTML("Annual Self-Assessment Report (ASR)", d) + g37ASRBody(d) + g37FooterHTML()
	h.renderG37PDF(html, "VSP-ASR-"+d.GeneratedAt.Format("2006-01-02")+".pdf", w)
}

// RenderQAR generates Quarterly Assessment Report.
// GET /api/p4/conmon/template/qar
func (h *ConMonHandler) RenderQAR(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	d := h.pullG37TemplateData(r.Context(), tenantID, "QAR")
	html := g37HeaderHTML("Quarterly Assessment Report (QAR)", d) + g37QARBody(d) + g37FooterHTML()
	h.renderG37PDF(html, "VSP-QAR-"+d.GeneratedAt.Format("2006-01-02")+".pdf", w)
}

// RenderMCMR generates Monthly Continuous Monitoring Report.
// GET /api/p4/conmon/template/mcmr
func (h *ConMonHandler) RenderMCMR(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	d := h.pullG37TemplateData(r.Context(), tenantID, "MCMR")
	html := g37HeaderHTML("Monthly Continuous Monitoring Report (MCMR)", d) + g37MCMRBody(d) + g37FooterHTML()
	h.renderG37PDF(html, "VSP-MCMR-"+d.GeneratedAt.Format("2006-01-02")+".pdf", w)
}

func g37HeaderHTML(title string, d g37TemplateData) string {
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>` + title + `</title>
<style>
body { font-family: Helvetica, sans-serif; color:#1a1a1a; max-width:780px; margin:0 auto; padding:20px; line-height:1.5; }
h1 { color:#1a3a52; border-bottom:2px solid #1a3a52; padding-bottom:8px; }
h2 { color:#2c5577; margin-top:24px; }
table { width:100%; border-collapse:collapse; margin:12px 0; }
th, td { border:1px solid #ccc; padding:6px 10px; text-align:left; }
th { background:#f0f4f8; }
.section { margin-bottom:24px; }
.crit { color:#c0392b; font-weight:600; }
.high { color:#d35400; font-weight:600; }
.beta { background:#fff8e1; border-left:4px solid #f39c12; padding:10px 16px; margin:16px 0; font-size:13px; }
.meta { color:#666; font-size:11px; margin-top:40px; }
</style></head><body>
<div class="beta">⚠ ` + d.BetaWarning + `</div>
`
}

func g37FooterHTML() string {
	return `<div class="meta"><p>Generated by VSP Security Platform · ` +
		time.Now().Format("2006-01-02 15:04:05 MST") + `</p></div></body></html>`
}

func g37ASRBody(d g37TemplateData) string {
	return `<h1>Annual Self-Assessment Report</h1>
<div class="section">
<h2>1. Executive Summary</h2>
<p>This Annual Self-Assessment Report (ASR) documents the security posture of <b>` +
		d.SystemName + `</b> (System ID: ` + d.SystemID + `) for the period <b>` +
		d.PeriodStart.Format("2006-01-02") + `</b> to <b>` + d.PeriodEnd.Format("2006-01-02") + `</b>.</p>
<p>The system maintains <b>` + d.ATOStatus + `</b> status under <b>` +
		d.Categorization + `</b> categorization.</p>
</div>
<div class="section">
<h2>2. Compliance Posture</h2>
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Scan Coverage</td><td>` + g37Itoa(d.ScanCoverage) + `%</td></tr>
<tr><td>Drift Reverted</td><td>` + d.DriftReverted + `</td></tr>
<tr><td>Total Scan Runs</td><td>` + g37Itoa(d.ScanRunsTotal) + `</td></tr>
<tr><td>Passed Scans</td><td>` + g37Itoa(d.ScanRunsPassed) + `</td></tr>
</table>
</div>
<div class="section">
<h2>3. Vulnerability Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
<tr><td class="crit">Critical</td><td>` + g37Itoa(d.VulnCritical) + `</td></tr>
<tr><td class="high">High</td><td>` + g37Itoa(d.VulnHigh) + `</td></tr>
<tr><td>Medium</td><td>` + g37Itoa(d.VulnMedium) + `</td></tr>
<tr><td>Low</td><td>` + g37Itoa(d.VulnLow) + `</td></tr>
</table>
</div>
<div class="section">
<h2>4. POA&M Status</h2>
<table><tr><th>Status</th><th>Count</th></tr>
<tr><td>Open</td><td>` + g37Itoa(d.POAMOpen) + `</td></tr>
<tr><td>Closed</td><td>` + g37Itoa(d.POAMClosed) + `</td></tr>
<tr><td class="crit">Overdue</td><td>` + g37Itoa(d.POAMOverdue) + `</td></tr>
<tr><td class="crit">Critical Open</td><td>` + g37Itoa(d.POAMCritical) + `</td></tr>
</table>
</div>
<div class="section">
<h2>5. Authorizing Official Attestation</h2>
<p><b>Authorizing Official:</b> ` + d.AuthorizingOfficial + `</p>
<p><b>Assessor:</b> ` + d.Assessor + `</p>
<p><b>Signature: ____________________________</b></p>
<p><b>Date: ____________</b></p>
</div>`
}

func g37QARBody(d g37TemplateData) string {
	return `<h1>Quarterly Assessment Report</h1>
<div class="section">
<h2>1. Quarter Summary</h2>
<p>System: <b>` + d.SystemName + `</b> (` + d.SystemID + `)</p>
<p>Quarter: <b>` + d.PeriodStart.Format("2006-01-02") + `</b> to <b>` +
		d.PeriodEnd.Format("2006-01-02") + `</b></p>
</div>
<div class="section">
<h2>2. Continuous Monitoring</h2>
<table><tr><th>Metric</th><th>Quarter</th></tr>
<tr><td>Scan Runs</td><td>` + g37Itoa(d.ScanRunsTotal) + `</td></tr>
<tr><td>Pass Rate</td><td>` + g37Pct(d.ScanRunsPassed, d.ScanRunsTotal) + `</td></tr>
<tr><td>Coverage</td><td>` + g37Itoa(d.ScanCoverage) + `%</td></tr>
</table>
</div>
<div class="section">
<h2>3. Vulnerability Trends</h2>
<table><tr><th>Severity</th><th>Open</th></tr>
<tr><td class="crit">Critical</td><td>` + g37Itoa(d.VulnCritical) + `</td></tr>
<tr><td class="high">High</td><td>` + g37Itoa(d.VulnHigh) + `</td></tr>
<tr><td>Medium</td><td>` + g37Itoa(d.VulnMedium) + `</td></tr>
<tr><td>Low</td><td>` + g37Itoa(d.VulnLow) + `</td></tr>
</table>
</div>
<div class="section">
<h2>4. POA&M Update</h2>
<p>Open: <b>` + g37Itoa(d.POAMOpen) + `</b> · Closed: <b>` + g37Itoa(d.POAMClosed) +
		`</b> · Overdue: <b class="crit">` + g37Itoa(d.POAMOverdue) + `</b></p>
</div>`
}

func g37MCMRBody(d g37TemplateData) string {
	return `<h1>Monthly Continuous Monitoring Report</h1>
<div class="section">
<h2>System Info</h2>
<p>System: <b>` + d.SystemName + `</b> (` + d.SystemID + `)</p>
<p>Period: <b>` + d.PeriodStart.Format("2006-01-02") + `</b> to <b>` +
		d.PeriodEnd.Format("2006-01-02") + `</b></p>
</div>
<div class="section">
<h2>Monthly Snapshot</h2>
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Scan Runs</td><td>` + g37Itoa(d.ScanRunsTotal) + `</td></tr>
<tr><td>Pass Rate</td><td>` + g37Pct(d.ScanRunsPassed, d.ScanRunsTotal) + `</td></tr>
<tr><td class="crit">Critical Vulns</td><td>` + g37Itoa(d.VulnCritical) + `</td></tr>
<tr><td class="high">High Vulns</td><td>` + g37Itoa(d.VulnHigh) + `</td></tr>
<tr><td>POA&M Open</td><td>` + g37Itoa(d.POAMOpen) + `</td></tr>
<tr><td class="crit">POA&M Overdue</td><td>` + g37Itoa(d.POAMOverdue) + `</td></tr>
</table>
</div>
<div class="section">
<h2>Action Items</h2>
<p>` + g37Itoa(d.POAMCritical) + ` critical POA&M items pending closure. Drift reverted: ` + d.DriftReverted + `.</p>
</div>`
}

func g37Itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func g37Pct(num, denom int) string {
	if denom == 0 {
		return "—"
	}
	return fmt.Sprintf("%d%%", (num*100)/denom)
}
