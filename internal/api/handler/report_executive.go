package handler

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// GET /api/v1/vsp/executive_report_pdf/{rid}
func (h *Report) ExecutivePDF(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")

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

	data := buildExecData(run, rf)

	tmpHTML, err := os.CreateTemp("", "vsp-exec-*.html")
	if err != nil {
		jsonError(w, "temp file error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpHTML.Name())
	if err := execTmpl.Execute(tmpHTML, data); err != nil {
		jsonError(w, "template error", http.StatusInternalServerError)
		return
	}
	tmpHTML.Close()

	pdfPath := filepath.Join(os.TempDir(), "vsp-exec-"+rid+".pdf")
	defer os.Remove(pdfPath)

	var pdfErr error
	for _, conv := range [][]string{
		{"wkhtmltopdf", "--quiet", "--page-size", "A4",
			"--margin-top", "15mm", "--margin-bottom", "15mm",
			"--margin-left", "15mm", "--margin-right", "15mm",
			"--enable-local-file-access", tmpHTML.Name(), pdfPath},
		{"weasyprint", tmpHTML.Name(), pdfPath},
		{"chromium-browser", "--headless", "--no-sandbox",
			"--print-to-pdf=" + pdfPath, "file://" + tmpHTML.Name()},
		{"google-chrome", "--headless", "--no-sandbox",
			"--print-to-pdf=" + pdfPath, "file://" + tmpHTML.Name()},
	} {
		if _, err := exec.LookPath(conv[0]); err != nil {
			continue
		}
		if pdfErr = exec.CommandContext(r.Context(), conv[0], conv[1:]...).Run(); pdfErr == nil { //#nosec G702 -- conv[0] from hardcoded allowlist only
			break
		}
	}

	if pdfErr != nil || !fileExists(pdfPath) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=vsp-executive-%s.html", rid))
		w.Header().Set("X-PDF-Fallback", "true")
		execTmpl.Execute(w, data) //nolint:errcheck
		return
	}

	b, _ := os.ReadFile(pdfPath) //nolint:gosec // G703: pdfPath uses rid validated by isValidRID()
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=vsp-executive-%s.pdf", rid))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	w.Write(b) //nolint:errcheck
}

// ── Executive data model ─────────────────────────────────────────────────────

type execData struct {
	Run            *store.Run
	GeneratedAt    string
	RiskScore      int
	RiskLevel      string
	RiskColor      string
	Summary        execSummary
	TopFindings    []store.Finding
	ToolBreakdown  []toolStat
	Recommendations []string
}

type execSummary struct{ Critical, High, Medium, Low, Total int }
type toolStat    struct{ Tool string; Count int; Pct int }

func buildExecData(run *store.Run, findings []store.Finding) execData {
	d := execData{
		Run:         run,
		GeneratedAt: time.Now().Format("January 2, 2006 at 15:04 UTC"),
	}

	toolMap := map[string]int{}
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL": d.Summary.Critical++
		case "HIGH":     d.Summary.High++
		case "MEDIUM":   d.Summary.Medium++
		case "LOW":      d.Summary.Low++
		}
		toolMap[f.Tool]++
	}
	d.Summary.Total = len(findings)

	// Risk score 0-100 (lower = safer)
	score := d.Summary.Critical*25 + d.Summary.High*10 +
		d.Summary.Medium*3 + d.Summary.Low*1
	if score > 100 { score = 100 }
	d.RiskScore = score
	switch {
	case score >= 75: d.RiskLevel, d.RiskColor = "CRITICAL", "#dc2626"
	case score >= 50: d.RiskLevel, d.RiskColor = "HIGH",     "#ea580c"
	case score >= 25: d.RiskLevel, d.RiskColor = "MEDIUM",   "#d97706"
	default:          d.RiskLevel, d.RiskColor = "LOW",      "#16a34a"
	}

	// Top 10 critical/high findings
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			d.TopFindings = append(d.TopFindings, f)
			if len(d.TopFindings) >= 10 { break }
		}
	}

	// Tool breakdown
	total := len(findings)
	if total == 0 { total = 1 }
	for tool, cnt := range toolMap {
		d.ToolBreakdown = append(d.ToolBreakdown, toolStat{
			Tool:  tool,
			Count: cnt,
			Pct:   cnt * 100 / total,
		})
	}
	sort.Slice(d.ToolBreakdown, func(i, j int) bool {
		return d.ToolBreakdown[i].Count > d.ToolBreakdown[j].Count
	})

	// Recommendations
	if d.Summary.Critical > 0 {
		d.Recommendations = append(d.Recommendations,
			fmt.Sprintf("Immediate action required: %d critical vulnerabilities must be remediated within 24 hours", d.Summary.Critical))
	}
	if d.Summary.High > 5 {
		d.Recommendations = append(d.Recommendations,
			fmt.Sprintf("Schedule remediation sprint: %d high-severity findings exceed acceptable threshold", d.Summary.High))
	}
	for _, t := range d.ToolBreakdown {
		if t.Pct > 40 {
			d.Recommendations = append(d.Recommendations,
				fmt.Sprintf("%s accounts for %d%% of findings — review %s configuration and suppression rules", t.Tool, t.Pct, t.Tool))
			break
		}
	}
	if run.Gate == "PASS" {
		d.Recommendations = append(d.Recommendations,
			"Security gate passed — maintain current posture and schedule next scan within 7 days")
	} else {
		d.Recommendations = append(d.Recommendations,
			"Security gate failed — block deployment until critical and high findings are resolved")
	}
	if len(d.Recommendations) == 0 {
		d.Recommendations = append(d.Recommendations,
			"No critical issues detected — continue regular scanning cadence")
	}

	return d
}

// ── Executive HTML template ──────────────────────────────────────────────────

var execTmpl = template.Must(template.New("exec").Funcs(template.FuncMap{
	"inc": func(i int) int { return i + 1 },
	"sevColor": func(s string) string {
		m := map[string]string{
			"CRITICAL": "#dc2626", "HIGH": "#ea580c",
			"MEDIUM": "#d97706", "LOW": "#16a34a",
		}
		if c, ok := m[s]; ok { return c }
		return "#6b7280"
	},
	"barWidth": func(pct int) string { return fmt.Sprintf("%d%%", pct) },
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VSP Executive Security Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;color:#1e293b;font-size:14px}
.page{max-width:900px;margin:0 auto;padding:0}

/* Cover */
.cover{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:#fff;padding:60px 56px 48px;position:relative}
.cover-logo{font-size:13px;font-weight:600;letter-spacing:2px;color:#60a5fa;text-transform:uppercase;margin-bottom:40px}
.cover h1{font-size:36px;font-weight:700;line-height:1.2;margin-bottom:8px}
.cover .subtitle{font-size:16px;color:#94a3b8;margin-bottom:40px}
.cover-meta{display:flex;gap:40px;flex-wrap:wrap;margin-top:32px;padding-top:32px;border-top:1px solid rgba(255,255,255,0.1)}
.cover-meta-item .label{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.cover-meta-item .value{font-size:15px;font-weight:600;color:#e2e8f0}

/* Risk gauge */
.risk-gauge{position:absolute;top:48px;right:56px;text-align:center}
.gauge-ring{width:110px;height:110px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;border:6px solid}
.gauge-score{font-size:32px;font-weight:700}
.gauge-label{font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:2px;font-weight:600}

/* Sections */
.section{background:#fff;margin:16px;border-radius:12px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.06)}
.section-title{font-size:16px;font-weight:600;color:#0f172a;margin-bottom:20px;display:flex;align-items:center;gap:8px}
.section-title::before{content:"";display:block;width:4px;height:18px;border-radius:2px;background:#2563eb}

/* Summary cards */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.card{border-radius:8px;padding:20px 16px;text-align:center;border:1px solid}
.card-val{font-size:36px;font-weight:700;line-height:1}
.card-lbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-top:6px}

/* Tool bars */
.tool-bar{margin-bottom:10px}
.tool-bar-header{display:flex;justify-content:space-between;margin-bottom:4px;font-size:13px}
.tool-bar-track{height:8px;background:#f1f5f9;border-radius:4px;overflow:hidden}
.tool-bar-fill{height:100%;border-radius:4px;background:#2563eb;transition:width .3s}

/* Top findings table */
table{width:100%;border-collapse:collapse}
th{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;font-weight:600;padding:8px 12px;text-align:left;border-bottom:2px solid #f1f5f9}
td{padding:10px 12px;border-bottom:1px solid #f8fafc;font-size:13px;vertical-align:top}
.pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}

/* Recommendations */
.rec{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid #f1f5f9}
.rec:last-child{border-bottom:none}
.rec-icon{width:24px;height:24px;border-radius:50%;background:#dbeafe;color:#2563eb;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0;margin-top:1px}
.rec-text{font-size:13px;color:#374151;line-height:1.5}

/* Footer */
.footer{text-align:center;padding:24px;color:#94a3b8;font-size:12px}

@media print{
  body{background:#fff}
  .section{box-shadow:none;border:1px solid #e2e8f0}
}
</style>
</head>
<body>
<div class="page">

<!-- Cover -->
<div class="cover">
  <div class="cover-logo">VSP · Security Platform</div>
  <h1>Executive Security<br>Report</h1>
  <div class="subtitle">Vulnerability & Security Posture Assessment</div>
  <div class="risk-gauge">
    <div class="gauge-ring" style="border-color:{{.RiskColor}};color:{{.RiskColor}}">
      <div class="gauge-score">{{.RiskScore}}</div>
      <div class="gauge-label" style="color:{{.RiskColor}}">{{.RiskLevel}}</div>
    </div>
    <div style="font-size:11px;color:#64748b;margin-top:8px">Risk Score</div>
  </div>
  <div class="cover-meta">
    <div class="cover-meta-item">
      <div class="label">Scan ID</div>
      <div class="value">{{.Run.RID}}</div>
    </div>
    <div class="cover-meta-item">
      <div class="label">Mode</div>
      <div class="value">{{.Run.Mode}}</div>
    </div>
    <div class="cover-meta-item">
      <div class="label">Gate</div>
      <div class="value" style="color:{{if eq .Run.Gate "PASS"}}#4ade80{{else}}#f87171{{end}}">{{.Run.Gate}}</div>
    </div>
    <div class="cover-meta-item">
      <div class="label">Posture</div>
      <div class="value">{{.Run.Posture}}</div>
    </div>
    <div class="cover-meta-item">
      <div class="label">Generated</div>
      <div class="value">{{.GeneratedAt}}</div>
    </div>
  </div>
</div>

<!-- Summary -->
<div class="section">
  <div class="section-title">Findings Summary</div>
  <div class="cards">
    <div class="card" style="border-color:#fecaca;background:#fff1f1">
      <div class="card-val" style="color:#dc2626">{{.Summary.Critical}}</div>
      <div class="card-lbl" style="color:#dc2626">Critical</div>
    </div>
    <div class="card" style="border-color:#fed7aa;background:#fff7ed">
      <div class="card-val" style="color:#ea580c">{{.Summary.High}}</div>
      <div class="card-lbl" style="color:#ea580c">High</div>
    </div>
    <div class="card" style="border-color:#fde68a;background:#fffbeb">
      <div class="card-val" style="color:#d97706">{{.Summary.Medium}}</div>
      <div class="card-lbl" style="color:#d97706">Medium</div>
    </div>
    <div class="card" style="border-color:#bbf7d0;background:#f0fdf4">
      <div class="card-val" style="color:#16a34a">{{.Summary.Low}}</div>
      <div class="card-lbl" style="color:#16a34a">Low</div>
    </div>
  </div>
  <div style="font-size:13px;color:#64748b;text-align:right">Total findings: <strong style="color:#0f172a">{{.Summary.Total}}</strong></div>
</div>

<!-- Tool breakdown -->
{{if .ToolBreakdown}}
<div class="section">
  <div class="section-title">Findings by Tool</div>
  {{range .ToolBreakdown}}
  <div class="tool-bar">
    <div class="tool-bar-header">
      <span style="font-weight:500">{{.Tool}}</span>
      <span style="color:#64748b">{{.Count}} findings ({{.Pct}}%)</span>
    </div>
    <div class="tool-bar-track">
      <div class="tool-bar-fill" style="width:{{barWidth .Pct}}"></div>
    </div>
  </div>
  {{end}}
</div>
{{end}}

<!-- Top findings -->
{{if .TopFindings}}
<div class="section">
  <div class="section-title">Priority Findings (Critical &amp; High)</div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Tool</th>
        <th>Rule</th>
        <th>Location</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
    {{range .TopFindings}}
    <tr>
      <td><span class="pill" style="background:{{sevColor .Severity}}">{{.Severity}}</span></td>
      <td style="color:#64748b;white-space:nowrap">{{.Tool}}</td>
      <td style="font-family:monospace;font-size:11px;color:#6366f1">{{.RuleID}}</td>
      <td style="font-family:monospace;font-size:11px;color:#374151;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Path}}{{if .LineNum}}:{{.LineNum}}{{end}}</td>
      <td style="font-size:12px;color:#374151">{{.Message}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

<!-- Recommendations -->
<div class="section">
  <div class="section-title">Recommendations</div>
  {{range $i, $r := .Recommendations}}
  <div class="rec">
    <div class="rec-icon">{{inc $i}}</div>
    <div class="rec-text">{{$r}}</div>
  </div>
  {{end}}
</div>

<div class="footer">
  Generated by VSP Security Platform v0.9.0 &nbsp;·&nbsp; {{.GeneratedAt}} &nbsp;·&nbsp; Confidential
</div>

</div>
</body>
</html>`))

// GET /api/v1/vsp/executive_report_html/{rid}
func (h *Report) ExecutiveHTML(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
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
	data := buildExecData(run, rf)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=vsp-executive-%s.html", rid))
	}
	execTmpl.Execute(w, data) //nolint:errcheck
}
