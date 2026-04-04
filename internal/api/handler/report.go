package handler

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Report struct{ DB *store.DB }

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevColor": func(s string) string {
		m := map[string]string{"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d","INFO":"#6b7280"}
		if c, ok := m[s]; ok { return c }
		return "#6b7280"
	},
	"fmtTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
}).Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VSP Report — {{.Run.RID}}</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
.header{background:#1e3a5f;padding:24px 40px;border-bottom:2px solid #2563eb}
.header h1{margin:0;font-size:24px;color:#60a5fa}
.header .meta{color:#94a3b8;font-size:13px;margin-top:4px}
.summary{display:flex;gap:16px;padding:24px 40px;flex-wrap:wrap}
.card{background:#1e293b;border-radius:8px;padding:16px 24px;min-width:120px;text-align:center}
.card .val{font-size:32px;font-weight:700}
.card .lbl{font-size:12px;color:#94a3b8;margin-top:4px}
.section{padding:0 40px 32px}
.section h2{font-size:16px;color:#60a5fa;border-bottom:1px solid #1e293b;padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#1e293b;padding:8px 12px;text-align:left;color:#94a3b8;font-weight:500}
td{padding:8px 12px;border-bottom:1px solid #1e293b}
.pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}
</style>
</head>
<body>
<div class="header">
  <h1>VSP Security Report</h1>
  <div class="meta">RID: {{.Run.RID}} &nbsp;|&nbsp; Mode: {{.Run.Mode}} &nbsp;|&nbsp; {{fmtTime .Run.CreatedAt}}</div>
</div>
<div class="summary">
  <div class="card"><div class="val" style="color:{{sevColor "CRITICAL"}}">{{.Summary.Critical}}</div><div class="lbl">CRITICAL</div></div>
  <div class="card"><div class="val" style="color:{{sevColor "HIGH"}}">{{.Summary.High}}</div><div class="lbl">HIGH</div></div>
  <div class="card"><div class="val" style="color:{{sevColor "MEDIUM"}}">{{.Summary.Medium}}</div><div class="lbl">MEDIUM</div></div>
  <div class="card"><div class="val" style="color:{{sevColor "LOW"}}">{{.Summary.Low}}</div><div class="lbl">LOW</div></div>
  <div class="card"><div class="val" style="color:{{if eq .Run.Gate "PASS"}}#4ade80{{else if eq .Run.Gate "FAIL"}}#f87171{{else}}#fbbf24{{end}}">{{.Run.Gate}}</div><div class="lbl">GATE</div></div>
  <div class="card"><div class="val" style="color:#60a5fa">{{.Run.Posture}}</div><div class="lbl">POSTURE</div></div>
</div>
<div class="section">
  <h2>Findings ({{len .Findings}})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr></thead>
    <tbody>
    {{range .Findings}}
    <tr>
      <td><span class="pill" style="background:{{sevColor .Severity}}">{{.Severity}}</span></td>
      <td style="color:#94a3b8">{{.Tool}}</td>
      <td style="font-family:monospace;font-size:11px;color:#818cf8">{{.RuleID}}</td>
      <td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Path}}</td>
      <td style="color:#64748b">{{.LineNum}}</td>
      <td style="font-size:12px">{{.Message}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
</body>
</html>`))

type reportData struct {
	Run      *store.Run
	Findings []store.Finding
	Summary  struct{ Critical, High, Medium, Low int }
}

// GET /api/v1/vsp/run_report_html/{rid}
func (h *Report) HTML(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	rid := chi.URLParam(r, "rid")
	run, err := h.DB.GetRunByRID(r.Context(), claims.TenantID, rid)
	if err != nil || run == nil { jsonError(w, "run not found", http.StatusNotFound); return }

	findings, _, _ := h.DB.ListFindings(r.Context(), claims.TenantID, store.FindingFilter{RunID: run.ID, Limit: 1000})
	var rf []store.Finding
	for _, f := range findings { if f.RunID == run.ID { rf = append(rf, f) } }

	data := reportData{Run: run, Findings: rf}
	for _, f := range rf {
		switch f.Severity {
		case "CRITICAL": data.Summary.Critical++
		case "HIGH":     data.Summary.High++
		case "MEDIUM":   data.Summary.Medium++
		case "LOW":      data.Summary.Low++
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=vsp-%s.html", rid))
	}
	reportTmpl.Execute(w, data) //nolint:errcheck
}
