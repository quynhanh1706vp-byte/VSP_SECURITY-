package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Assets struct{ DB *store.DB }

type Asset struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	IP          string    `json:"ip"`
	Environment string    `json:"env"`
	CritCount   int       `json:"critical"`
	HighCount   int       `json:"high"`
	TotalFinds  int       `json:"total_findings"`
	RiskScore   int       `json:"risk_score"`
	LastScan    time.Time `json:"last_scan"`
	Tags        []string  `json:"tags"`
}

// GET /api/v1/assets
func (h *Assets) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	var assets []Asset

	// Primary: log_sources (real hosts)
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT id, name, host, protocol, tags,
		       status, COALESCE(eps,0), created_at
		FROM   log_sources
		WHERE  tenant_id=$1
		ORDER  BY created_at DESC`, claims.TenantID)
	if err == nil {
		defer rows.Close()
		i := 0
		for rows.Next() {
			var a Asset
			var proto string
			var eps int
			if err := rows.Scan(&a.ID, &a.Name, &a.IP, &proto,
				&a.Tags, &a.Type, &eps, &a.LastScan); err != nil {
				continue
			}
			i++
			a.Type = protoToType(proto)
			a.Environment = "prod"
			a.RiskScore = 0
			if a.Tags == nil {
				a.Tags = []string{}
			}
			assets = append(assets, a)
		}
	}

	// Secondary: findings by tool (scanner assets)
	rows2, err2 := h.DB.Pool().Query(r.Context(), `
		SELECT
			tool,
			COUNT(*) as total,
			COUNT(CASE WHEN severity='CRITICAL' THEN 1 END) as crit,
			COUNT(CASE WHEN severity='HIGH'     THEN 1 END) as high,
			MAX(created_at) as last_seen
		FROM findings
		WHERE tenant_id=$1
		  AND tool != ''
		GROUP BY tool
		ORDER BY crit DESC, high DESC
		LIMIT 20`, claims.TenantID)
	if err2 == nil {
		defer rows2.Close()
		i := len(assets)
		for rows2.Next() {
			var a Asset
			var tool string
			rows2.Scan(&tool, &a.TotalFinds, &a.CritCount, &a.HighCount, &a.LastScan) //nolint:errcheck
			i++
			a.ID = "scanner-" + tool
			a.Name = tool + " scanner"
			a.Type = "scanner"
			a.IP = "internal"
			a.Environment = "prod"
			a.Tags = []string{"scanner", tool}
			a.RiskScore = calcRisk(a.CritCount, a.HighCount, a.TotalFinds)
			assets = append(assets, a)
		}
	}

	if assets == nil {
		assets = []Asset{}
	}
	jsonOK(w, map[string]any{"assets": assets, "total": len(assets)})
}

// GET /api/v1/assets/summary
func (h *Assets) Summary(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())

	// Count log_sources
	var srcTotal int
	h.DB.Pool().QueryRow(r.Context(), `
		SELECT COUNT(*) FROM log_sources WHERE tenant_id=$1`, claims.TenantID,
	).Scan(&srcTotal) //nolint:errcheck

	// Count scanner tools with findings
	var scannerTotal, critical, high int
	h.DB.Pool().QueryRow(r.Context(), `
		SELECT
			COUNT(DISTINCT tool),
			COUNT(DISTINCT CASE WHEN severity='CRITICAL' THEN tool END),
			COUNT(DISTINCT CASE WHEN severity='HIGH'     THEN tool END)
		FROM findings WHERE tenant_id=$1`, claims.TenantID,
	).Scan(&scannerTotal, &critical, &high) //nolint:errcheck

	total := srcTotal + scannerTotal
	jsonOK(w, map[string]any{
		"total":    total,
		"critical": critical,
		"high":     high,
		"clean":    total - critical - high,
	})
}

// GET /api/v1/assets/{id}/findings
func (h *Assets) Findings(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	if !validateUUID(id) {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Strip "scanner-" prefix if present
	tool := id
	if len(id) > 8 && id[:8] == "scanner-" {
		tool = id[8:]
	}

	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT id, severity, tool, rule_id, message, path, line, COALESCE(cwe,'')
		FROM findings
		WHERE tenant_id=$1
		  AND (tool=$2 OR id::text=$2)
		ORDER BY severity DESC LIMIT 50`,
		claims.TenantID, tool)
	if err != nil {
		jsonOK(w, map[string]any{"findings": []any{}, "total": 0})
		return
	}
	defer rows.Close()
	type F struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Tool     string `json:"tool"`
		RuleID   string `json:"rule_id"`
		Message  string `json:"message"`
		Path     string `json:"path"`
		Line     int    `json:"line"`
		CWE      string `json:"cwe"`
	}
	var out []F
	for rows.Next() {
		var f F
		rows.Scan(&f.ID, &f.Severity, &f.Tool, &f.RuleID, &f.Message, &f.Path, &f.Line, &f.CWE) //nolint:errcheck
		out = append(out, f)
	}
	if out == nil {
		out = []F{}
	}
	jsonOK(w, map[string]any{"findings": out, "total": len(out)})
}

// POST /api/v1/assets
func (h *Assets) Create(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var req struct {
		Name string   `json:"name"`
		IP   string   `json:"ip"`
		Type string   `json:"type"`
		Env  string   `json:"env"`
		Tags []string `json:"tags"`
	}
	if !decodeJSON(w, r, &req) {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}
	var id string
	// Validate
	if req.Name == "" || len(req.Name) > 200 {
		jsonError(w, "name: required, max 200 chars", http.StatusBadRequest)
		return
	}
	if req.IP != "" && len(req.IP) > 45 {
		jsonError(w, "ip: max 45 chars", http.StatusBadRequest)
		return
	}
	err := h.DB.Pool().QueryRow(r.Context(), `
		INSERT INTO log_sources
			(tenant_id, name, host, protocol, format, tags, status)
		VALUES ($1,$2,$3,'asset','cmdb',$4,'ok')
		RETURNING id`,
		claims.TenantID, req.Name, req.IP, req.Tags,
	).Scan(&id)
	if err != nil {
		jsonError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": id, "name": req.Name})
}

func protoToType(proto string) string {
	switch proto {
	case "syslog-udp", "syslog-tcp", "syslog-tls":
		return "server"
	case "agent":
		return "host"
	case "s3":
		return "cloud"
	case "kafka":
		return "queue"
	case "asset", "cmdb":
		return "asset"
	default:
		return "host"
	}
}

func calcRisk(crit, high, total int) int {
	score := crit*40 + high*10 + total/10
	if score > 100 {
		score = 100
	}
	return score
}
