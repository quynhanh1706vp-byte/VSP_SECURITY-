package handler

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/store"
)

type SoftwareInventoryHandler struct {
	DB *store.DB
}

type SWReportPayload struct {
	Hostname     string      `json:"hostname"`
	OS           string      `json:"os"`
	OSVersion    string      `json:"os_version"`
	Arch         string      `json:"arch"`
	AgentVersion string      `json:"agent_version"`
	Packages     []SWPackage `json:"packages"`
	Timestamp    time.Time   `json:"timestamp"`
}

type SWPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	SHA256    string `json:"sha256"`
	Signed    bool   `json:"signed"`
	Source    string `json:"source"`
}

var crackPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(crack|keygen|patch|activat|serial|bypass|hack|pirat|warez|nulled)`),
	regexp.MustCompile(`(?i)(kmspico|daz|ratiborus|re-loader|toolkit.*activat)`),
}

var suspPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(torrent|utorrent|bittorrent|limewire)`),
	regexp.MustCompile(`(?i)(xmrig|minerd|cpuminer|claymore)`),
	regexp.MustCompile(`(?i)(advanced.*systemcare|driver.*booster|iobit)`),
}

func calcRiskScore(crackCount, eolCount, suspCount int) (int, string) {
	raw := crackCount*30 + eolCount*20 + suspCount*10
	score := int(math.Min(float64(raw), 100))
	switch {
	case score >= 70:
		return score, "critical"
	case score >= 40:
		return score, "high"
	case score >= 10:
		return score, "medium"
	default:
		return score, "clean"
	}
}

func (h *SoftwareInventoryHandler) ReceiveReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var payload SWReportPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid json"})
		return
	}
	if payload.Hostname == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "hostname required"})
		return
	}
	if payload.Timestamp.IsZero() {
		payload.Timestamp = time.Now()
	}
	ctx := r.Context()
	crackCount, eolCount, suspCount := 0, 0, 0
	inserted, updated := 0, 0

	for _, pkg := range payload.Packages {
		isCrack, isSusp := false, false
		suspReason := ""
		label := pkg.Name + " " + pkg.Publisher
		for _, p := range crackPatterns {
			if p.MatchString(label) {
				isCrack = true
				suspReason = "crack/keygen pattern detected"
				break
			}
		}
		if !isCrack {
			for _, p := range suspPatterns {
				if p.MatchString(label) {
					isSusp = true
					suspReason = "suspicious software pattern"
					break
				}
			}
		}
		if !pkg.Signed && pkg.Publisher == "" && !isCrack && !isSusp {
			isSusp = true
			suspReason = "unsigned, unknown publisher"
		}
		isEOL := false
		var eolHits int
		_ = h.DB.Pool().QueryRow(ctx, `
			SELECT COUNT(*) FROM eol_database
			WHERE product_name ILIKE $1 AND status='eol'`,
			"%"+strings.Split(pkg.Name, " ")[0]+"%",
		).Scan(&eolHits)
		if eolHits > 0 {
			isEOL = true
		}
		if isCrack {
			crackCount++
		} else if isEOL {
			eolCount++
		} else if isSusp {
			suspCount++
		}
		tag, err := h.DB.Pool().Exec(ctx, `
			INSERT INTO software_findings
				(hostname, name, version, publisher, sha256, signed, suspicious, susp_reason, source, detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (hostname, name, version) DO UPDATE SET
				publisher   = EXCLUDED.publisher,
				sha256      = EXCLUDED.sha256,
				signed      = EXCLUDED.signed,
				suspicious  = EXCLUDED.suspicious,
				susp_reason = EXCLUDED.susp_reason,
				source      = EXCLUDED.source,
				detected_at = EXCLUDED.detected_at
		`, payload.Hostname, pkg.Name, pkg.Version, pkg.Publisher,
			pkg.SHA256, pkg.Signed, isCrack || isSusp, suspReason,
			pkg.Source, payload.Timestamp)
		if err == nil {
			if tag.RowsAffected() == 1 {
				inserted++
			} else {
				updated++
			}
		}
	}

	riskScore, riskLevel := calcRiskScore(crackCount, eolCount, suspCount)
	reportJSON, _ := json.Marshal(payload)
	_, err := h.DB.Pool().Exec(ctx, `
		INSERT INTO software_assets
			(hostname, os, os_version, arch, agent_version,
			 total_software, suspicious_count, eol_count, crack_count,
			 risk_score, risk_level, last_seen, report_json, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
		ON CONFLICT (hostname) DO UPDATE SET
			os               = EXCLUDED.os,
			os_version       = EXCLUDED.os_version,
			arch             = EXCLUDED.arch,
			agent_version    = EXCLUDED.agent_version,
			total_software   = EXCLUDED.total_software,
			suspicious_count = EXCLUDED.suspicious_count,
			eol_count        = EXCLUDED.eol_count,
			crack_count      = EXCLUDED.crack_count,
			risk_score       = EXCLUDED.risk_score,
			risk_level       = EXCLUDED.risk_level,
			last_seen        = EXCLUDED.last_seen,
			report_json      = EXCLUDED.report_json,
			updated_at       = NOW()
	`, payload.Hostname, payload.OS, payload.OSVersion, payload.Arch, payload.AgentVersion,
		len(payload.Packages), suspCount, eolCount, crackCount,
		riskScore, riskLevel, payload.Timestamp, reportJSON)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	// SIEM alert nếu risk critical hoặc có crack
	if riskLevel == "critical" || crackCount > 0 {
		sev := "HIGH"
		if riskLevel == "critical" || crackCount > 0 {
			sev = "CRITICAL"
		}
		title := payload.Hostname + ": "
		if crackCount > 0 {
			title += "unauthorized/crack software detected"
		} else {
			title += "EOL/high-risk software detected"
		}
		// Get tenant_id từ DB
		var tenantID string
		_ = h.DB.Pool().QueryRow(ctx,
			`SELECT id FROM tenants LIMIT 1`).Scan(&tenantID)
		if tenantID != "" {
			sourceRefs, _ := json.Marshal(map[string]interface{}{
				"hostname":    payload.Hostname,
				"risk_score":  riskScore,
				"crack_count": crackCount,
				"eol_count":   eolCount,
				"susp_count":  suspCount,
			})
			_, _ = h.DB.Pool().Exec(ctx, `
				INSERT INTO incidents (tenant_id, title, severity, status, source_refs)
				VALUES ($1,$2,$3,'open',$4)
			`, tenantID, title, sev, sourceRefs)
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "hostname": payload.Hostname,
		"total": len(payload.Packages), "inserted": inserted, "updated": updated,
		"crack_count": crackCount, "eol_count": eolCount, "susp_count": suspCount,
		"risk_score": riskScore, "risk_level": riskLevel,
	})
}

type InventoryAsset struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	OSVersion     string    `json:"os_version"`
	Arch          string    `json:"arch"`
	TotalSoftware int       `json:"total_software"`
	SuspCount     int       `json:"suspicious_count"`
	EOLCount      int       `json:"eol_count"`
	CrackCount    int       `json:"crack_count"`
	RiskScore     int       `json:"risk_score"`
	RiskLevel     string    `json:"risk_level"`
	LastSeen      time.Time `json:"last_seen"`
	AgentVersion  string    `json:"agent_version"`
}

func (h *SoftwareInventoryHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT id, hostname, os, os_version, arch,
		       total_software, suspicious_count, eol_count, crack_count,
		       risk_score, risk_level, last_seen, agent_version
		FROM software_assets
		ORDER BY risk_score DESC, last_seen DESC LIMIT 200`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"assets": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()
	var assets []InventoryAsset
	for rows.Next() {
		var a InventoryAsset
		_ = rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.OSVersion, &a.Arch,
			&a.TotalSoftware, &a.SuspCount, &a.EOLCount, &a.CrackCount,
			&a.RiskScore, &a.RiskLevel, &a.LastSeen, &a.AgentVersion)
		assets = append(assets, a)
	}
	if assets == nil {
		assets = []InventoryAsset{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"assets": assets, "total": len(assets)})
}

func (h *SoftwareInventoryHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	type Stats struct {
		TotalAssets    int `json:"total_assets"`
		TotalSoftware  int `json:"total_software"`
		TotalEOL       int `json:"eol_total"`
		TotalCrack     int `json:"crack_total"`
		CriticalAssets int `json:"critical_assets"`
		CleanAssets    int `json:"clean_assets"`
	}
	var s Stats
	_ = h.DB.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM software_assets`).Scan(&s.TotalAssets)
	_ = h.DB.Pool().QueryRow(r.Context(), `SELECT COALESCE(SUM(total_software),0) FROM software_assets`).Scan(&s.TotalSoftware)
	_ = h.DB.Pool().QueryRow(r.Context(), `SELECT COALESCE(SUM(eol_count),0) FROM software_assets`).Scan(&s.TotalEOL)
	_ = h.DB.Pool().QueryRow(r.Context(), `SELECT COALESCE(SUM(crack_count),0) FROM software_assets`).Scan(&s.TotalCrack)
	_ = h.DB.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM software_assets WHERE risk_score>=70`).Scan(&s.CriticalAssets)
	_ = h.DB.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM software_assets WHERE risk_level='clean'`).Scan(&s.CleanAssets)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func (h *SoftwareInventoryHandler) GetAsset(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	var a InventoryAsset
	err := h.DB.Pool().QueryRow(r.Context(), `
		SELECT id, hostname, os, os_version, arch,
		       total_software, suspicious_count, eol_count, crack_count,
		       risk_score, risk_level, last_seen, agent_version
		FROM software_assets WHERE hostname=$1`, hostname).Scan(
		&a.ID, &a.Hostname, &a.OS, &a.OSVersion, &a.Arch,
		&a.TotalSoftware, &a.SuspCount, &a.EOLCount, &a.CrackCount,
		&a.RiskScore, &a.RiskLevel, &a.LastSeen, &a.AgentVersion)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"asset": map[string]interface{}{}, "findings": []interface{}{}})
		return
	}
	type Finding struct {
		Name       string    `json:"name"`
		Version    string    `json:"version"`
		Publisher  string    `json:"publisher"`
		SHA256     string    `json:"sha256"`
		Signed     bool      `json:"signed"`
		SuspReason string    `json:"susp_reason"`
		Source     string    `json:"source"`
		DetectedAt time.Time `json:"detected_at"`
	}
	rows, _ := h.DB.Pool().Query(r.Context(), `
		SELECT name, version, publisher, sha256, signed, susp_reason, source, detected_at
		FROM software_findings WHERE hostname=$1 ORDER BY detected_at DESC LIMIT 50`, hostname)
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		var f Finding
		_ = rows.Scan(&f.Name, &f.Version, &f.Publisher, &f.SHA256,
			&f.Signed, &f.SuspReason, &f.Source, &f.DetectedAt)
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []Finding{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"asset": a, "findings": findings})
}

func (h *SoftwareInventoryHandler) ListEOL(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT product_name, vendor, version_pattern, eol_date, status, source
		FROM eol_database ORDER BY eol_date DESC NULLS LAST LIMIT 100`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
		return
	}
	defer rows.Close()
	type EOLEntry struct {
		ProductName    string `json:"product_name"`
		Vendor         string `json:"vendor"`
		VersionPattern string `json:"version_pattern"`
		EOLDate        string `json:"eol_date"`
		Status         string `json:"status"`
		Source         string `json:"source"`
	}
	var entries []EOLEntry
	for rows.Next() {
		var e EOLEntry
		var eolDate *string
		_ = rows.Scan(&e.ProductName, &e.Vendor, &e.VersionPattern, &eolDate, &e.Status, &e.Source)
		if eolDate != nil {
			e.EOLDate = *eolDate
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []EOLEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"entries": entries, "total": len(entries)})
}
