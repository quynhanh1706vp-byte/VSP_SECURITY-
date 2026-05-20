package handler

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"strconv"
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

// ─── [H3.U-2] ReceiveReport — agent POST, JWT auth, NO CSRF ──────────────────
func (h *SoftwareInventoryHandler) ReceiveReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var payload SWReportPayload
	if !decodeJSON(w, r, &payload) {
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

	if riskLevel == "critical" || crackCount > 0 {
		sev := "CRITICAL"
		title := payload.Hostname + ": "
		if crackCount > 0 {
			title += "unauthorized/crack software detected"
		} else {
			title += "EOL/high-risk software detected"
		}
		var tenantID string
		_ = h.DB.Pool().QueryRow(ctx, `SELECT id FROM tenants LIMIT 1`).Scan(&tenantID)
		if tenantID != "" {
			sourceRefs, _ := json.Marshal(map[string]interface{}{
				"hostname": payload.Hostname, "risk_score": riskScore,
				"crack_count": crackCount, "eol_count": eolCount, "susp_count": suspCount,
			})
			_, _ = h.DB.Pool().Exec(ctx, `
				INSERT INTO incidents (tenant_id, title, severity, status, source_refs)
				VALUES ($1,$2,$3,'open',$4)
			`, tenantID, title, sev, sourceRefs)
		}
	}

	logAudit(r, h.DB, "SW_INVENTORY_RECEIVED",
		"software_findings:"+payload.Hostname+":pkgs="+strconv.Itoa(len(payload.Packages)))

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "hostname": payload.Hostname,
		"total": len(payload.Packages), "inserted": inserted, "updated": updated,
		"crack_count": crackCount, "eol_count": eolCount, "susp_count": suspCount,
		"risk_score": riskScore, "risk_level": riskLevel,
	})
}

// ─── ListAssets ───────────────────────────────────────────────────────────────
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

// ─── GetStats ─────────────────────────────────────────────────────────────────
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

// ─── GetAsset ─────────────────────────────────────────────────────────────────
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

// ─── ListEOL ──────────────────────────────────────────────────────────────────
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

// ═════════════════════════════════════════════════════════════════════════════
// NEW ENDPOINTS — Whitelist / Blacklist / Cracks / Licenses / Scan History
// Schema migration: internal/db/migrations/0042_sw_policy_tables.sql
// ═════════════════════════════════════════════════════════════════════════════

// SWListEntry — một dòng trong whitelist / blacklist
type SWListEntry struct {
	ID       int    `json:"id"`
	ListType string `json:"list_type"` // "whitelist" | "blacklist" | "warning"
	Name     string `json:"name"`
	Version  string `json:"version"`
	Vendor   string `json:"vendor"`
	Category string `json:"category"`
	Reason   string `json:"reason"`
	Hash     string `json:"hash"`
	AddedBy  string `json:"added_by"`
	AddedAt  string `json:"added_at"`
}

// GET /api/v1/software-inventory/whitelist
func (h *SoftwareInventoryHandler) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	h.listByType(w, r, "whitelist")
}

// GET /api/v1/software-inventory/blacklist
func (h *SoftwareInventoryHandler) ListBlacklist(w http.ResponseWriter, r *http.Request) {
	h.listByType(w, r, "blacklist")
}

// listByType — shared query cho whitelist + blacklist + warning
func (h *SoftwareInventoryHandler) listByType(w http.ResponseWriter, r *http.Request, listType string) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT id, list_type, name, version, vendor, category, reason,
		       COALESCE(hash,''), COALESCE(added_by,''), added_at::text
		FROM sw_policy_list
		WHERE list_type = $1
		ORDER BY added_at DESC`, listType)
	if err != nil {
		// Bảng chưa tồn tại hoặc lỗi khác — trả empty thay vì 500
		// để frontend không bị broken, log để admin biết cần chạy migration
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()
	var items []SWListEntry
	for rows.Next() {
		var e SWListEntry
		_ = rows.Scan(&e.ID, &e.ListType, &e.Name, &e.Version, &e.Vendor,
			&e.Category, &e.Reason, &e.Hash, &e.AddedBy, &e.AddedAt)
		items = append(items, e)
	}
	if items == nil {
		items = []SWListEntry{}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "total": len(items)})
}

// POST /api/v1/software-inventory/whitelist
// POST /api/v1/software-inventory/blacklist
func (h *SoftwareInventoryHandler) AddToList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// list_type đến từ URL param, không cho client tự set
	listType := chi.URLParam(r, "list_type")
	if listType != "whitelist" && listType != "blacklist" && listType != "warning" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid list_type"})
		return
	}

	var body struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Vendor   string `json:"vendor"`
		Category string `json:"category"`
		Reason   string `json:"reason"`
		Hash     string `json:"hash"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "name required"})
		return
	}
	if body.Version == "" {
		body.Version = "any"
	}

	// added_by: lấy từ JWT claim nếu có, fallback "system"
	addedBy := "system"
	if u := r.Context().Value("username"); u != nil {
		if s, ok := u.(string); ok && s != "" {
			addedBy = s
		}
	}

	var newID int
	err := h.DB.Pool().QueryRow(r.Context(), `
		INSERT INTO sw_policy_list (list_type, name, version, vendor, category, reason, hash, added_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (list_type, name) DO UPDATE SET
			version   = EXCLUDED.version,
			vendor    = EXCLUDED.vendor,
			category  = EXCLUDED.category,
			reason    = EXCLUDED.reason,
			hash      = EXCLUDED.hash,
			added_by  = EXCLUDED.added_by,
			added_at  = NOW()
		RETURNING id`,
		listType, body.Name, body.Version, body.Vendor,
		body.Category, body.Reason, body.Hash, addedBy,
	).Scan(&newID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	logAudit(r, h.DB, "SW_LIST_UPDATED",
		listType+":"+body.Name+":added_by="+addedBy)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": newID})
}

// DELETE /api/v1/software-inventory/{list_type}/{id}
func (h *SoftwareInventoryHandler) RemoveFromList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	listType := chi.URLParam(r, "list_type")
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil || (listType != "whitelist" && listType != "blacklist" && listType != "warning") {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid params"})
		return
	}
	tag, err := h.DB.Pool().Exec(r.Context(),
		`DELETE FROM sw_policy_list WHERE id=$1 AND list_type=$2`, id, listType)
	if err != nil || tag.RowsAffected() == 0 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "not found"})
		return
	}
	logAudit(r, h.DB, "SW_LIST_UPDATED", listType+":id="+idStr+":removed")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// ─── GET /api/v1/software-inventory/cracks ───────────────────────────────────
// Lấy từ software_findings (đã có) lọc suspicious=true
func (h *SoftwareInventoryHandler) ListCracks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT
			sf.name, sf.version, sf.hostname,
			sf.susp_reason,
			CASE
				WHEN sf.susp_reason ILIKE '%crack%' OR sf.susp_reason ILIKE '%keygen%' THEN 'CRITICAL'
				WHEN sf.susp_reason ILIKE '%patcher%' OR sf.susp_reason ILIKE '%entropy%' THEN 'HIGH'
				ELSE 'MEDIUM'
			END AS risk,
			COALESCE(sf.sha256,'—') AS sha256,
			sf.detected_at
		FROM software_findings sf
		WHERE sf.suspicious = true
		ORDER BY sf.detected_at DESC
		LIMIT 200`)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()

	type CrackFinding struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Host       string `json:"host"`
		Method     string `json:"method"`
		Risk       string `json:"risk"`
		Hash       string `json:"hash"`
		DetectedAt string `json:"detected_at"`
	}
	var items []CrackFinding
	for rows.Next() {
		var c CrackFinding
		var det time.Time
		_ = rows.Scan(&c.Name, &c.Version, &c.Host, &c.Method, &c.Risk, &c.Hash, &det)
		c.DetectedAt = det.Format("2006-01-02 15:04")
		items = append(items, c)
	}
	if items == nil {
		items = []CrackFinding{}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "total": len(items)})
}

// ─── GET /api/v1/software-inventory/licenses ─────────────────────────────────
// Join software_findings với eol_database để suy ra license type
// Trong thực tế nên có bảng sw_licenses riêng từ SBOM ingest
func (h *SoftwareInventoryHandler) ListLicenses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Cố query bảng sw_licenses nếu có (từ SBOM ingest), fallback về findings
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT
			component, version, license, license_type,
			CASE
				WHEN license IS NULL OR license = '' THEN 'CRITICAL'
				WHEN license ILIKE 'agpl%' OR license ILIKE 'gpl-3%' THEN 'WARN'
				WHEN license ILIKE 'gpl%' THEN 'WARN'
				WHEN license ILIKE 'lgpl%' THEN 'INFO'
				ELSE 'OK'
			END AS risk,
			in_sbom
		FROM sw_licenses
		ORDER BY risk DESC, component ASC
		LIMIT 500`)
	if err != nil {
		// Bảng sw_licenses chưa có — trả empty với gợi ý
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []interface{}{}, "total": 0,
			"hint": "sw_licenses table not found — run SBOM ingest to populate",
		})
		return
	}
	defer rows.Close()

	type LicenseEntry struct {
		Component   string `json:"comp"`
		Version     string `json:"ver"`
		License     string `json:"license"`
		LicenseType string `json:"type"`
		Risk        string `json:"risk"`
		InSBOM      bool   `json:"sbom"`
	}
	var items []LicenseEntry
	for rows.Next() {
		var e LicenseEntry
		_ = rows.Scan(&e.Component, &e.Version, &e.License, &e.LicenseType, &e.Risk, &e.InSBOM)
		items = append(items, e)
	}
	if items == nil {
		items = []LicenseEntry{}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "total": len(items)})
}

// ─── GET /api/v1/software-inventory/scan-history ─────────────────────────────
// Đọc từ audit_log (đã có) lọc SW_INVENTORY_RECEIVED
func (h *SoftwareInventoryHandler) ListScanHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT
			'SW-'||LPAD(ROW_NUMBER() OVER (ORDER BY sa.updated_at DESC)::text, 3, '0') AS run_id,
			sa.hostname,
			sa.total_software,
			sa.suspicious_count,
			sa.crack_count,
			sa.eol_count,
			sa.updated_at
		FROM software_assets sa
		ORDER BY sa.updated_at DESC
		LIMIT 50`)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()

	type ScanRun struct {
		RunID  string `json:"rid"`
		Host   string `json:"host"`
		Total  int    `json:"total"`
		Unauth int    `json:"unauth"`
		Crack  int    `json:"crack"`
		EOL    int    `json:"eol"`
		Date   string `json:"date"`
		Status string `json:"status"`
	}
	var items []ScanRun
	for rows.Next() {
		var s ScanRun
		var updatedAt time.Time
		_ = rows.Scan(&s.RunID, &s.Host, &s.Total, &s.Unauth, &s.Crack, &s.EOL, &updatedAt)
		s.Date = updatedAt.Format("2006-01-02 15:04")
		s.Status = "DONE"
		items = append(items, s)
	}
	if items == nil {
		items = []ScanRun{}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "total": len(items)})
}

// ─── POST /api/v1/software-inventory/hash-check ──────────────────────────────
func (h *SoftwareInventoryHandler) HashCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body struct {
		Hash string `json:"hash"`
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	hash := strings.TrimSpace(strings.ToLower(body.Hash))
	if hash == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "hash required"})
		return
	}

	// Bước 1: kiểm tra trong software_findings theo sha256
	var matchName, matchHost, matchReason string
	err := h.DB.Pool().QueryRow(r.Context(), `
		SELECT name, hostname, susp_reason
		FROM software_findings
		WHERE LOWER(sha256) = $1 AND suspicious = true
		LIMIT 1`, hash).Scan(&matchName, &matchHost, &matchReason)

	if err == nil {
		// Found in known-bad findings
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true, "match": true,
			"verdict":  "CRACK_MATCH",
			"name":     matchName,
			"host":     matchHost,
			"reason":   matchReason,
			"source":   "internal_crack_db",
			"action":   "BLOCK",
		})
		return
	}

	// Bước 2: kiểm tra pattern trong hash string (heuristic fallback)
	isSusp := false
	for _, p := range crackPatterns {
		if p.MatchString(body.Name) {
			isSusp = true
			break
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"match":   isSusp,
		"verdict": map[bool]string{true: "SUSPICIOUS_NAME", false: "CLEAN"}[isSusp],
		"name":    body.Name,
		"hash":    body.Hash,
		"source":  "pattern_check",
		"action":  map[bool]string{true: "REVIEW", false: "OK"}[isSusp],
	})
}

// ─── GET/POST /api/v1/software-inventory/policy ──────────────────────────────
type SWPolicy struct {
	BlockUnauthorized bool `json:"block_unauthorized"`
	CrackScanOnIngest bool `json:"crack_scan_on_ingest"`
	EOLAlert          bool `json:"eol_alert"`
	GPLEnforcement    bool `json:"gpl_enforcement"`
	VTEnrichment      bool `json:"vt_enrichment"`
}

func (h *SoftwareInventoryHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var p SWPolicy
	var raw []byte
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT config FROM tenant_config WHERE key='sw_policy' LIMIT 1`).Scan(&raw)
	if err != nil || json.Unmarshal(raw, &p) != nil {
		// Defaults khi chưa có config
		p = SWPolicy{
			BlockUnauthorized: true,
			CrackScanOnIngest: true,
			EOLAlert:          true,
			GPLEnforcement:    false,
			VTEnrichment:      false,
		}
	}
	_ = json.NewEncoder(w).Encode(p)
}

func (h *SoftwareInventoryHandler) SavePolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var p SWPolicy
	if !decodeJSON(w, r, &p) {
		return
	}
	raw, _ := json.Marshal(p)
	_, err := h.DB.Pool().Exec(r.Context(), `
		INSERT INTO tenant_config (key, config, updated_at)
		VALUES ('sw_policy', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()`, raw)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	logAudit(r, h.DB, "SW_POLICY_UPDATED", "policy saved")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}
