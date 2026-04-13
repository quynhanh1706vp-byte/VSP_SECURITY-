package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/vsp/platform/internal/store"
)

type SoftwareInventoryHandler struct {
	DB *store.DB
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
		ORDER BY risk_score DESC, last_seen DESC LIMIT 200
	`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"assets": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()
	var assets []InventoryAsset
	for rows.Next() {
		var a InventoryAsset
		rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.OSVersion, &a.Arch,
			&a.TotalSoftware, &a.SuspCount, &a.EOLCount, &a.CrackCount,
			&a.RiskScore, &a.RiskLevel, &a.LastSeen, &a.AgentVersion)
		assets = append(assets, a)
	}
	if assets == nil {
		assets = []InventoryAsset{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"assets": assets, "total": len(assets)})
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
	h.DB.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM software_assets`).Scan(&s.TotalAssets)
	h.DB.Pool().QueryRow(r.Context(), `SELECT COALESCE(SUM(total_software),0) FROM software_assets`).Scan(&s.TotalSoftware)
	h.DB.Pool().QueryRow(r.Context(), `SELECT COALESCE(SUM(eol_count),0) FROM software_assets`).Scan(&s.TotalEOL)
	h.DB.Pool().QueryRow(r.Context(), `SELECT COALESCE(SUM(crack_count),0) FROM software_assets`).Scan(&s.TotalCrack)
	h.DB.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM software_assets WHERE risk_score>=70`).Scan(&s.CriticalAssets)
	h.DB.Pool().QueryRow(r.Context(), `SELECT COUNT(*) FROM software_assets WHERE risk_level='clean'`).Scan(&s.CleanAssets)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func (h *SoftwareInventoryHandler) GetAsset(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	var a InventoryAsset
	err := h.DB.Pool().QueryRow(r.Context(), `
		SELECT id, hostname, os, os_version, arch,
		       total_software, suspicious_count, eol_count, crack_count,
		       risk_score, risk_level, last_seen, agent_version
		FROM software_assets WHERE hostname=$1
	`, hostname).Scan(&a.ID, &a.Hostname, &a.OS, &a.OSVersion, &a.Arch,
		&a.TotalSoftware, &a.SuspCount, &a.EOLCount, &a.CrackCount,
		&a.RiskScore, &a.RiskLevel, &a.LastSeen, &a.AgentVersion)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"asset": map[string]interface{}{}, "findings": []interface{}{}})
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
		FROM software_findings WHERE hostname=$1 ORDER BY detected_at DESC LIMIT 50
	`, hostname)
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		var f Finding
		rows.Scan(&f.Name, &f.Version, &f.Publisher, &f.SHA256, &f.Signed, &f.SuspReason, &f.Source, &f.DetectedAt)
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []Finding{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"asset": a, "findings": findings})
}

func (h *SoftwareInventoryHandler) ReceiveReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func (h *SoftwareInventoryHandler) ListEOL(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Pool().Query(r.Context(), `
		SELECT product_name, vendor, version_pattern, eol_date, status, source
		FROM eol_database ORDER BY eol_date DESC NULLS LAST LIMIT 100
	`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}})
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
		rows.Scan(&e.ProductName, &e.Vendor, &e.VersionPattern, &eolDate, &e.Status, &e.Source)
		if eolDate != nil {
			e.EOLDate = *eolDate
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []EOLEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"entries": entries, "total": len(entries)})
}
