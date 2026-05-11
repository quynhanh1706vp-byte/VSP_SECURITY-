// Package handler — data residency configuration endpoint.
//
// Tenant admins set the primary region + optional egress regions for
// their tenant. The middleware enforces this on every authenticated
// request; this handler is the management surface.
package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Residency struct {
	DB *store.DB
}

func NewResidency(db *store.DB) *Residency { return &Residency{DB: db} }

type residencyConfig struct {
	PrimaryRegion      string   `json:"primary_region"`
	AllowEgressRegions []string `json:"allow_egress_regions"`
	Basis              string   `json:"basis,omitempty"`
}

// validRegions is a soft whitelist — operator can append by editing
// this slice + redeploying. The DB column is free-text so adding a
// region doesn't need a migration; the whitelist guards against typos.
var validRegions = map[string]bool{
	"vn-1": true, "vn-2": true, // Vietnam mainland (Hanoi, HCMC)
	"sg-1":         true, // Singapore (closest APAC neighbour)
	"jp-1":         true, // Tokyo
	"eu-frankfurt": true,
	"eu-paris":     true,
	"us-east-1":    true,
	"us-west-2":    true,
}

func (h *Residency) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var primary, basis string
	var egress []string
	err := h.DB.Pool().QueryRow(r.Context(),
		`SELECT primary_region, allow_egress_regions, COALESCE(basis,'')
		   FROM tenant_residency WHERE tenant_id = $1`,
		tenantID).Scan(&primary, &egress, &basis)
	if err != nil {
		// No row = unconfigured — return empty config.
		jsonOK(w, residencyConfig{})
		return
	}
	jsonOK(w, residencyConfig{
		PrimaryRegion:      primary,
		AllowEgressRegions: egress,
		Basis:              basis,
	})
}

func (h *Residency) Set(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok || claims.Role != "admin" {
		jsonError(w, "forbidden — admin role required", http.StatusForbidden)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	userID := resolveUserUUID(r.Context(), h.DB, claims.UserID)
	var userPtr *string
	if userID != "" {
		userPtr = &userID
	}
	var cfg residencyConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	cfg.PrimaryRegion = strings.ToLower(strings.TrimSpace(cfg.PrimaryRegion))
	if !validRegions[cfg.PrimaryRegion] {
		jsonError(w, "primary_region not in supported list", http.StatusBadRequest)
		return
	}
	cleanEgress := make([]string, 0, len(cfg.AllowEgressRegions))
	for _, e := range cfg.AllowEgressRegions {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == cfg.PrimaryRegion {
			continue
		}
		if !validRegions[e] {
			jsonError(w, "egress region "+e+" not in supported list",
				http.StatusBadRequest)
			return
		}
		cleanEgress = append(cleanEgress, e)
	}
	if len(cfg.Basis) > 1024 {
		cfg.Basis = cfg.Basis[:1024]
	}

	if _, err := h.DB.Pool().Exec(r.Context(),
		`INSERT INTO tenant_residency
		   (tenant_id, primary_region, allow_egress_regions, basis,
		    confirmed_by, confirmed_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (tenant_id) DO UPDATE
		 SET primary_region       = EXCLUDED.primary_region,
		     allow_egress_regions = EXCLUDED.allow_egress_regions,
		     basis                = EXCLUDED.basis,
		     confirmed_by         = EXCLUDED.confirmed_by,
		     confirmed_at         = NOW(),
		     updated_at           = NOW()`,
		tenantID, cfg.PrimaryRegion, cleanEgress, cfg.Basis, userPtr,
	); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit(r, h.DB, "RESIDENCY_CONFIGURED",
		"tenant_residency/"+tenantID+":"+cfg.PrimaryRegion)
	jsonOK(w, cfg)
}

// Violations returns recent residency violation records for the tenant.
func (h *Residency) Violations(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), h.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT id::text, gateway_region, expected_region, request_path,
		        COALESCE(request_ip,''), detected_at
		   FROM residency_violations
		  WHERE tenant_id = $1
		  ORDER BY detected_at DESC LIMIT 200`, tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type item struct {
		ID             string `json:"id"`
		GatewayRegion  string `json:"gateway_region"`
		ExpectedRegion string `json:"expected_region"`
		Path           string `json:"path"`
		IP             string `json:"ip,omitempty"`
		DetectedAt     string `json:"detected_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var detected string
		if err := rows.Scan(&it.ID, &it.GatewayRegion, &it.ExpectedRegion,
			&it.Path, &it.IP, &detected); err == nil {
			it.DetectedAt = detected
			out = append(out, it)
		}
	}
	jsonOK(w, map[string]any{"violations": out, "total": len(out)})
}
