// Package handler — MITRE ATT&CK heatmap.
//
// Endpoint: GET /api/v1/attack/heatmap?days=30
//
// Aggregates findings into a tactic × technique grid, producing the
// "Navigator-style" coverage view. Each cell carries the count of findings
// mapped to that technique plus the maximum severity seen.
//
// Mapping: see mitre_mapping.go. Findings whose tool/rule/CWE doesn't
// resolve to a technique are dropped (and the count of unmapped is
// returned in the response so the FE can flag mapping gaps).
package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Attack struct {
	DB *store.DB
}

func NewAttack(db *store.DB) *Attack { return &Attack{DB: db} }

type techCell struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Count  int            `json:"count"`
	MaxSev string         `json:"max_severity"`
	Sev    map[string]int `json:"by_severity"`
}

type tacticOut struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Techniques []techCell `json:"techniques"`
	Count      int        `json:"count"`
}

func (h *Attack) Heatmap(w http.ResponseWriter, r *http.Request) {
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

	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v > 0 && v <= 365 {
		days = v
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	rows, err := h.DB.Pool().Query(r.Context(),
		`SELECT tool, COALESCE(rule_id,''), COALESCE(cwe,''), severity
		   FROM findings
		  WHERE tenant_id = $1 AND created_at >= $2`,
		tenantID, cutoff)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// agg[techniqueID] = (count, sev counts, maxSev)
	type acc struct {
		count  int
		sev    map[string]int
		maxSev string
	}
	agg := map[string]*acc{}
	total, unmapped := 0, 0
	for rows.Next() {
		var tool, ruleID, cwe, sev string
		if err := rows.Scan(&tool, &ruleID, &cwe, &sev); err != nil {
			continue
		}
		total++
		tID := classifyFinding(tool, ruleID, cwe)
		if tID == "" {
			unmapped++
			continue
		}
		a, ok := agg[tID]
		if !ok {
			a = &acc{sev: map[string]int{}}
			agg[tID] = a
		}
		a.count++
		s := normalizeSev(sev)
		a.sev[s]++
		if sevRank(s) > sevRank(a.maxSev) {
			a.maxSev = s
		}
	}

	// Build tactic-grouped output preserving canonical ordering.
	out := make([]tacticOut, 0, len(mitreTactics))
	for _, ta := range mitreTactics {
		t := tacticOut{ID: ta.ID, Name: ta.Name, Techniques: []techCell{}}
		for tid, info := range techniqueCatalog {
			if info.Tactic != ta.ID {
				continue
			}
			if a, ok := agg[tid]; ok {
				t.Techniques = append(t.Techniques, techCell{
					ID: tid, Name: info.Name, Count: a.count,
					MaxSev: a.maxSev, Sev: a.sev,
				})
				t.Count += a.count
			}
		}
		out = append(out, t)
	}

	jsonOK(w, map[string]any{
		"window_days":        days,
		"total_findings":     total,
		"mapped_findings":    total - unmapped,
		"unmapped":           unmapped,
		"tactics":            out,
		"tactics_covered":    countCovered(out),
		"techniques_covered": len(agg),
	})
}

func normalizeSev(s string) string {
	switch s {
	case "critical", "CRITICAL":
		return "critical"
	case "high", "HIGH":
		return "high"
	case "medium", "MEDIUM", "moderate":
		return "medium"
	case "low", "LOW":
		return "low"
	}
	return "info"
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func countCovered(tactics []tacticOut) int {
	n := 0
	for _, t := range tactics {
		if t.Count > 0 {
			n++
		}
	}
	return n
}
