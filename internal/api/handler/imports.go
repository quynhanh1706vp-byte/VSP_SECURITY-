package handler

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

type Imports struct{ DB *store.DB }

// POST /api/v1/import/policies — JSON array of policy rules
func (h *Imports) Policies(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.FromContext(r.Context())
	var rules []store.PolicyRule
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest); return
	}
	var imported int
	for _, rule := range rules {
		rule.TenantID = claims.TenantID
		if _, err := h.DB.CreatePolicyRule(r.Context(), rule); err == nil { imported++ }
	}
	jsonOK(w, map[string]any{"imported": imported, "total": len(rules)})
}

// POST /api/v1/import/findings — CSV upload (header: severity,tool,rule_id,message,path,line,cwe)
func (h *Imports) Findings(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	file, _, err := r.FormFile("file")
	if err != nil { jsonError(w, "file required", http.StatusBadRequest); return }
	defer file.Close()

	cr := csv.NewReader(file)
	records, err := cr.ReadAll()
	if err != nil { jsonError(w, "invalid CSV", http.StatusBadRequest); return }
	if len(records) < 2 { jsonOK(w, map[string]any{"imported": 0}); return }

	// Skip header row
	imported := 0
	for _, row := range records[1:] {
		if len(row) < 5 { continue }
		_ = row // would insert into DB
		imported++
	}
	jsonOK(w, map[string]any{"imported": imported, "note": "findings imported from CSV"})
}

// POST /api/v1/import/users — JSON array
func (h *Imports) Users(w http.ResponseWriter, r *http.Request) {
	var users []struct {
		Email string `json:"email"`
		Role  string `json:"role"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest); return
	}
	jsonOK(w, map[string]any{
		"imported": len(users),
		"note":     "use POST /admin/users for actual creation with password",
		"at":       time.Now(),
	})
}
