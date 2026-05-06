// VSP_PATCH_F1 — Bulk Findings actions (Sprint 1, patch 1/8)
//
// Drop this file into cmd/gateway/. The patcher script will register the
// two routes inside the authenticated /api/v1 group of main.go.
//
// Routes (registered by patcher in main.go, not here):
//   POST /api/v1/vulns/bulk      → handleVulnsBulk
//   POST /api/v1/vulns/bulk/undo → handleVulnsBulkUndo
//
// Refs: ROADMAP_PRO_100.md
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// bulkActionRecord stores one bulk action for the 60s undo window.
type bulkActionRecord struct {
	UndoToken string         `json:"undo_token"`
	Action    string         `json:"action"`
	CVEIDs    []string       `json:"cve_ids"`
	Metadata  map[string]any `json:"metadata"`
	UserID    string         `json:"user_id,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

var (
	bulkUndoMu    sync.Mutex
	bulkUndoStore = make(map[string]*bulkActionRecord)
)

// cleanupBulkUndoStore garbage-collects undo records older than 60s.
// Call once from main(): go cleanupBulkUndoStore()
func cleanupBulkUndoStore() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		bulkUndoMu.Lock()
		cutoff := time.Now().Add(-60 * time.Second)
		for k, rec := range bulkUndoStore {
			if rec.CreatedAt.Before(cutoff) {
				delete(bulkUndoStore, k)
			}
		}
		bulkUndoMu.Unlock()
	}
}

func newUndoToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "und_" + hex.EncodeToString(b)
}

func newBulkActionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "act_" + hex.EncodeToString(b)
}

// handleVulnsBulk: POST /api/v1/vulns/bulk
func handleVulnsBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action   string         `json:"action"`
		CVEIDs   []string       `json:"cve_ids"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBulkErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	defer r.Body.Close()

	switch req.Action {
	case "resolve", "suppress", "assign", "create_poam":
	default:
		writeBulkErr(w, http.StatusBadRequest, "unknown action: "+req.Action)
		return
	}

	if len(req.CVEIDs) == 0 {
		writeBulkErr(w, http.StatusBadRequest, "cve_ids cannot be empty")
		return
	}
	if len(req.CVEIDs) > 1000 {
		writeBulkErr(w, http.StatusBadRequest, "max 1000 cve_ids per request")
		return
	}

	// TODO(F1-DB): wire to real findings store.
	//   resolve     → UPDATE findings SET status='resolved' WHERE cve_id = ANY($1)
	//   suppress    → INSERT INTO suppressions ...
	//   assign      → UPDATE findings SET assignee = $1 WHERE ...
	//   create_poam → INSERT INTO poam_items ...

	userID, _ := r.Context().Value("user_id").(string)
	actionID := newBulkActionID()
	undoToken := newUndoToken()

	bulkUndoMu.Lock()
	bulkUndoStore[undoToken] = &bulkActionRecord{
		UndoToken: undoToken,
		Action:    req.Action,
		CVEIDs:    req.CVEIDs,
		Metadata:  req.Metadata,
		UserID:    userID,
		CreatedAt: time.Now(),
	}
	bulkUndoMu.Unlock()

	log.Printf("[bulk-vulns] user=%s action=%s n=%d action_id=%s",
		userID, req.Action, len(req.CVEIDs), actionID)

	writeBulkJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"affected":   len(req.CVEIDs),
		"action_id":  actionID,
		"undo_token": undoToken,
	})
}

// handleVulnsBulkUndo: POST /api/v1/vulns/bulk/undo
func handleVulnsBulkUndo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UndoToken string `json:"undo_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBulkErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	defer r.Body.Close()

	bulkUndoMu.Lock()
	rec, ok := bulkUndoStore[req.UndoToken]
	if ok {
		delete(bulkUndoStore, req.UndoToken)
	}
	bulkUndoMu.Unlock()

	if !ok {
		writeBulkErr(w, http.StatusNotFound, "undo token expired or unknown")
		return
	}

	// TODO(F1-DB): reverse the action in DB.

	log.Printf("[bulk-vulns] UNDO action=%s n=%d token=%s",
		rec.Action, len(rec.CVEIDs), rec.UndoToken)

	writeBulkJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"reverted": len(rec.CVEIDs),
		"action":   rec.Action,
	})
}

// ─── helpers (prefixed to avoid collision with anything in main.go) ───

func writeBulkJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeBulkErr(w http.ResponseWriter, status int, msg string) {
	writeBulkJSON(w, status, map[string]any{"ok": false, "error": msg})
}
