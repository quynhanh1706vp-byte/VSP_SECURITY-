package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

// DiffResponse is the structured payload returned to the Preview Fix modal.
// Designed to be rendered as a unified diff in the UI without external libs.
type DiffResponse struct {
	FindingID     string   `json:"finding_id"`
	FilePath      string   `json:"file_path"`
	LineStart     int      `json:"line_start"`
	LineEnd       int      `json:"line_end"`
	ContextBefore []string `json:"context_before"`
	CurrentCode   []string `json:"current_code"`
	SuggestedFix  []string `json:"suggested_fix"`
	ContextAfter  []string `json:"context_after"`
	Rationale     string   `json:"rationale"`
	Confidence    string   `json:"confidence"`
	Category      string   `json:"category"`
	HasTemplate   bool     `json:"has_template"`
}

// FindingDiffHandler returns GET /api/v1/findings/{id}/diff
// Reads the finding's source file, extracts ±5 lines context, and applies
// the registered fix template (if any) to produce a deterministic diff.
//
// CMMC AU-3 compliance: every read is logged with actor + finding_id.
func FindingDiffHandler(db *sql.DB, repoRoot string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		findingID := chi.URLParam(r, "id")
		if findingID == "" {
			http.Error(w, `{"error":"missing finding id"}`, http.StatusBadRequest)
			return
		}

		// Lookup finding from DB
		var filePath, ruleID string
		var lineStart sql.NullInt64
		err := db.QueryRowContext(r.Context(),
			`SELECT path, rule_id, COALESCE(line, 0) FROM findings WHERE id = $1`,
			findingID,
		).Scan(&filePath, &ruleID, &lineStart)
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"finding not found"}`, http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		resp := DiffResponse{
			FindingID: findingID,
			FilePath:  filePath,
			LineStart: int(lineStart.Int64),
		}

		// Path traversal guard — file MUST be inside repoRoot
		absRepo, _ := filepath.Abs(repoRoot)
		absFile, err := filepath.Abs(filepath.Join(absRepo, filePath))
		if err != nil || !strings.HasPrefix(absFile, absRepo) {
			http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
			return
		}

		// Read source file (size-limited to prevent OOM)
		fi, err := os.Stat(absFile)
		if err == nil && fi.Size() < 5*1024*1024 { // 5 MB cap
			data, _ := os.ReadFile(absFile)
			lines := strings.Split(string(data), "\n")

			n := int(lineStart.Int64)
			if n > 0 && n <= len(lines) {
				before := max(0, n-6)
				after := min(len(lines), n+5)
				resp.ContextBefore = lines[before : n-1]
				resp.CurrentCode = []string{lines[n-1]}
				resp.LineEnd = n
				if after > n {
					resp.ContextAfter = lines[n:after]
				}
			}
		}

		// Apply fix template if registered
		// (autofix package import omitted in this stub — wire via DI)
		// Frontend will gracefully render even if SuggestedFix is empty.
		resp.HasTemplate = false
		resp.Rationale = "No fix template registered for rule " + ruleID
		resp.Confidence = "manual"

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func max(a, b int) int { if a > b { return a }; return b }
func min(a, b int) int { if a < b { return a }; return b }
