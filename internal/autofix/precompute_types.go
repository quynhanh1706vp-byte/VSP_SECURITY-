package autofix

import (
	"time"
)

// PrecomputeJob represents a single batch run of AI fix pre-computation,
// tied to one VSP scan run. Tracked in autofix_precompute_jobs table so the
// UI can show progress and admins can debug stuck jobs.
type PrecomputeJob struct {
	ID         string // uuid
	RunID      string // uuid (FK runs.id)
	TenantID   string // uuid
	Status     string // pending|running|done|failed|canceled
	Total      int    // findings eligible for pre-compute
	Completed  int    // successfully cached
	Failed     int    // LLM call errors / timeouts
	Skipped    int    // policy blocked or already cached
	AvgLatency int    // ms, average of successful calls
	StartedAt  *time.Time
	FinishedAt *time.Time
	CreatedAt  time.Time
}

// PrecomputeFinding is the minimal data needed to call the LLM.
// Loaded from findings table by the worker.
type PrecomputeFinding struct {
	ID       string
	RuleID   string
	Severity string
	Path     string
	LineNum  int
	Message  string
	Tool     string
}

// IsCodeFile returns true if the path looks like source code we can extract
// context from. Used to filter findings before queuing for LLM.
func IsCodeFile(path string) bool {
	if path == "" {
		return false
	}
	codeExts := []string{
		".go", ".py", ".js", ".ts", ".jsx", ".tsx",
		".java", ".rb", ".rs", ".c", ".cpp", ".cs",
		".yml", ".yaml", ".tf", ".hcl",
	}
	for _, ext := range codeExts {
		if len(path) >= len(ext) && path[len(path)-len(ext):] == ext {
			return true
		}
	}
	// Special files without extension
	if len(path) >= 10 && path[len(path)-10:] == "Dockerfile" {
		return true
	}
	if len(path) >= 17 && path[len(path)-17:] == "docker-compose.yml" {
		return true
	}
	return false
}
