package llm

import "context"

// Provider abstracts local LLM runtimes (Ollama, llama.cpp, vLLM, mock).
// All implementations MUST:
//   - Use loopback URLs only (127.0.0.1 / localhost) — verified at construction
//   - Output structured JSON matching FixResponse schema
//   - Not retain or log code content
type Provider interface {
	Name() string
	Health(ctx context.Context) error
	GenerateFix(ctx context.Context, req FixRequest) (FixResponse, error)
}

// FixRequest is what the handler sends to the LLM.
// Code context is intentionally limited to ±10 lines to minimize prompt size.
type FixRequest struct {
	RuleID          string `json:"rule_id"`
	RuleDescription string `json:"rule_description"`
	FilePath        string `json:"file_path"`        // for language detection
	Language        string `json:"language"`         // go|yaml|tf|py|...
	CodeBefore      string `json:"code_before"`
	VulnerableCode  string `json:"vulnerable_code"`
	CodeAfter       string `json:"code_after"`
	Severity        string `json:"severity"`         // critical|high|medium|low
}

// FixResponse is what the LLM produces (parsed from JSON in model output).
// Provider/Model/LatencyMs/TokensUsed are filled by the impl, not the model.
type FixResponse struct {
	SuggestedCode  string `json:"suggested_code"`
	Rationale      string `json:"rationale"`
	Confidence     string `json:"confidence"`     // high|medium|low
	BreakingChange bool   `json:"breaking_change"`

	Provider   string `json:"-"`
	Model      string `json:"-"`
	LatencyMs  int64  `json:"-"`
	TokensUsed int    `json:"-"`
}

// LanguageFromPath returns a best-effort language tag from file extension.
// Used to give the LLM a hint about what syntax to follow.
func LanguageFromPath(path string) string {
	extMap := map[string]string{
		".go": "go", ".py": "python", ".js": "javascript", ".ts": "typescript",
		".java": "java", ".rb": "ruby", ".rs": "rust", ".c": "c", ".cpp": "cpp",
		".tf": "terraform", ".hcl": "hcl",
		".yaml": "yaml", ".yml": "yaml",
		".json": "json", ".toml": "toml",
		".sh": "bash", ".bash": "bash",
		".dockerfile": "dockerfile",
		".sql": "sql",
	}
	// Find last . in path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			if lang, ok := extMap[path[i:]]; ok {
				return lang
			}
			return "text"
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	// Special filenames
	switch {
	case contains(path, "Dockerfile"):
		return "dockerfile"
	case contains(path, "Makefile"):
		return "makefile"
	}
	return "text"
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
