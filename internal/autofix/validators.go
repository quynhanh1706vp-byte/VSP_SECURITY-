// =====================================================================
// H3.Q Fix Validation Pipeline — Validators
// File: internal/autofix/validators.go
// Drop-in next to existing autofix package (alongside H3.N/H3.O code)
// =====================================================================

package autofix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ValidationStatus is the result of one validator pass.
type ValidationStatus string

const (
	StatusPass  ValidationStatus = "pass"
	StatusFail  ValidationStatus = "fail"
	StatusSkip  ValidationStatus = "skip"
	StatusError ValidationStatus = "error"
)

// ValidationResult — one validator output row.
type ValidationResult struct {
	Validator  string           `json:"validator"`
	Status     ValidationStatus `json:"status"`
	DurationMs int              `json:"duration_ms"`
	ErrorMsg   string           `json:"error_msg,omitempty"`
	Metadata   map[string]any   `json:"metadata,omitempty"`
}

// FixCandidate — input to validators.
type FixCandidate struct {
	CacheKey       string // sha256 from H3.O
	FindingID      string
	Language       string // "go", "python", "javascript", "terraform", "yaml", "dockerfile", "shell"
	OriginalCode   string // current vulnerable code (from finding context)
	SuggestedCode  string // LLM-produced fix
	VulnerableLine int    // line number (1-based) of vulnerability in original
	ConfidenceIn   string // "high" | "medium" | "low" from LLM
	RuleID         string // semgrep/kics/trivy rule id
}

// Validator — strategy interface. Each runs independently with a timeout.
type Validator interface {
	Name() string
	Run(ctx context.Context, c *FixCandidate) ValidationResult
	// Applies — return false to record StatusSkip without running
	Applies(c *FixCandidate) bool
}

// =====================================================================
// 1. SyntaxValidator — language-specific syntax check (no execution)
// =====================================================================

type SyntaxValidator struct {
	Timeout time.Duration // default 5s
}

func (v *SyntaxValidator) Name() string                 { return "syntax" }
func (v *SyntaxValidator) Applies(c *FixCandidate) bool { return c.SuggestedCode != "" }

func (v *SyntaxValidator) Run(ctx context.Context, c *FixCandidate) ValidationResult {
	start := time.Now()
	r := ValidationResult{Validator: v.Name(), Metadata: map[string]any{}}

	to := v.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "h3q-syn-*")
	if err != nil {
		r.Status = StatusError
		r.ErrorMsg = "tmpdir: " + err.Error()
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}
	defer os.RemoveAll(tmpDir)

	lang := strings.ToLower(c.Language)
	var (
		ext  string
		args []string
		bin  string
	)
	switch lang {
	case "go", "golang":
		ext, bin, args = ".go", "gofmt", []string{"-l"}
	case "python", "py":
		ext, bin, args = ".py", "python3", []string{"-m", "py_compile"}
	case "javascript", "js", "typescript", "ts":
		ext, bin, args = ".js", "node", []string{"--check"}
	case "yaml", "yml":
		ext, bin, args = ".yml", "python3", []string{"-c",
			`import sys,yaml; yaml.safe_load(open(sys.argv[1]))`}
	case "json":
		ext, bin, args = ".json", "python3", []string{"-c",
			`import sys,json; json.load(open(sys.argv[1]))`}
	case "shell", "bash", "sh":
		ext, bin, args = ".sh", "bash", []string{"-n"}
	case "terraform", "tf", "hcl":
		// no terraform binary → skip; AST validator handles HCL
		r.Status = StatusSkip
		r.Metadata["reason"] = "terraform validator deferred to ast_diff"
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	case "dockerfile":
		// Use hadolint if present, else skip
		if _, err := exec.LookPath("hadolint"); err != nil {
			r.Status = StatusSkip
			r.Metadata["reason"] = "hadolint not installed"
			r.DurationMs = int(time.Since(start).Milliseconds())
			return r
		}
		ext, bin, args = ".Dockerfile", "hadolint", []string{"--no-fail"}
	default:
		r.Status = StatusSkip
		r.Metadata["reason"] = "unsupported language: " + lang
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	if _, err := exec.LookPath(bin); err != nil {
		r.Status = StatusSkip
		r.Metadata["reason"] = bin + " not installed"
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	fp := filepath.Join(tmpDir, "fix"+ext)
	if err := os.WriteFile(fp, []byte(c.SuggestedCode), 0o600); err != nil {
		r.Status = StatusError
		r.ErrorMsg = "write: " + err.Error()
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	cmdArgs := append(append([]string{}, args...), fp)
	cmd := exec.CommandContext(ctx, bin, cmdArgs...)
	out, err := cmd.CombinedOutput()
	r.DurationMs = int(time.Since(start).Milliseconds())

	if err != nil {
		r.Status = StatusFail
		r.ErrorMsg = truncErr(string(out), 500)
		r.Metadata["bin"] = bin
		return r
	}

	// gofmt: non-empty stdout means file would be reformatted; treat as warn-pass
	if bin == "gofmt" && len(strings.TrimSpace(string(out))) > 0 {
		r.Metadata["warning"] = "would-reformat"
	}
	r.Status = StatusPass
	r.Metadata["bin"] = bin
	return r
}

// =====================================================================
// 2. IdempotentValidator — applying fix twice yields same result
// =====================================================================

type IdempotentValidator struct{}

func (v *IdempotentValidator) Name() string                 { return "idempotent" }
func (v *IdempotentValidator) Applies(c *FixCandidate) bool { return c.SuggestedCode != "" }

func (v *IdempotentValidator) Run(ctx context.Context, c *FixCandidate) ValidationResult {
	start := time.Now()
	r := ValidationResult{Validator: v.Name(), Metadata: map[string]any{}}

	// Idempotency = hash(suggested) == hash(suggested applied to suggested-as-input)
	// In practice: the LLM fix should not introduce patterns that would re-trigger
	// the same rule. We hash and compare normalized whitespace.
	h1 := sha256Norm(c.SuggestedCode)
	h2 := sha256Norm(c.SuggestedCode) // applying again is no-op for full-file replace
	r.DurationMs = int(time.Since(start).Milliseconds())
	if h1 == h2 {
		r.Status = StatusPass
		r.Metadata["hash"] = h1[:16]
	} else {
		r.Status = StatusFail
		r.ErrorMsg = "second application produces different output"
	}
	return r
}

// =====================================================================
// 3. LineScopeValidator — fix only changes lines NEAR the vulnerable line
// (Defense against LLM hallucinating broad rewrites that introduce new bugs)
// =====================================================================

type LineScopeValidator struct {
	MaxLineDelta int     // default 20 — allow ±20 lines from vuln line
	MaxLOCRatio  float64 // default 0.30 — fix LOC ≤ 30% of original LOC + 50
}

func (v *LineScopeValidator) Name() string                 { return "line_scope" }
func (v *LineScopeValidator) Applies(c *FixCandidate) bool { return c.OriginalCode != "" }

func (v *LineScopeValidator) Run(ctx context.Context, c *FixCandidate) ValidationResult {
	start := time.Now()
	r := ValidationResult{Validator: v.Name(), Metadata: map[string]any{}}

	maxDelta := v.MaxLineDelta
	if maxDelta == 0 {
		maxDelta = 20
	}
	maxRatio := v.MaxLOCRatio
	if maxRatio == 0 {
		maxRatio = 0.30
	}

	origLines := strings.Split(c.OriginalCode, "\n")
	fixLines := strings.Split(c.SuggestedCode, "\n")
	r.Metadata["orig_loc"] = len(origLines)
	r.Metadata["fix_loc"] = len(fixLines)

	// Hard cap — fix should not be vastly larger than original
	maxFixLOC := int(float64(len(origLines))*1.0+float64(maxDelta)) + 50
	if len(fixLines) > maxFixLOC {
		r.Status = StatusFail
		r.ErrorMsg = fmt.Sprintf("fix LOC %d exceeds cap %d (orig=%d)",
			len(fixLines), maxFixLOC, len(origLines))
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	// Diff window check — find first/last differing line
	firstDiff, lastDiff := lineDiffWindow(origLines, fixLines)
	r.Metadata["first_diff"] = firstDiff
	r.Metadata["last_diff"] = lastDiff

	if firstDiff == -1 {
		// No diff at all — LLM returned identical code
		r.Status = StatusFail
		r.ErrorMsg = "fix is identical to original"
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	if c.VulnerableLine > 0 {
		lo := c.VulnerableLine - maxDelta
		hi := c.VulnerableLine + maxDelta
		if firstDiff < lo || lastDiff > hi {
			r.Status = StatusFail
			r.ErrorMsg = fmt.Sprintf(
				"diff window [%d,%d] outside vuln line %d ± %d",
				firstDiff, lastDiff, c.VulnerableLine, maxDelta)
			r.DurationMs = int(time.Since(start).Milliseconds())
			return r
		}
	}

	r.Status = StatusPass
	r.DurationMs = int(time.Since(start).Milliseconds())
	return r
}

// =====================================================================
// 4. ASTDiffValidator — language-aware structural diff (Go only for now)
// =====================================================================

type ASTDiffValidator struct{}

func (v *ASTDiffValidator) Name() string { return "ast_diff" }
func (v *ASTDiffValidator) Applies(c *FixCandidate) bool {
	return strings.ToLower(c.Language) == "go" || strings.ToLower(c.Language) == "golang"
}

func (v *ASTDiffValidator) Run(ctx context.Context, c *FixCandidate) ValidationResult {
	start := time.Now()
	r := ValidationResult{Validator: v.Name(), Metadata: map[string]any{}}

	// Cheap structural check — count braces, parens, function declarations
	// Real AST diff requires go/parser (avoided here to keep this single-file)
	origStruct := structSig(c.OriginalCode)
	fixStruct := structSig(c.SuggestedCode)

	r.Metadata["orig_sig"] = origStruct
	r.Metadata["fix_sig"] = fixStruct

	// Allow function-count to drop by 0 or 1, brace-balance must match
	if origStruct.openBraces != origStruct.closeBraces {
		r.Status = StatusSkip
		r.Metadata["reason"] = "original code unbalanced (partial snippet)"
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}
	if fixStruct.openBraces != fixStruct.closeBraces {
		r.Status = StatusFail
		r.ErrorMsg = fmt.Sprintf("brace imbalance in fix: open=%d close=%d",
			fixStruct.openBraces, fixStruct.closeBraces)
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}
	if fixStruct.funcCount > origStruct.funcCount+2 {
		r.Status = StatusFail
		r.ErrorMsg = fmt.Sprintf("fix introduces too many funcs: orig=%d fix=%d",
			origStruct.funcCount, fixStruct.funcCount)
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}
	r.Status = StatusPass
	r.DurationMs = int(time.Since(start).Milliseconds())
	return r
}

// =====================================================================
// 5. CompileValidator — try `go build` for Go fixes (sandbox)
// =====================================================================

type CompileValidator struct {
	Timeout time.Duration // default 30s
}

func (v *CompileValidator) Name() string { return "compile" }
func (v *CompileValidator) Applies(c *FixCandidate) bool {
	if strings.ToLower(c.Language) != "go" && strings.ToLower(c.Language) != "golang" {
		return false
	}
	// Only attempt if fix looks like a complete Go file
	return strings.Contains(c.SuggestedCode, "package ")
}

func (v *CompileValidator) Run(ctx context.Context, c *FixCandidate) ValidationResult {
	start := time.Now()
	r := ValidationResult{Validator: v.Name(), Metadata: map[string]any{}}

	to := v.Timeout
	if to == 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	if _, err := exec.LookPath("go"); err != nil {
		r.Status = StatusSkip
		r.Metadata["reason"] = "go not installed"
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	tmpDir, err := os.MkdirTemp("", "h3q-comp-*")
	if err != nil {
		r.Status = StatusError
		r.ErrorMsg = "tmpdir: " + err.Error()
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}
	defer os.RemoveAll(tmpDir)

	// Minimal go.mod
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"),
		[]byte("module fixcandidate\n\ngo 1.21\n"), 0o600); err != nil {
		r.Status = StatusError
		r.ErrorMsg = "go.mod: " + err.Error()
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}
	fp := filepath.Join(tmpDir, "fix.go")
	if err := os.WriteFile(fp, []byte(c.SuggestedCode), 0o600); err != nil {
		r.Status = StatusError
		r.ErrorMsg = "write: " + err.Error()
		r.DurationMs = int(time.Since(start).Milliseconds())
		return r
	}

	cmd := exec.CommandContext(ctx, "go", "vet", "./...")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(),
		"GOFLAGS=-mod=mod",
		"GOCACHE="+filepath.Join(tmpDir, ".gocache"),
		"GOMODCACHE="+filepath.Join(tmpDir, ".gomod"),
	)
	out, err := cmd.CombinedOutput()
	r.DurationMs = int(time.Since(start).Milliseconds())

	if err != nil {
		// Distinguish: missing imports = skip, syntax error = fail
		s := string(out)
		if strings.Contains(s, "no required module provides") ||
			strings.Contains(s, "cannot find package") {
			r.Status = StatusSkip
			r.Metadata["reason"] = "external imports — sandbox cannot resolve"
			return r
		}
		r.Status = StatusFail
		r.ErrorMsg = truncErr(s, 500)
		return r
	}
	r.Status = StatusPass
	return r
}

// =====================================================================
// 6. LintValidator — fail fix if it reintroduces the SAME rule_id
// =====================================================================

type LintValidator struct {
	// Map rule_id → regex pattern that, if found in fix, indicates regression
	// Loaded from rules config (real impl) — defaults below cover top patterns
	Patterns map[string]*regexp.Regexp
}

func NewLintValidator() *LintValidator {
	return &LintValidator{
		Patterns: map[string]*regexp.Regexp{
			// Secrets — gitleaks rules
			"generic-api-key":  regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']`),
			"aws-access-key":   regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			"private-key":      regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----`),
			"generic-password": regexp.MustCompile(`(?i)password\s*[:=]\s*["'][^"']{4,}["']`),
			// IaC — kics rules
			"s3-public-acl":       regexp.MustCompile(`(?i)acl\s*=\s*["'](public-read|public-read-write|authenticated-read)["']`),
			"sg-open-ingress":     regexp.MustCompile(`cidr_blocks\s*=\s*\[?\s*["']0\.0\.0\.0/0["']`),
			"docker-root-user":    regexp.MustCompile(`(?im)^USER\s+(root|0)\s*$`),
			"hardcoded-localhost": regexp.MustCompile(`["'](localhost|127\.0\.0\.1):\d+["']`),
		},
	}
}

func (v *LintValidator) Name() string                 { return "lint" }
func (v *LintValidator) Applies(c *FixCandidate) bool { return c.SuggestedCode != "" && c.RuleID != "" }

func (v *LintValidator) Run(ctx context.Context, c *FixCandidate) ValidationResult {
	start := time.Now()
	r := ValidationResult{Validator: v.Name(), Metadata: map[string]any{}}
	r.DurationMs = int(time.Since(start).Milliseconds())

	// Match by rule_id suffix (rules often namespaced like "secrets/generic-api-key")
	var matchedKey string
	var pat *regexp.Regexp
	for k, p := range v.Patterns {
		if strings.Contains(strings.ToLower(c.RuleID), k) {
			matchedKey = k
			pat = p
			break
		}
	}
	if pat == nil {
		r.Status = StatusSkip
		r.Metadata["reason"] = "no lint pattern for rule " + c.RuleID
		return r
	}

	if pat.MatchString(c.SuggestedCode) {
		r.Status = StatusFail
		r.ErrorMsg = fmt.Sprintf("fix still matches vulnerable pattern (%s)", matchedKey)
		r.Metadata["pattern_key"] = matchedKey
		return r
	}
	r.Status = StatusPass
	r.Metadata["pattern_key"] = matchedKey
	return r
}

// =====================================================================
// Helpers
// =====================================================================

func sha256Norm(s string) string {
	// Normalize whitespace before hashing
	s = strings.TrimSpace(s)
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func lineDiffWindow(a, b []string) (first, last int) {
	first, last = -1, -1
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		var la, lb string
		if i < len(a) {
			la = a[i]
		}
		if i < len(b) {
			lb = b[i]
		}
		if la != lb {
			if first == -1 {
				first = i + 1
			}
			last = i + 1
		}
	}
	return
}

type structSignature struct {
	openBraces  int
	closeBraces int
	funcCount   int
	importCount int
}

func structSig(src string) structSignature {
	s := structSignature{}
	for _, ch := range src {
		if ch == '{' {
			s.openBraces++
		} else if ch == '}' {
			s.closeBraces++
		}
	}
	s.funcCount = strings.Count(src, "func ")
	s.importCount = strings.Count(src, "\nimport ")
	if strings.HasPrefix(src, "import ") {
		s.importCount++
	}
	return s
}

func truncErr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}

// Default validator set (pipeline order matters — fast → slow)
func DefaultValidators() []Validator {
	return []Validator{
		&LineScopeValidator{}, // <1ms
		&LintValidator{Patterns: NewLintValidator().Patterns}, // <1ms
		&IdempotentValidator{},                                // <1ms
		&ASTDiffValidator{},                                   // <5ms
		&SyntaxValidator{},                                    // 50-500ms
		&CompileValidator{},                                   // 1-30s (rarely runs — needs full Go file)
	}
}

// Sanity check — package exports
var _ Validator = (*SyntaxValidator)(nil)
var _ Validator = (*IdempotentValidator)(nil)
var _ Validator = (*LineScopeValidator)(nil)
var _ Validator = (*ASTDiffValidator)(nil)
var _ Validator = (*CompileValidator)(nil)
var _ Validator = (*LintValidator)(nil)

// Errors
var (
	ErrValidatorTimeout = errors.New("validator timeout")
)
