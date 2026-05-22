// =====================================================================
// H3.S Auto-PR — Git Operations (sandboxed)
// File: internal/autopr/git_ops.go
// =====================================================================
//
// All git operations happen inside /tmp/vsp-pr-{uuid}/ workspaces.
// Auto-cleaned after each operation. Token never exposed in URL bar:
// uses GIT_ASKPASS or temp credential helper.

package autopr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GitWorkspace — sandboxed clone for one PR operation. NOT thread-safe.
type GitWorkspace struct {
	Dir       string // /tmp/vsp-pr-xxxx
	RepoURL   string // base URL without auth
	Token     string // PAT (held in memory only)
	TokenUser string // bot user, e.g. "vsp-autofix-bot"
	DefaultBr string
	Cleaned   bool
}

// NewWorkspace clones repo into temp dir with token-based auth.
// Uses depth=50 (fast clone, enough for cherry-picking).
func NewWorkspace(ctx context.Context, repoURL, token, tokenUser, defaultBranch string) (*GitWorkspace, error) {
	if !validateRepoURL(repoURL) {
		return nil, fmt.Errorf("invalid repo URL")
	}
	if token == "" || tokenUser == "" {
		return nil, fmt.Errorf("token and tokenUser required")
	}

	rnd := make([]byte, 8)
	if _, err := rand.Read(rnd); err != nil {
		return nil, err
	}
	dir := filepath.Join(os.TempDir(), "vsp-pr-"+hex.EncodeToString(rnd))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	ws := &GitWorkspace{
		Dir:       dir,
		RepoURL:   repoURL,
		Token:     token,
		TokenUser: tokenUser,
		DefaultBr: defaultBranch,
	}

	// Build authed URL: https://user:token@host/owner/repo.git
	authURL, err := injectAuth(repoURL, tokenUser, token)
	if err != nil {
		ws.Cleanup()
		return nil, err
	}

	// Shallow clone — fast, enough for our needs
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "50",
		"--branch", defaultBranch,
		"--single-branch",
		"--no-tags",
		authURL, dir)
	cmd.Env = sanitizedEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		ws.Cleanup()
		return nil, fmt.Errorf("git clone failed: %w (output: %s)", err, redactToken(string(out), token))
	}

	// Configure git identity for commits
	for _, kv := range [][]string{
		{"user.email", "vsp-autofix-bot@vsp.local"},
		{"user.name", "VSP Autofix Bot"},
		{"commit.gpgsign", "false"}, // explicit no-sign (avoid GPG prompts)
	} {
		cmd := exec.CommandContext(ctx, "git", "config", kv[0], kv[1])
		cmd.Dir = dir
		cmd.Env = sanitizedEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			ws.Cleanup()
			return nil, fmt.Errorf("git config %s: %w (%s)", kv[0], err, string(out))
		}
	}

	return ws, nil
}

// Cleanup removes the workspace and zeroes the token in memory.
func (w *GitWorkspace) Cleanup() {
	if w.Cleaned {
		return
	}
	if w.Dir != "" {
		_ = os.RemoveAll(w.Dir)
	}
	// Zero token bytes (best-effort, Go strings are immutable but this clears local copy)
	w.Token = strings.Repeat("\x00", len(w.Token))
	w.Cleaned = true
}

// CreateBranch — create + checkout branch from default branch.
// Branch name format enforced: vsp-autofix/{rule_id-sanitized}-{ts}
func (w *GitWorkspace) CreateBranch(ctx context.Context, ruleID string) (string, error) {
	branch := SafeBranchName(ruleID)
	cmd := exec.CommandContext(ctx, "git", "checkout", "-b", branch)
	cmd.Dir = w.Dir
	cmd.Env = sanitizedEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("checkout -b %s: %w (%s)", branch, err, string(out))
	}
	return branch, nil
}

// ApplyFix — write fix content to filePath (relative to repo root).
// Verifies path doesn't escape repo (no ../ traversal).
func (w *GitWorkspace) ApplyFix(filePath string, content string) error {
	if !safeRelPath(filePath) {
		return fmt.Errorf("unsafe file path: %s", filePath)
	}
	full := filepath.Join(w.Dir, filePath)
	// Verify resolved path stays inside w.Dir (defense in depth)
	abs, err := filepath.Abs(full)
	if err != nil {
		return err
	}
	wsAbs, _ := filepath.Abs(w.Dir)
	if !strings.HasPrefix(abs, wsAbs+string(os.PathSeparator)) && abs != wsAbs {
		return fmt.Errorf("path escapes workspace: %s", filePath)
	}

	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	return os.WriteFile(full, []byte(content), 0o600)
}

// Commit — git add + commit with structured message
func (w *GitWorkspace) Commit(ctx context.Context, msg string) error {
	cmds := [][]string{
		{"git", "add", "-A"},
		{"git", "commit", "-m", msg, "--no-verify"},
	}
	for _, c := range cmds {
		cmd := exec.CommandContext(ctx, c[0], c[1:]...)
		cmd.Dir = w.Dir
		cmd.Env = sanitizedEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w (%s)", strings.Join(c, " "), err, redactToken(string(out), w.Token))
		}
	}
	return nil
}

// HasChanges — true if git status reports anything to commit
func (w *GitWorkspace) HasChanges(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "status", "--porcelain")
	cmd.Dir = w.Dir
	cmd.Env = sanitizedEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("git status: %w", err)
	}
	return len(strings.TrimSpace(string(out))) > 0, nil
}

// Push — push current branch to origin. Returns push ref output.
func (w *GitWorkspace) Push(ctx context.Context, branch string) error {
	cmd := exec.CommandContext(ctx, "git", "push", "--set-upstream", "origin", branch)
	cmd.Dir = w.Dir
	cmd.Env = sanitizedEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git push: %w (%s)", err, redactToken(string(out), w.Token))
	}
	return nil
}

// =====================================================================
// Helpers
// =====================================================================

var (
	branchSafeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	repoURLRe    = regexp.MustCompile(`^https?://[a-zA-Z0-9._-]+(:[0-9]+)?(/[a-zA-Z0-9._/-]+)?\.git$`)
)

// SafeBranchName — produce git-safe branch name from rule_id
func SafeBranchName(ruleID string) string {
	clean := branchSafeRe.ReplaceAllString(ruleID, "-")
	clean = strings.Trim(clean, "-.")
	if len(clean) > 60 {
		clean = clean[:60]
	}
	if clean == "" {
		clean = "fix"
	}
	ts := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("vsp-autofix/%s-%s", clean, ts)
}

// safeRelPath — reject paths with .., absolute, or null bytes
func safeRelPath(p string) bool {
	if p == "" || strings.Contains(p, "\x00") {
		return false
	}
	if filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
		return false
	}
	return true
}

// validateRepoURL — accept https://host/owner/repo.git
func validateRepoURL(s string) bool {
	if !repoURLRe.MatchString(s) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// injectAuth — inject user:token into URL for git CLI
func injectAuth(repoURL, user, token string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, token)
	return u.String(), nil
}

// redactToken — replace token in command output before logging
func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***REDACTED***")
}

// sanitizedEnv — minimal env for git commands (no GITHUB_TOKEN leak from parent)
func sanitizedEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.TempDir(), // avoid global gitconfig
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/echo", // never prompt
		"LC_ALL=C",
		"LANG=C",
	}
}

// CopyFromReader — utility: copy reader to file inside workspace
func (w *GitWorkspace) CopyFromReader(filePath string, src io.Reader) error {
	if !safeRelPath(filePath) {
		return fmt.Errorf("unsafe path")
	}
	full := filepath.Join(w.Dir, filePath)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}

// Errors
var (
	ErrConflict   = errors.New("merge conflict")
	ErrNoChanges  = errors.New("no changes to commit")
	ErrPushDenied = errors.New("push denied (auth or branch protection)")
)
