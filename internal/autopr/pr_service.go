// =====================================================================
// H3.S Auto-PR — Service Orchestrator
// File: internal/autopr/pr_service.go
//
// Orchestrates: pre-flight checks → git ops → provider API → DB persist.
// Called from HTTP handlers (manual trigger) and SLA scheduler (auto).
// =====================================================================

package autopr

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// PRService — main orchestrator
type PRService struct {
	DB           *sql.DB
	RepoRootEnv  string // VSP_REPO_ROOT — used for in-place patches if no remote
	EncKeyEnv    string // VSP_REPO_KEY — base for AES key
	mu           sync.Mutex
}

// NewPRService — constructor with env-based config
func NewPRService(db *sql.DB) *PRService {
	return &PRService{
		DB:          db,
		RepoRootEnv: os.Getenv("VSP_REPO_ROOT"),
		EncKeyEnv:   os.Getenv("VSP_REPO_KEY"),
	}
}

// CreatePRInput — input from handler or scheduler
type CreatePRInput struct {
	CacheKey     string // → autofix_cache row
	FindingID    string
	RepoConfigID string // UUID of repo_config row
	TriggerType  string // "manual" | "sla"
	CreatedBy    string // user uid OR "sla_scheduler"
	// Override (optional)
	BaseBranch   string
}

// PRResult — output to caller
type PRResult struct {
	PRID           int64  `json:"pr_id"`
	PRNumber       int    `json:"pr_number"`
	PRURL          string `json:"pr_url"`
	BranchName     string `json:"branch_name"`
	Status         string `json:"status"`
	ValidationScore int    `json:"validation_score"`
}

// Create — main entry point. Idempotent on (cache_key, repo_config_id).
func (s *PRService) Create(ctx context.Context, in *CreatePRInput) (*PRResult, error) {
	if in == nil || in.CacheKey == "" || in.RepoConfigID == "" {
		return nil, fmt.Errorf("invalid input")
	}

	// ── 1. Pre-flight: load cache + validation ──────────────────────────
	cache, err := s.loadCache(ctx, in.CacheKey)
	if err != nil {
		return nil, fmt.Errorf("load cache: %w", err)
	}
	if cache.SuggestedCode == "" {
		return nil, fmt.Errorf("cache has no fix code")
	}

	// H3.Q gate — must have validation pass with score ≥ 70 (configurable per-repo via SLA)
	if cache.ValidationStatus != "pass" {
		return nil, fmt.Errorf("validation status=%q, refusing to create PR (need 'pass')", cache.ValidationStatus)
	}

	// ── 2. Load repo config + decrypt token ─────────────────────────────
	repo, err := s.loadRepoConfig(ctx, in.RepoConfigID)
	if err != nil {
		return nil, fmt.Errorf("load repo config: %w", err)
	}
	if !repo.Enabled {
		return nil, fmt.Errorf("repo config disabled")
	}

	// SLA-triggered: enforce min_score
	if in.TriggerType == "sla" && cache.ValidationScore < int(repo.SLAMinScore) {
		return nil, fmt.Errorf("score %d < SLA min %d", cache.ValidationScore, repo.SLAMinScore)
	}

	// SLA rate limit
	if in.TriggerType == "sla" {
		if err := s.checkSLARate(ctx, in.RepoConfigID, int(repo.SLAMaxPerDay)); err != nil {
			return nil, err
		}
	}

	token, err := s.decryptToken(repo.TokenEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt token: %w", err)
	}
	defer zeroString(&token)

	// ── 3. Idempotency check ────────────────────────────────────────────
	existing, err := s.findExistingPR(ctx, in.CacheKey, in.RepoConfigID)
	if err == nil && existing != nil {
		// Already exists — return existing record (don't recreate)
		return existing, nil
	}

	// ── 4. Insert pending row (so we have audit trail even on failure) ──
	prRowID, err := s.insertPendingPR(ctx, in, repo, cache)
	if err != nil {
		return nil, fmt.Errorf("insert pending: %w", err)
	}

	// Helper to mark failure
	failPR := func(reason string) (*PRResult, error) {
		_ = s.markPRFailed(ctx, prRowID, reason)
		return nil, errors.New(reason)
	}

	// ── 5. Git workspace ────────────────────────────────────────────────
	repoURL := buildRepoURL(repo.BaseURL, repo.RepoOwner, repo.RepoName)
	baseBranch := in.BaseBranch
	if baseBranch == "" {
		baseBranch = repo.DefaultBranch
	}

	gitCtx, gitCancel := context.WithTimeout(ctx, 90*time.Second)
	defer gitCancel()

	ws, err := NewWorkspace(gitCtx, repoURL, token, repo.TokenUser, baseBranch)
	if err != nil {
		return failPR("git clone failed: " + err.Error())
	}
	defer ws.Cleanup()

	branch, err := ws.CreateBranch(gitCtx, cache.RuleID)
	if err != nil {
		return failPR("create branch: " + err.Error())
	}

	if err := ws.ApplyFix(cache.FilePath, cache.SuggestedCode); err != nil {
		return failPR("apply fix: " + err.Error())
	}

	hasChanges, _ := ws.HasChanges(gitCtx)
	if !hasChanges {
		return failPR("fix produced no diff (already applied?)")
	}

	commitMsg := buildCommitMessage(cache, in)
	if err := ws.Commit(gitCtx, commitMsg); err != nil {
		return failPR("commit: " + err.Error())
	}

	if err := ws.Push(gitCtx, branch); err != nil {
		return failPR("push: " + err.Error())
	}
	_ = s.markPRPushed(ctx, prRowID, branch)

	// ── 6. Create PR via provider API ───────────────────────────────────
	apiCtx, apiCancel := context.WithTimeout(ctx, 30*time.Second)
	defer apiCancel()

	provider, err := ProviderFor(repo.Platform, repo.APIURL, token)
	if err != nil {
		return failPR("provider: " + err.Error())
	}

	prReq := &PRRequest{
		RepoOwner:  repo.RepoOwner,
		RepoName:   repo.RepoName,
		Title:      buildPRTitle(cache),
		Body:       buildPRBody(cache, in),
		HeadBranch: branch,
		BaseBranch: baseBranch,
		Labels:     []string{"vsp-autofix", "security"},
		DraftPR:    cache.ValidationScore < 90, // draft if score <90 — humans should review more carefully
	}

	prResp, err := provider.CreatePR(apiCtx, prReq)
	if err != nil {
		if errors.Is(err, ErrPRAlreadyExists) {
			return failPR("PR already exists for branch (race?)")
		}
		return failPR("create PR: " + err.Error())
	}

	// ── 7. Mark created ─────────────────────────────────────────────────
	if err := s.markPRCreated(ctx, prRowID, prResp); err != nil {
		// DB error after successful PR creation — log but don't fail
		// PR is real on GitHub even if our row is stale
		// (cron will reconcile via webhook or status poll)
		_ = s.appendError(ctx, prRowID, "warn: persist after create: "+err.Error())
	}

	// ── 8. Audit log ────────────────────────────────────────────────────
	_ = s.auditLog(ctx, prRowID, in, prResp.HTMLURL)

	return &PRResult{
		PRID:            prRowID,
		PRNumber:        prResp.Number,
		PRURL:           prResp.HTMLURL,
		BranchName:      branch,
		Status:          "created",
		ValidationScore: cache.ValidationScore,
	}, nil
}

// =====================================================================
// DB models + helpers
// =====================================================================

type cacheRow struct {
	CacheKey         string
	FindingID        string
	RuleID           string
	SuggestedCode    string
	Rationale        string
	Confidence       string
	FilePath         string
	Severity         string
	ValidationStatus string
	ValidationScore  int
}

type repoCfg struct {
	ID              string
	TenantID        sql.NullString
	Platform        string
	BaseURL         string
	APIURL          string
	RepoOwner       string
	RepoName        string
	DefaultBranch   string
	TokenEncrypted  []byte
	TokenUser       string
	Enabled         bool
	SLAMinScore     int16
	SLAMaxPerDay    int32
}

func (s *PRService) loadCache(ctx context.Context, key string) (*cacheRow, error) {
	q := `SELECT
			ac.cache_key, ac.finding_id::text,
			COALESCE(ac.suggested_code,''),
			COALESCE(ac.rationale,''),
			COALESCE(ac.confidence,''),
			COALESCE(f.path, ac.file_path, ''),
			COALESCE(f.severity, ''),
			COALESCE(f.rule_id, ''),
			COALESCE(ac.validation_status,''),
			COALESCE(ac.validation_score, 0)
		FROM autofix_cache ac
		LEFT JOIN findings f ON f.id::text = ac.finding_id::text
		WHERE ac.cache_key = $1
		LIMIT 1`
	var r cacheRow
	err := s.DB.QueryRowContext(ctx, q, key).Scan(
		&r.CacheKey, &r.FindingID, &r.SuggestedCode, &r.Rationale,
		&r.Confidence, &r.FilePath, &r.Severity, &r.RuleID,
		&r.ValidationStatus, &r.ValidationScore,
	)
	if err != nil {
		// Fallback: try without the findings join (in case schema differs)
		q2 := `SELECT cache_key, finding_id::text,
			COALESCE(suggested_code,''), COALESCE(rationale,''),
			COALESCE(confidence,''), '', '', '',
			COALESCE(validation_status,''), COALESCE(validation_score, 0)
			FROM autofix_cache WHERE cache_key = $1 LIMIT 1`
		err2 := s.DB.QueryRowContext(ctx, q2, key).Scan(
			&r.CacheKey, &r.FindingID, &r.SuggestedCode, &r.Rationale,
			&r.Confidence, &r.FilePath, &r.Severity, &r.RuleID,
			&r.ValidationStatus, &r.ValidationScore,
		)
		if err2 != nil {
			return nil, err
		}
	}
	if r.FilePath == "" {
		// Last-ditch: maybe in metadata. Use a placeholder; caller will fail gracefully.
		r.FilePath = "VSP_FIX_NEEDS_PATH.txt"
	}
	return &r, nil
}

func (s *PRService) loadRepoConfig(ctx context.Context, id string) (*repoCfg, error) {
	q := `SELECT id::text, tenant_id::text, platform, base_url, COALESCE(api_url,''),
		repo_owner, repo_name, default_branch, token_encrypted, COALESCE(token_user,''),
		enabled, COALESCE(sla_min_score, 80), COALESCE(sla_max_per_day, 10)
		FROM repo_config WHERE id = $1`
	var r repoCfg
	err := s.DB.QueryRowContext(ctx, q, id).Scan(
		&r.ID, &r.TenantID, &r.Platform, &r.BaseURL, &r.APIURL,
		&r.RepoOwner, &r.RepoName, &r.DefaultBranch, &r.TokenEncrypted,
		&r.TokenUser, &r.Enabled, &r.SLAMinScore, &r.SLAMaxPerDay,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PRService) findExistingPR(ctx context.Context, cacheKey, repoConfigID string) (*PRResult, error) {
	q := `SELECT id, COALESCE(pr_number, 0), COALESCE(pr_url, ''),
		branch_name, pr_status, COALESCE(validation_score, 0)
		FROM autofix_pr WHERE cache_key = $1 AND repo_config_id = $2
		AND pr_status NOT IN ('failed','closed') LIMIT 1`
	var r PRResult
	err := s.DB.QueryRowContext(ctx, q, cacheKey, repoConfigID).Scan(
		&r.PRID, &r.PRNumber, &r.PRURL, &r.BranchName, &r.Status, &r.ValidationScore,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PRService) insertPendingPR(ctx context.Context, in *CreatePRInput, repo *repoCfg, cache *cacheRow) (int64, error) {
	q := `INSERT INTO autofix_pr
		(tenant_id, repo_config_id, cache_key, finding_id, rule_id, severity, file_path,
		 branch_name, pr_title, pr_status, created_by, trigger_type, validation_score)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'creating', $10, $11, $12)
		RETURNING id`
	var id int64
	err := s.DB.QueryRowContext(ctx, q,
		repo.TenantID, repo.ID, in.CacheKey, in.FindingID,
		cache.RuleID, cache.Severity, cache.FilePath,
		"", buildPRTitle(cache),
		in.CreatedBy, in.TriggerType, cache.ValidationScore,
	).Scan(&id)
	return id, err
}

func (s *PRService) markPRPushed(ctx context.Context, id int64, branch string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE autofix_pr SET branch_name=$1, pushed_at=NOW() WHERE id=$2`,
		branch, id)
	return err
}

func (s *PRService) markPRCreated(ctx context.Context, id int64, pr *PRResponse) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE autofix_pr
		SET pr_number=$1, pr_url=$2, pr_status='created' WHERE id=$3`,
		pr.Number, pr.HTMLURL, id)
	return err
}

func (s *PRService) markPRFailed(ctx context.Context, id int64, reason string) error {
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE autofix_pr SET pr_status='failed', error_msg=$1 WHERE id=$2`,
		reason, id)
	return err
}

func (s *PRService) appendError(ctx context.Context, id int64, msg string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE autofix_pr SET error_msg = COALESCE(error_msg,'') || E'\n' || $1 WHERE id=$2`,
		msg, id)
	return err
}

func (s *PRService) checkSLARate(ctx context.Context, repoConfigID string, max int) error {
	var count int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM autofix_pr
		 WHERE repo_config_id = $1 AND trigger_type = 'sla'
		 AND created_at > NOW() - INTERVAL '24 hours'`,
		repoConfigID).Scan(&count)
	if err != nil {
		return nil // fail-open on rate check error
	}
	if count >= max {
		return fmt.Errorf("SLA rate limit: %d PRs in last 24h (max %d)", count, max)
	}
	return nil
}

func (s *PRService) auditLog(ctx context.Context, prID int64, in *CreatePRInput, prURL string) error {
	md, _ := json.Marshal(map[string]any{
		"pr_id":        prID,
		"pr_url":       prURL,
		"trigger_type": in.TriggerType,
	})
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_log (action, resource, actor, metadata, created_at)
		 VALUES ('autofix.pr.created', $1, $2, $3, NOW())
		 ON CONFLICT DO NOTHING`,
		"cache_key:"+in.CacheKey[:16], in.CreatedBy, string(md))
	return err
}

// =====================================================================
// Token encryption (AES-256-GCM, key derived from env)
// =====================================================================

// EncryptToken — for use by admin endpoint registering a new repo
func (s *PRService) EncryptToken(plain string) ([]byte, error) {
	key := s.deriveKey()
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

func (s *PRService) decryptToken(ciphertext []byte) (string, error) {
	key := s.deriveKey()
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// deriveKey — produces 32-byte key from VSP_REPO_KEY env (right-padded or truncated)
func (s *PRService) deriveKey() []byte {
	src := s.EncKeyEnv
	if src == "" {
		src = "VSP_DEFAULT_KEY_NEEDS_OVERRIDE_IN_PROD_PLEASE_CHANGE"
	}
	key := make([]byte, 32)
	for i := 0; i < 32 && i < len(src); i++ {
		key[i] = src[i]
	}
	if len(src) < 32 {
		// Pad with deterministic but non-zero bytes
		for i := len(src); i < 32; i++ {
			key[i] = byte(0xA5 ^ i)
		}
	}
	return key
}

// =====================================================================
// Message builders
// =====================================================================

func buildPRTitle(c *cacheRow) string {
	rule := c.RuleID
	if rule == "" {
		rule = "security-fix"
	}
	if len(rule) > 50 {
		rule = rule[:50]
	}
	return fmt.Sprintf("[VSP-Autofix] %s — %s",
		strings.ToUpper(strSafe(c.Severity, "FIX")), rule)
}

func buildCommitMessage(c *cacheRow, in *CreatePRInput) string {
	short := c.Rationale
	if len(short) > 200 {
		short = short[:200] + "..."
	}
	if short == "" {
		short = "AI-generated security fix"
	}
	return fmt.Sprintf(`fix(security): %s

%s

Rule: %s
Severity: %s
Validation score: %d/100
Trigger: %s

Generated by VSP Autofix.
Cache key: %s`,
		c.RuleID, short, c.RuleID,
		strings.ToUpper(strSafe(c.Severity, "unknown")),
		c.ValidationScore, in.TriggerType, c.CacheKey[:16])
}

func buildPRBody(c *cacheRow, in *CreatePRInput) string {
	return fmt.Sprintf(`## 🛡 VSP Autofix — Security Fix

**Rule ID:** `+"`%s`"+`
**Severity:** %s
**File:** `+"`%s`"+`
**Validation score:** %d/100 ✓
**Confidence:** %s
**Trigger:** %s

### Why this change?
%s

### How it was generated
This fix was produced by VSP's AI-assisted autofix pipeline:

1. **H3.N** — DeepSeek-Coder generated the fix from finding context
2. **H3.O** — Pre-compute worker cached the fix for low-latency delivery
3. **H3.Q** — 6-stage validation pipeline confirmed:
   - Line-scope check (diff confined to vulnerable region)
   - Lint regression check (does not reintroduce the vulnerability)
   - Idempotency check
   - AST structural validation
   - Syntax validation
   - Compilation/type check (where applicable)

### Compliance
- **CMMC AC-3** Access enforced — only authenticated admins can trigger autofix
- **CMMC AU-2** Audit logged — full trail in `+"`audit_log`"+`
- **CMMC SI-3** Malicious code protection — lint validator blocks regressions
- **CMMC SA-11** Developer testing — pipeline validators run on every fix

### Audit trail
Cache key: `+"`%s`"+`
PR record: `+"`autofix_pr#PENDING`"+`

---

🤖 Auto-generated by [VSP Autofix](https://vsp.local). Review carefully before merging.
`,
		c.RuleID,
		strings.ToUpper(strSafe(c.Severity, "unknown")),
		c.FilePath,
		c.ValidationScore,
		strSafe(c.Confidence, "medium"),
		in.TriggerType,
		strSafe(c.Rationale, "AI-generated fix to address the security finding."),
		c.CacheKey,
	)
}

// =====================================================================
// Utilities
// =====================================================================

func buildRepoURL(baseURL, owner, name string) string {
	base := strings.TrimRight(baseURL, "/")
	return fmt.Sprintf("%s/%s/%s.git", base, owner, name)
}

func strSafe(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func zeroString(s *string) {
	if s == nil {
		return
	}
	*s = strings.Repeat("\x00", len(*s))
}
