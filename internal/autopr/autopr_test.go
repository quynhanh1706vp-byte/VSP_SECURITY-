// =====================================================================
// H3.S Auto-PR — Tests
// File: internal/autopr/autopr_test.go
// Run: cd internal/autopr && go test -v -run TestH3S
// =====================================================================

package autopr

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ───────────────────────────────────────────────────────────────────
// Branch name + path safety
// ───────────────────────────────────────────────────────────────────

func TestH3S_SafeBranchName_Valid(t *testing.T) {
	cases := []string{"secrets/api-key", "kics.s3.public", "cwe-79", "abc"}
	for _, ruleID := range cases {
		b := SafeBranchName(ruleID)
		if !strings.HasPrefix(b, "vsp-autofix/") {
			t.Errorf("expected prefix, got %s", b)
		}
		if strings.Contains(b, " ") || strings.Contains(b, "..") {
			t.Errorf("unsafe branch: %s", b)
		}
	}
}

func TestH3S_SafeBranchName_Sanitizes(t *testing.T) {
	b := SafeBranchName("../../etc/passwd")
	if strings.Contains(b, "..") || strings.Contains(b, "/etc/") {
		t.Fatalf("traversal not sanitized: %s", b)
	}
}

func TestH3S_SafePath_RejectsTraversal(t *testing.T) {
	bad := []string{"../etc/passwd", "/abs/path", "a/../../b", "\x00null"}
	for _, p := range bad {
		if safeRelPath(p) {
			t.Errorf("should reject: %s", p)
		}
	}
}

func TestH3S_SafePath_AcceptsValid(t *testing.T) {
	good := []string{"src/main.go", "config/db.yml", "a.txt"}
	for _, p := range good {
		if !safeRelPath(p) {
			t.Errorf("should accept: %s", p)
		}
	}
}

// ───────────────────────────────────────────────────────────────────
// URL validation + auth injection
// ───────────────────────────────────────────────────────────────────

func TestH3S_ValidateRepoURL(t *testing.T) {
	good := []string{
		"https://github.com/owner/repo.git",
		"https://ghe.company.com/owner/repo.git",
		"https://gitea.local:3000/u/r.git",
	}
	for _, u := range good {
		if !validateRepoURL(u) {
			t.Errorf("should accept: %s", u)
		}
	}
	bad := []string{
		"javascript:alert(1)",
		"file:///etc/passwd",
		"ssh://git@host/r.git",
		"https://host/path", // missing .git
	}
	for _, u := range bad {
		if validateRepoURL(u) {
			t.Errorf("should reject: %s", u)
		}
	}
}

func TestH3S_InjectAuth(t *testing.T) {
	authed, err := injectAuth("https://ghe.company.com/owner/repo.git", "bot", "ghp_xxx")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authed, "bot:ghp_xxx@") {
		t.Fatalf("expected user:token in URL, got %s", authed)
	}
}

func TestH3S_RedactToken(t *testing.T) {
	out := redactToken("git push: token=ghp_secret_123 failed", "ghp_secret_123")
	if strings.Contains(out, "ghp_secret_123") {
		t.Fatal("token not redacted")
	}
	if !strings.Contains(out, "REDACTED") {
		t.Fatal("expected REDACTED marker")
	}
}

// ───────────────────────────────────────────────────────────────────
// PG array parsing
// ───────────────────────────────────────────────────────────────────

func TestH3S_ParsePgArray(t *testing.T) {
	cases := map[string][]string{
		"{critical,high}":     {"critical", "high"},
		`{"critical","high"}`: {"critical", "high"},
		"{}":                  {},
		"{single}":            {"single"},
	}
	for input, want := range cases {
		got := parsePgArray(input)
		if len(got) != len(want) {
			t.Errorf("input=%q got=%v want=%v", input, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("input=%q [%d] got=%q want=%q", input, i, got[i], want[i])
			}
		}
	}
}

// ───────────────────────────────────────────────────────────────────
// Provider — GitHub Enterprise mock
// ───────────────────────────────────────────────────────────────────

func TestH3S_GitHubEnterprise_CreatePR_Success(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/pulls") {
			http.Error(w, "wrong route", 404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":42,"html_url":"https://ghe/owner/repo/pull/42","state":"open"}`))
	}))
	defer mock.Close()

	gh := NewGitHubEnterprise(mock.URL, "test-token")
	pr, err := gh.CreatePR(context.Background(), &PRRequest{
		RepoOwner: "owner", RepoName: "repo",
		Title: "test", Body: "body",
		HeadBranch: "feature", BaseBranch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 42 {
		t.Errorf("expected #42, got %d", pr.Number)
	}
}

func TestH3S_GitHubEnterprise_CreatePR_AlreadyExists(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"A pull request already exists for foo:bar"}]}`))
	}))
	defer mock.Close()

	gh := NewGitHubEnterprise(mock.URL, "tok")
	_, err := gh.CreatePR(context.Background(), &PRRequest{
		RepoOwner: "o", RepoName: "r", Title: "t", HeadBranch: "h", BaseBranch: "main",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != ErrPRAlreadyExists.Error() {
		t.Errorf("expected ErrPRAlreadyExists, got %v", err)
	}
}

func TestH3S_ProviderFor(t *testing.T) {
	cases := []struct {
		platform string
		apiURL   string
		wantName string
	}{
		{"github", "https://api.github.com", "github"},
		{"github_enterprise", "https://ghe.company.com/api/v3", "github_enterprise"},
		{"gitlab", "https://gitlab.com/api/v4", "gitlab"},
		{"gitea", "https://gitea.local/api/v1", "gitea"},
	}
	for _, tc := range cases {
		p, err := ProviderFor(tc.platform, tc.apiURL, "tok")
		if err != nil {
			t.Errorf("platform=%s: %v", tc.platform, err)
			continue
		}
		if p.Name() != tc.wantName {
			t.Errorf("platform=%s url=%s: name=%s want=%s",
				tc.platform, tc.apiURL, p.Name(), tc.wantName)
		}
	}
	if _, err := ProviderFor("svn", "x", "y"); err == nil {
		t.Error("svn should be unsupported")
	}
}

// ───────────────────────────────────────────────────────────────────
// Token encryption (AES-256-GCM)
// ───────────────────────────────────────────────────────────────────

func TestH3S_TokenEncryption_Roundtrip(t *testing.T) {
	svc := &PRService{EncKeyEnv: "test-key-32-bytes-long-enough!!"}
	plain := "ghp_test_token_value"
	encrypted, err := svc.EncryptToken(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(encrypted) == plain {
		t.Fatal("ciphertext = plaintext")
	}
	decrypted, err := svc.decryptToken(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plain {
		t.Errorf("roundtrip: got %q want %q", decrypted, plain)
	}
}

func TestH3S_TokenEncryption_DifferentNonces(t *testing.T) {
	svc := &PRService{EncKeyEnv: "key-32-bytes-aaaaaaaaaaaaaaaa!!!"}
	a, _ := svc.EncryptToken("same")
	b, _ := svc.EncryptToken("same")
	if string(a) == string(b) {
		t.Fatal("two encryptions of same plaintext should differ (random nonce)")
	}
}

// ───────────────────────────────────────────────────────────────────
// Webhook signature verification
// ───────────────────────────────────────────────────────────────────

func TestH3S_VerifyGitHubSignature_Valid(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	secret := "webhook-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	validSig := hex.EncodeToString(mac.Sum(nil))
	if !verifyGitHubSignature(secret, body, "sha256="+validSig) {
		t.Fatal("valid signature rejected")
	}
}

func TestH3S_VerifyGitHubSignature_Invalid(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	if verifyGitHubSignature("secret", body, "sha256=deadbeef") {
		t.Fatal("invalid signature accepted")
	}
	if verifyGitHubSignature("secret", body, "wrong-format") {
		t.Fatal("malformed header accepted")
	}
}

func TestH3S_VerifyGitHubSignature_NoSecret(t *testing.T) {
	if !verifyGitHubSignature("", []byte("anything"), "anything") {
		t.Fatal("empty secret should accept (legacy compat)")
	}
}

// ───────────────────────────────────────────────────────────────────
// JSON helpers (smoke)
// ───────────────────────────────────────────────────────────────────

func TestH3S_BuildPRBody_NoNullBytes(t *testing.T) {
	c := &cacheRow{
		CacheKey: "abc123def456ghi789jkl012mno345pq",
		RuleID:   "test-rule",
		FilePath: "x.go",
		Severity: "high",
	}
	body := buildPRBody(c, &CreatePRInput{TriggerType: "manual"})
	if strings.Contains(body, "\x00") {
		t.Fatal("null byte in PR body")
	}
	if !strings.Contains(body, "test-rule") {
		t.Fatal("rule_id missing")
	}
	// Sanity: must be valid JSON-encodable
	if _, err := json.Marshal(body); err != nil {
		t.Fatal(err)
	}
}
