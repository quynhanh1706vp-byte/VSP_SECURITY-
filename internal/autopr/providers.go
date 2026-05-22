// =====================================================================
// H3.S Auto-PR — Platform Provider Clients
// File: internal/autopr/providers.go
//
// Multi-platform PR creation. Primary target: GitHub Enterprise.
// Also supports github.com, GitLab, Gitea (interface ready).
// =====================================================================

package autopr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PRRequest — input to provider for creating PR
type PRRequest struct {
	RepoOwner  string
	RepoName   string
	Title      string
	Body       string
	HeadBranch string // your branch name (e.g. vsp-autofix/foo-2026...)
	BaseBranch string // target branch (e.g. main)
	Labels     []string
	DraftPR    bool
}

// PRResponse — output from provider
type PRResponse struct {
	Number  int    `json:"number"`
	URL     string `json:"url"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	NodeID  string `json:"node_id,omitempty"`
}

// Provider — abstract platform interface
type Provider interface {
	Name() string
	CreatePR(ctx context.Context, req *PRRequest) (*PRResponse, error)
	GetPR(ctx context.Context, owner, repo string, number int) (*PRResponse, error)
}

// =====================================================================
// GitHub Enterprise (and github.com — same API, different base URL)
// =====================================================================

type GitHubEnterprise struct {
	APIBaseURL string // e.g. https://ghe.company.com/api/v3
	Token      string
	Client     *http.Client
}

func NewGitHubEnterprise(apiBaseURL, token string) *GitHubEnterprise {
	if apiBaseURL == "" {
		apiBaseURL = "https://api.github.com"
	}
	return &GitHubEnterprise{
		APIBaseURL: strings.TrimRight(apiBaseURL, "/"),
		Token:      token,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (g *GitHubEnterprise) Name() string {
	if strings.Contains(g.APIBaseURL, "api.github.com") {
		return "github"
	}
	return "github_enterprise"
}

// CreatePR — POST /repos/{owner}/{repo}/pulls
func (g *GitHubEnterprise) CreatePR(ctx context.Context, req *PRRequest) (*PRResponse, error) {
	body := map[string]any{
		"title": req.Title,
		"body":  req.Body,
		"head":  req.HeadBranch,
		"base":  req.BaseBranch,
		"draft": req.DraftPR,
	}
	buf, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/repos/%s/%s/pulls",
		g.APIBaseURL, req.RepoOwner, req.RepoName)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+g.Token)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "vsp-autofix-bot/1.0")

	resp, err := g.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("github API: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusCreated {
		var pr PRResponse
		if err := json.Unmarshal(respBody, &pr); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		return &pr, nil
	}

	// Parse error message
	var errResp struct {
		Message string `json:"message"`
		Errors  []struct {
			Resource string `json:"resource"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(respBody, &errResp)

	// Common case: PR already exists for this branch
	if resp.StatusCode == http.StatusUnprocessableEntity {
		for _, e := range errResp.Errors {
			if e.Code == "custom" && strings.Contains(e.Message, "already exists") {
				return nil, ErrPRAlreadyExists
			}
		}
	}

	return nil, fmt.Errorf("github API HTTP %d: %s",
		resp.StatusCode, errResp.Message)
}

// GetPR — fetch current state
func (g *GitHubEnterprise) GetPR(ctx context.Context, owner, repo string, number int) (*PRResponse, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d",
		g.APIBaseURL, owner, repo, number)
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	httpReq.Header.Set("Authorization", "Bearer "+g.Token)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get PR HTTP %d", resp.StatusCode)
	}
	var pr PRResponse
	if err := json.Unmarshal(respBody, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// =====================================================================
// Provider factory — picks impl based on platform string in repo_config
// =====================================================================

func ProviderFor(platform, apiURL, token string) (Provider, error) {
	switch strings.ToLower(platform) {
	case "github_enterprise", "github":
		return NewGitHubEnterprise(apiURL, token), nil
	case "gitlab":
		return NewGitLab(apiURL, token), nil
	case "gitea":
		return NewGitea(apiURL, token), nil
	}
	return nil, fmt.Errorf("unsupported platform: %s", platform)
}

// =====================================================================
// GitLab — POST /api/v4/projects/:id/merge_requests
// =====================================================================

type GitLab struct {
	APIBaseURL string
	Token      string
	Client     *http.Client
}

func NewGitLab(apiBaseURL, token string) *GitLab {
	if apiBaseURL == "" {
		apiBaseURL = "https://gitlab.com/api/v4"
	}
	return &GitLab{
		APIBaseURL: strings.TrimRight(apiBaseURL, "/"),
		Token:      token,
		Client:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitLab) Name() string { return "gitlab" }

func (g *GitLab) CreatePR(ctx context.Context, req *PRRequest) (*PRResponse, error) {
	// GitLab uses URL-encoded "owner/repo" as project ID
	projectID := req.RepoOwner + "/" + req.RepoName
	body := map[string]any{
		"source_branch": req.HeadBranch,
		"target_branch": req.BaseBranch,
		"title":         req.Title,
		"description":   req.Body,
	}
	buf, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/projects/%s/merge_requests",
		g.APIBaseURL, urlEscape(projectID))
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	httpReq.Header.Set("PRIVATE-TOKEN", g.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusCreated {
		var raw struct {
			IID    int    `json:"iid"`
			WebURL string `json:"web_url"`
			State  string `json:"state"`
		}
		if err := json.Unmarshal(respBody, &raw); err != nil {
			return nil, err
		}
		return &PRResponse{
			Number: raw.IID, HTMLURL: raw.WebURL, URL: raw.WebURL, State: raw.State,
		}, nil
	}
	return nil, fmt.Errorf("gitlab HTTP %d: %s", resp.StatusCode, string(respBody))
}

func (g *GitLab) GetPR(ctx context.Context, owner, repo string, number int) (*PRResponse, error) {
	projectID := owner + "/" + repo
	url := fmt.Sprintf("%s/projects/%s/merge_requests/%d",
		g.APIBaseURL, urlEscape(projectID), number)
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	httpReq.Header.Set("PRIVATE-TOKEN", g.Token)
	resp, err := g.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get MR HTTP %d", resp.StatusCode)
	}
	var raw struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, err
	}
	return &PRResponse{Number: raw.IID, HTMLURL: raw.WebURL, State: raw.State}, nil
}

// =====================================================================
// Gitea — same API shape as GitHub
// =====================================================================

type Gitea struct {
	APIBaseURL string
	Token      string
	Client     *http.Client
}

func NewGitea(apiBaseURL, token string) *Gitea {
	return &Gitea{
		APIBaseURL: strings.TrimRight(apiBaseURL, "/"),
		Token:      token,
		Client:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *Gitea) Name() string { return "gitea" }

func (g *Gitea) CreatePR(ctx context.Context, req *PRRequest) (*PRResponse, error) {
	body := map[string]any{
		"title": req.Title,
		"body":  req.Body,
		"head":  req.HeadBranch,
		"base":  req.BaseBranch,
	}
	buf, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/repos/%s/%s/pulls",
		g.APIBaseURL, req.RepoOwner, req.RepoName)
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	httpReq.Header.Set("Authorization", "token "+g.Token)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := g.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusCreated {
		var pr PRResponse
		if err := json.Unmarshal(respBody, &pr); err != nil {
			return nil, err
		}
		return &pr, nil
	}
	return nil, fmt.Errorf("gitea HTTP %d: %s", resp.StatusCode, string(respBody))
}

func (g *Gitea) GetPR(ctx context.Context, owner, repo string, number int) (*PRResponse, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d", g.APIBaseURL, owner, repo, number)
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	httpReq.Header.Set("Authorization", "token "+g.Token)
	resp, err := g.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get PR HTTP %d", resp.StatusCode)
	}
	var pr PRResponse
	if err := json.Unmarshal(respBody, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// =====================================================================
// Utilities
// =====================================================================

func urlEscape(s string) string {
	// Minimal escape for path segment (slash → %2F, space → %20)
	r := strings.NewReplacer("/", "%2F", " ", "%20")
	return r.Replace(s)
}

// Errors
var (
	ErrPRAlreadyExists = fmt.Errorf("pull request already exists for this branch")
	ErrUnauthorized    = fmt.Errorf("provider authentication failed")
)
