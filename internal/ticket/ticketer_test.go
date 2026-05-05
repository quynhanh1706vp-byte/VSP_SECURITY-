package ticket

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Jira ──────────────────────────────────────────────────────────────────

func TestCreateJira_OK(t *testing.T) {
	var got jiraIssueCreate
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"10042","key":"SEC-42"}`))
	}))
	defer srv.Close()

	tk := New(Config{
		JiraBaseURL:  srv.URL,
		JiraEmail:    "bot@vsp.local",
		JiraAPIToken: "tok-xyz",
	})
	id, url, err := tk.Create(context.Background(), "jira", "SEC", "Critical alert", "Found CVE-2024-9999",
		map[string]interface{}{
			"priority": "P1",
			"labels":   []string{"vsp", "auto"},
		})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id != "SEC-42" {
		t.Errorf("want id=SEC-42, got %s", id)
	}
	if !strings.Contains(url, "/browse/SEC-42") {
		t.Errorf("want browse url, got %s", url)
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		t.Errorf("want Basic auth, got %s", authHeader)
	}
	if got.Fields.Project.Key != "SEC" {
		t.Errorf("want project=SEC, got %s", got.Fields.Project.Key)
	}
	if got.Fields.Summary != "Critical alert" {
		t.Errorf("wrong summary")
	}
	if got.Fields.Priority == nil || got.Fields.Priority.Name != "P1" {
		t.Errorf("priority not propagated")
	}
}

func TestCreateJira_MissingConfig(t *testing.T) {
	tk := New(Config{})
	_, _, err := tk.Create(context.Background(), "jira", "SEC", "x", "y", nil)
	if err == nil {
		t.Fatal("want error for missing config")
	}
	if !strings.Contains(err.Error(), "base_url, email, api_token") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestCreateJira_MissingProject(t *testing.T) {
	tk := New(Config{
		JiraBaseURL:  "https://x.atlassian.net",
		JiraEmail:    "a@b.c",
		JiraAPIToken: "t",
	})
	_, _, err := tk.Create(context.Background(), "jira", "", "x", "y", nil)
	if err == nil || !strings.Contains(err.Error(), "project key required") {
		t.Errorf("want missing project error, got: %v", err)
	}
}

func TestCreateJira_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorMessages":["Bad auth"]}`))
	}))
	defer srv.Close()

	tk := New(Config{
		JiraBaseURL:  srv.URL,
		JiraEmail:    "x", JiraAPIToken: "y",
	})
	_, _, err := tk.Create(context.Background(), "jira", "SEC", "s", "d", nil)
	if err == nil || !strings.Contains(err.Error(), "http 401") {
		t.Errorf("want 401 error, got: %v", err)
	}
}

// ── PagerDuty ─────────────────────────────────────────────────────────────

// We intercept the events.pagerduty.com URL by giving the ticketer a mock server
// and rewriting the URL in createPagerDuty isn't possible directly — instead we
// test via http.RoundTripper substitution.

type captureTransport struct {
	url      string
	gotBody  []byte
	respBody string
	respCode int
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.url = req.URL.String()
	if req.Body != nil {
		c.gotBody, _ = io.ReadAll(req.Body)
	}
	return &http.Response{
		StatusCode: c.respCode,
		Body:       io.NopCloser(strings.NewReader(c.respBody)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestCreatePagerDuty_OK(t *testing.T) {
	transport := &captureTransport{
		respCode: 202,
		respBody: `{"status":"success","message":"Event processed","dedup_key":"abc-123"}`,
	}
	tk := New(Config{PagerDutyRoutingKey: "RKEY"})
	tk.client.Transport = transport

	id, url, err := tk.Create(context.Background(), "pagerduty", "", "DB down", "primary failed",
		map[string]interface{}{"severity": "CRITICAL", "source": "db-01"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id != "abc-123" {
		t.Errorf("want id=abc-123, got %s", id)
	}
	if url != "" {
		t.Errorf("PD has no browser URL, got %s", url)
	}
	if !strings.Contains(transport.url, "events.pagerduty.com") {
		t.Errorf("wrong endpoint: %s", transport.url)
	}
	var sent pdEvent
	if err := json.Unmarshal(transport.gotBody, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.RoutingKey != "RKEY" {
		t.Errorf("routing key not set")
	}
	if sent.Payload.Severity != "critical" {
		t.Errorf("want severity=critical, got %s", sent.Payload.Severity)
	}
	if sent.Payload.Source != "db-01" {
		t.Errorf("source not propagated")
	}
}

func TestCreatePagerDuty_SeverityNormalization(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical",
		"HIGH":     "error",
		"MEDIUM":   "warning",
		"LOW":      "info",
		"P0":       "critical",
		"P2":       "warning",
	}
	for input, want := range cases {
		transport := &captureTransport{
			respCode: 202,
			respBody: `{"status":"success","dedup_key":"k"}`,
		}
		tk := New(Config{PagerDutyRoutingKey: "K"})
		tk.client.Transport = transport
		_, _, err := tk.Create(context.Background(), "pagerduty", "", "s", "d",
			map[string]interface{}{"severity": input})
		if err != nil {
			t.Fatalf("[%s] err: %v", input, err)
		}
		var sent pdEvent
		_ = json.Unmarshal(transport.gotBody, &sent)
		if sent.Payload.Severity != want {
			t.Errorf("[%s] want %s, got %s", input, want, sent.Payload.Severity)
		}
	}
}

func TestCreatePagerDuty_MissingKey(t *testing.T) {
	tk := New(Config{})
	_, _, err := tk.Create(context.Background(), "pagerduty", "", "x", "y", nil)
	if err == nil || !strings.Contains(err.Error(), "routing_key required") {
		t.Errorf("want missing key error, got: %v", err)
	}
}

// ── GitHub ────────────────────────────────────────────────────────────────

func TestCreateGitHub_OK(t *testing.T) {
	var got ghIssueCreate
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/api/issues" {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":99,"html_url":"https://github.com/acme/api/issues/99","node_id":"I_kw"}`))
	}))
	defer srv.Close()

	tk := New(Config{
		GitHubBaseURL: srv.URL,
		GitHubToken:   "ghp_xxx",
	})
	id, url, err := tk.Create(context.Background(), "github", "acme/api", "Bug found", "Stack trace...",
		map[string]interface{}{
			"labels":   []string{"bug", "p1"},
			"assignee": "alice",
		})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id != "acme/api#99" {
		t.Errorf("want id=acme/api#99, got %s", id)
	}
	if !strings.Contains(url, "/issues/99") {
		t.Errorf("wrong url: %s", url)
	}
	if authHeader != "Bearer ghp_xxx" {
		t.Errorf("wrong auth: %s", authHeader)
	}
	if got.Title != "Bug found" {
		t.Errorf("wrong title")
	}
	if len(got.Labels) != 2 || got.Labels[0] != "bug" {
		t.Errorf("labels not propagated: %v", got.Labels)
	}
	if got.Assignee != "alice" {
		t.Errorf("assignee not propagated")
	}
}

func TestCreateGitHub_MissingToken(t *testing.T) {
	tk := New(Config{})
	_, _, err := tk.Create(context.Background(), "github", "owner/repo", "x", "y", nil)
	if err == nil || !strings.Contains(err.Error(), "token required") {
		t.Errorf("want missing token, got: %v", err)
	}
}

func TestCreateGitHub_BadProject(t *testing.T) {
	tk := New(Config{GitHubToken: "t"})
	_, _, err := tk.Create(context.Background(), "github", "no-slash", "x", "y", nil)
	if err == nil || !strings.Contains(err.Error(), "owner/repo") {
		t.Errorf("want owner/repo error, got: %v", err)
	}
}

func TestCreateGitHub_FallbackRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/default/repo/issues") {
			t.Errorf("wrong fallback repo path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1,"html_url":"https://github.com/default/repo/issues/1"}`))
	}))
	defer srv.Close()

	tk := New(Config{
		GitHubBaseURL: srv.URL,
		GitHubToken:   "t",
		GitHubRepo:    "default/repo",
	})
	id, _, err := tk.Create(context.Background(), "github", "", "title", "body", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id != "default/repo#1" {
		t.Errorf("want fallback id, got %s", id)
	}
}

// ── Generic ───────────────────────────────────────────────────────────────

func TestCreate_UnsupportedSystem(t *testing.T) {
	tk := New(Config{})
	_, _, err := tk.Create(context.Background(), "carrier-pigeon", "", "x", "y", nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported system") {
		t.Errorf("want unsupported error, got: %v", err)
	}
}
