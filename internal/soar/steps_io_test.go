package soar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// stubHTTPDoer
type stubHTTPDoer struct {
	resp   *HTTPResp
	err    error
	called bool
	gotURL string
}

func (s *stubHTTPDoer) Do(req *HTTPReq) (*HTTPResp, error) {
	s.called = true
	s.gotURL = req.URL
	return s.resp, s.err
}

func TestHTTPExecutor_Success(t *testing.T) {
	stub := &stubHTTPDoer{
		resp: &HTTPResp{StatusCode: 200, Body: []byte(`{"ok":true}`)},
	}
	exec := NewHTTPExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepHTTP,
		Config: json.RawMessage(`{"url":"https://example.com/api","method":"GET"}`),
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	if !stub.called {
		t.Fatal("HTTP not called")
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["status_code"].(float64) != 200 {
		t.Errorf("status_code = %v", data["status_code"])
	}
}

func TestHTTPExecutor_TestMode(t *testing.T) {
	exec := NewHTTPExecutor(nil)
	n := &Node{
		ID: "n1", Type: StepHTTP,
		Config: json.RawMessage(`{"url":"https://x.com"}`),
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{IsTest: true})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["_test_mode"] != true {
		t.Errorf("expected test mode flag")
	}
}

func TestHTTPExecutor_TemplateExpansion(t *testing.T) {
	stub := &stubHTTPDoer{resp: &HTTPResp{StatusCode: 200}}
	exec := NewHTTPExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepHTTP,
		Config: json.RawMessage(`{"url":"https://api.example.com/${ctx.path}"}`),
	}
	ec := &ExecCtx{Vars: map[string]interface{}{"path": "users"}}
	_, _, err := exec.Run(context.Background(), n, ec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(stub.gotURL, "/users") {
		t.Errorf("URL not templated: %s", stub.gotURL)
	}
}

func TestHTTPExecutor_4xxError(t *testing.T) {
	stub := &stubHTTPDoer{resp: &HTTPResp{StatusCode: 404, Body: []byte("not found")}}
	exec := NewHTTPExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepHTTP,
		Config: json.RawMessage(`{"url":"https://x.com"}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error on 4xx")
	}
}

func TestHTTPExecutor_ExpectStatus(t *testing.T) {
	stub := &stubHTTPDoer{resp: &HTTPResp{StatusCode: 404}}
	exec := NewHTTPExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepHTTP,
		Config: json.RawMessage(`{"url":"https://x.com","expect_status":[404]}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatalf("404 in expect_status should not error: %v", err)
	}
}

// stubNotifier
type stubNotifier struct {
	called  bool
	channel string
	to      string
}

func (s *stubNotifier) Send(ctx context.Context, channel, to, msg, tmpl string, params map[string]interface{}) error {
	s.called = true
	s.channel = channel
	s.to = to
	return nil
}

func TestNotifyExecutor_Success(t *testing.T) {
	stub := &stubNotifier{}
	exec := NewNotifyExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepNotify,
		Config: json.RawMessage(`{"channel":"slack","to":"#sec","message":"hi"}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	if !stub.called || stub.channel != "slack" || stub.to != "#sec" {
		t.Errorf("notify not called correctly: %+v", stub)
	}
}

func TestNotifyExecutor_LegacyConfig(t *testing.T) {
	stub := &stubNotifier{}
	exec := NewNotifyExecutor(stub)
	// Legacy: no JSON config, just config_raw
	n := &Node{
		ID: "n1", Type: StepNotify,
		ConfigRaw: "channel: #security-alerts\nping: @oncall",
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	if !stub.called {
		t.Fatal("notify not called for legacy config")
	}
	if stub.channel != "slack" {
		t.Errorf("channel = %s, want slack", stub.channel)
	}
}

// stubTicketer
type stubTicketer struct {
	called bool
	id     string
	url    string
	err    error
}

func (s *stubTicketer) Create(ctx context.Context, sys, proj, sum, desc string, params map[string]interface{}) (string, string, error) {
	s.called = true
	if s.err != nil {
		return "", "", s.err
	}
	if s.id == "" {
		s.id = "TICKET-1"
	}
	if s.url == "" {
		s.url = "https://jira.example.com/TICKET-1"
	}
	return s.id, s.url, nil
}

func TestTicketExecutor_Success(t *testing.T) {
	stub := &stubTicketer{}
	exec := NewTicketExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepTicket,
		Config: json.RawMessage(`{"system":"jira","project":"SEC","summary":"Critical alert"}`),
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["ticket_id"] != "TICKET-1" {
		t.Errorf("ticket_id = %v", data["ticket_id"])
	}
}

func TestTicketExecutor_LegacyConfig(t *testing.T) {
	stub := &stubTicketer{}
	exec := NewTicketExecutor(stub)
	// Legacy: project + priority + auto_assign
	n := &Node{
		ID: "n1", Type: StepTicket,
		ConfigRaw: "project: VSP-SECURITY\npriority: P1\nauto_assign: security-team",
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	if !stub.called {
		t.Fatal("ticket not called")
	}
}

func TestTicketExecutor_ErrorPropagates(t *testing.T) {
	stub := &stubTicketer{err: errors.New("API down")}
	exec := NewTicketExecutor(stub)
	n := &Node{
		ID: "n1", Type: StepTicket,
		Config: json.RawMessage(`{"system":"jira","project":"X","summary":"y"}`),
	}
	_, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveTemplate_Basic(t *testing.T) {
	ec := &ExecCtx{
		Vars: map[string]interface{}{
			"host":     "server-1",
			"severity": "CRITICAL",
		},
		StepOutputs: map[string]json.RawMessage{
			"n0": json.RawMessage(`{"count":42}`),
		},
	}
	tests := []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"${ctx.host}", "server-1"},
		{"Alert on ${ctx.host}: ${ctx.severity}", "Alert on server-1: CRITICAL"},
		{"${steps.n0.count} findings", "42 findings"},
		{"${ctx.missing}", ""},
		{"${unknown.x}", "${unknown.x}"},
	}
	for _, tt := range tests {
		got := resolveTemplate(tt.in, ec, context.Background())
		if got != tt.want {
			t.Errorf("resolveTemplate(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveTemplate_Secrets(t *testing.T) {
	ec := &ExecCtx{
		Secrets: &stubResolver{vals: map[string]string{"jira": "TOKEN-XYZ"}},
	}
	got := resolveTemplate("Bearer ${secrets.jira}", ec, context.Background())
	if got != "Bearer TOKEN-XYZ" {
		t.Errorf("got %q", got)
	}
}
