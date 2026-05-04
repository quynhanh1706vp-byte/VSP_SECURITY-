package soar

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseLegacyConfig(t *testing.T) {
	raw := `provider: github
status: failure
context: vsp/gate`
	cfg := parseLegacyConfig(raw)
	if cfg["provider"] != "github" || cfg["status"] != "failure" || cfg["context"] != "vsp/gate" {
		t.Errorf("got %+v", cfg)
	}
}

func TestParseLegacyConfig_EmptyAndComments(t *testing.T) {
	raw := `# comment
key1: value1

# another
key2: value2
`
	cfg := parseLegacyConfig(raw)
	if len(cfg) != 2 || cfg["key1"] != "value1" || cfg["key2"] != "value2" {
		t.Errorf("got %+v", cfg)
	}
}

func TestParseLegacyConfig_StripBrackets(t *testing.T) {
	raw := `fields: [cvss,epss,kev]`
	cfg := parseLegacyConfig(raw)
	if cfg["fields"] != "cvss,epss,kev" {
		t.Errorf("got %q", cfg["fields"])
	}
}

func TestLegacyConditionToJS_Equality(t *testing.T) {
	js := legacyConditionToJS("gate=FAIL")
	// Should produce something like ctx.gate === "FAIL"
	if !strings.Contains(js, "ctx.gate") || !strings.Contains(js, `"FAIL"`) {
		t.Errorf("got %q", js)
	}
}

func TestLegacyConditionToJS_AndOr(t *testing.T) {
	js := legacyConditionToJS("gate=FAIL AND severity=HIGH")
	if !strings.Contains(js, "&&") {
		t.Errorf("expected &&, got %q", js)
	}
	js = legacyConditionToJS("gate=FAIL OR gate=ERROR")
	if !strings.Contains(js, "||") {
		t.Errorf("expected ||, got %q", js)
	}
}

func TestLegacyConditionToJS_InOperator(t *testing.T) {
	js := legacyConditionToJS("severity IN [CRITICAL,HIGH]")
	if !strings.Contains(js, ".indexOf(ctx.severity)") {
		t.Errorf("got %q", js)
	}
	if !strings.Contains(js, `"CRITICAL"`) || !strings.Contains(js, `"HIGH"`) {
		t.Errorf("got %q", js)
	}
}

func TestLegacyConditionToJS_RealPlaybookExpression(t *testing.T) {
	// Actual expression from "Gate FAIL auto-response" playbook
	js := legacyConditionToJS("gate=FAIL AND severity IN [CRITICAL,HIGH]")
	// Should evaluate via sandbox
	sb := NewSandbox()
	out, err := sb.Run(context.Background(),
		"(function(){ return ("+js+"); })()",
		SandboxInput{Vars: map[string]interface{}{
			"gate":     "FAIL",
			"severity": "HIGH",
		}}, 0)
	if err != nil {
		t.Fatalf("compiled JS failed: %s\n→ %v", js, err)
	}
	if out.Value != true {
		t.Errorf("expected true, got %v (js=%s)", out.Value, js)
	}
}

func TestLegacyEnrichExecutor(t *testing.T) {
	exec := &legacyEnrichExecutor{}
	n := &Node{
		ID: "n1", Type: StepEnrich,
		ConfigRaw: "source: NVD,OSV\nfields: [cvss,epss,kev]",
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["source"] != "NVD,OSV" {
		t.Errorf("source=%v", data["source"])
	}
	if data["fields"] != "cvss,epss,kev" {
		t.Errorf("fields=%v", data["fields"])
	}
}

func TestLegacyBlockExecutor(t *testing.T) {
	exec := &legacyBlockExecutor{}
	n := &Node{
		ID: "n1", Type: StepBlock,
		ConfigRaw: "provider: github\nstatus: failure\ncontext: vsp/gate",
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["provider"] != "github" || data["status"] != "failure" {
		t.Errorf("got %+v", data)
	}
}

func TestLegacyRemediateExecutor(t *testing.T) {
	exec := &legacyRemediateExecutor{}
	n := &Node{
		ID: "n1", Type: StepRemediate,
		ConfigRaw: "assignee: security-oncall\npriority: P1\nstatus: in_progress",
	}
	out, _, err := exec.Run(context.Background(), n, &ExecCtx{})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["assignee"] != "security-oncall" || data["priority"] != "P1" {
		t.Errorf("got %+v", data)
	}
}

func TestLegacyExecutors_DefaultStatusValues(t *testing.T) {
	// block without status → "failure"
	exec := &legacyBlockExecutor{}
	n := &Node{ID: "n1", Type: StepBlock, ConfigRaw: "provider: github"}
	out, _, _ := exec.Run(context.Background(), n, &ExecCtx{})
	var data map[string]interface{}
	json.Unmarshal(out, &data)
	if data["status"] != "failure" {
		t.Errorf("default status=%v", data["status"])
	}

	// remediate without status → "in_progress"
	rexec := &legacyRemediateExecutor{}
	rn := &Node{ID: "n1", Type: StepRemediate, ConfigRaw: "assignee: x"}
	rout, _, _ := rexec.Run(context.Background(), rn, &ExecCtx{})
	var rdata map[string]interface{}
	json.Unmarshal(rout, &rdata)
	if rdata["status"] != "in_progress" {
		t.Errorf("default rem status=%v", rdata["status"])
	}
}
