package llm

import (
	"os"
	"strings"
)

// Policy controls per-rule LLM behavior.
// Loaded from autofix_policy.yaml, but we use a minimal hand-rolled parser
// to avoid pulling in a yaml dependency (keep stdlib-only invariant).
type Policy struct {
	GlobalEnabled bool
	BlockedRules  map[string]string // rule_id → reason (note)
}

// LoadPolicy reads the YAML file and returns a Policy.
// On any error (file missing, parse error), returns a default-allow policy
// with secrets-related rules pre-blocked.
func LoadPolicy(path string) *Policy {
	p := &Policy{
		GlobalEnabled: true,
		BlockedRules: map[string]string{
			// Defaults — secrets/CVE rules where LLM is unhelpful or risky
			"gitleaks-aws-access-key":   "Hardcoded credentials must be rotated, not auto-generated",
			"gitleaks-private-key":      "Private keys must be rotated, not auto-generated",
			"gitleaks-jwt-token":        "Tokens must be rotated, not auto-generated",
			"gitleaks-generic-api-key":  "API keys must be rotated, not auto-generated",
			"bandit-hardcoded-password": "Hardcoded credentials must be rotated, not auto-generated",
			"trivy-cve-go-mod":          "Use trivy report to find patched versions",
			"trivy-cve-package-json":    "Use npm audit fix or vendor advisory",
			"kics-tls-min-version":      "Cryptographic config — manual review",
		},
	}

	if path == "" {
		return p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	parseSimpleYAML(p, string(data))
	return p
}

// AllowLLM returns true iff the LLM may generate a fix for ruleID.
func (p *Policy) AllowLLM(ruleID string) bool {
	if !p.GlobalEnabled {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(ruleID))
	if _, blocked := p.BlockedRules[key]; blocked {
		return false
	}
	return true
}

// BlockReason returns the human-readable reason if a rule is blocked.
func (p *Policy) BlockReason(ruleID string) string {
	key := strings.ToLower(strings.TrimSpace(ruleID))
	if r, ok := p.BlockedRules[key]; ok {
		return r
	}
	return ""
}

// parseSimpleYAML handles the limited subset of YAML our policy file uses.
// Looks for:
//
//	global:
//	  llm_enabled: false   ← optional kill switch
//	rules:
//	  <rule_id>:
//	    llm_allowed: false ← block list entries
//	    note: "..."        ← optional reason
func parseSimpleYAML(p *Policy, data string) {
	lines := strings.Split(data, "\n")
	inGlobal := false
	inRules := false
	currentRule := ""
	currentNote := ""
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Top-level sections
		if indent == 0 {
			if strings.HasPrefix(trim, "global:") {
				inGlobal, inRules = true, false
				currentRule = ""
				continue
			}
			if strings.HasPrefix(trim, "rules:") {
				inGlobal, inRules = false, true
				currentRule = ""
				continue
			}
			inGlobal, inRules = false, false
			continue
		}

		if inGlobal {
			if strings.HasPrefix(trim, "llm_enabled:") {
				val := strings.TrimSpace(strings.TrimPrefix(trim, "llm_enabled:"))
				val = stripInlineComment(val)
				p.GlobalEnabled = (val == "true")
			}
			continue
		}

		if inRules {
			// 2-space indent: rule id (e.g. "  kics-foo:")
			if indent == 2 && strings.HasSuffix(trim, ":") {
				currentRule = strings.ToLower(strings.TrimSuffix(trim, ":"))
				currentNote = ""
				continue
			}
			// 4-space indent: rule properties
			if indent == 4 && currentRule != "" {
				switch {
				case strings.HasPrefix(trim, "llm_allowed:"):
					val := strings.TrimSpace(strings.TrimPrefix(trim, "llm_allowed:"))
					val = stripInlineComment(val)
					if val == "false" {
						note := currentNote
						if note == "" {
							note = "Blocked by policy"
						}
						p.BlockedRules[currentRule] = note
					} else if val == "true" {
						// Override the default block list
						delete(p.BlockedRules, currentRule)
					}
				case strings.HasPrefix(trim, "note:"):
					currentNote = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trim, "note:")), `"\'`)
					// If we already set the rule as blocked, update the note
					if _, blocked := p.BlockedRules[currentRule]; blocked {
						p.BlockedRules[currentRule] = currentNote
					}
				}
			}
		}
	}
}

// stripInlineComment removes "# comment" suffix from a YAML value.
// Returns the trimmed value before the first " #" sequence.
func stripInlineComment(val string) string {
	if idx := strings.Index(val, " #"); idx >= 0 {
		val = val[:idx]
	}
	if idx := strings.Index(val, "\t#"); idx >= 0 {
		val = val[:idx]
	}
	return strings.TrimSpace(val)
}
