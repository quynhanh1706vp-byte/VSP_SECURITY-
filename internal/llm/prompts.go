package llm

import (
	"fmt"
	"strings"
)

// SystemPrompt instructs the LLM to behave as a security remediation assistant.
// Emphasises JSON-only output, schema compliance, and conservative confidence.
const SystemPrompt = `You are a security code remediation assistant.
Your task: given vulnerable code and a security rule violation, output
a JSON object with a precise fix.

RULES:
1. Output ONLY valid JSON matching the schema below — NO prose, NO markdown.
2. Preserve indentation and language style of the original code.
3. Only modify the lines containing the vulnerability.
4. If unsure, set "confidence": "low" and explain in "rationale".
5. If fix would break compatibility, set "breaking_change": true.
6. Keep "rationale" to 1-3 sentences max.

SCHEMA:
{
  "suggested_code": "<replacement for vulnerable lines>",
  "rationale": "<1-3 sentences explaining the fix>",
  "confidence": "high|medium|low",
  "breaking_change": true|false
}

EXAMPLES:

INPUT:
Rule: kics-iam-wildcard-action
Description: IAM policy uses wildcard action
Severity: high
Language: terraform
Vulnerable code:
  policy = jsonencode({
    Statement = [{ Action = "*", Resource = "*" }]
  })

OUTPUT:
{"suggested_code":"  policy = jsonencode({\n    Statement = [{ Action = [\"s3:GetObject\", \"s3:PutObject\"], Resource = \"arn:aws:s3:::my-bucket/*\" }]\n  })","rationale":"Replaced wildcard Action with explicit list and scoped Resource to specific bucket ARN to enforce least-privilege per CMMC AC-6.","confidence":"medium","breaking_change":true}

INPUT:
Rule: kics-k8s-privileged-container
Description: Container runs in privileged mode
Severity: high
Language: yaml
Vulnerable code:
        privileged: true

OUTPUT:
{"suggested_code":"        privileged: false","rationale":"Privileged containers bypass kernel security boundaries. Setting to false enforces least privilege per CIS Kubernetes Benchmark 5.2.1.","confidence":"high","breaking_change":false}

INPUT:
Rule: bandit-hardcoded-password
Description: Password literal in source code
Severity: high
Language: python
Vulnerable code:
password = "MySuperSecret123"

OUTPUT:
{"suggested_code":"password = os.environ.get(\"APP_PASSWORD\")","rationale":"Hardcoded password in source. Move to environment variable. The leaked credential must also be rotated immediately.","confidence":"high","breaking_change":true}

---
`

// BuildFixPrompt constructs the full prompt sent to the LLM.
// User prompt is appended after the system prompt + examples.
func BuildFixPrompt(req FixRequest) string {
	var sb strings.Builder
	sb.WriteString(SystemPrompt)
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("Rule: %s\n", req.RuleID))
	if req.RuleDescription != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", req.RuleDescription))
	}
	sb.WriteString(fmt.Sprintf("Severity: %s\n", req.Severity))
	sb.WriteString(fmt.Sprintf("Language: %s\n\n", req.Language))

	if req.CodeBefore != "" {
		sb.WriteString("Code context (lines before):\n")
		sb.WriteString(req.CodeBefore)
		sb.WriteString("\n\n")
	}
	sb.WriteString("Vulnerable code:\n")
	sb.WriteString(req.VulnerableCode)
	sb.WriteString("\n\n")
	if req.CodeAfter != "" {
		sb.WriteString("Code context (lines after):\n")
		sb.WriteString(req.CodeAfter)
		sb.WriteString("\n\n")
	}
	sb.WriteString("Output JSON now:")
	return sb.String()
}

// ValidateResponse checks that the parsed FixResponse satisfies invariants.
// Returns nil if valid, or an error describing the violation.
func ValidateResponse(r FixResponse) error {
	if strings.TrimSpace(r.SuggestedCode) == "" {
		return fmt.Errorf("suggested_code is empty")
	}
	if len(r.SuggestedCode) > 5*1024 {
		return fmt.Errorf("suggested_code too large (>5KB) — likely hallucination")
	}
	switch r.Confidence {
	case "high", "medium", "low":
		// ok
	default:
		return fmt.Errorf("invalid confidence: %q (must be high|medium|low)", r.Confidence)
	}
	if len(r.Rationale) > 1024 {
		return fmt.Errorf("rationale too long (>1KB)")
	}
	return nil
}
