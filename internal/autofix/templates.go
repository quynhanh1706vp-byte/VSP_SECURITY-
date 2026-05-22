package autofix

import (
	"regexp"
	"strings"
)

// FixTemplate describes a deterministic remediation for a known rule.
// All templates are hardcoded — no LLM, no external API calls.
// Each template is air-gap safe and audit-reproducible.
type FixTemplate struct {
	RuleID      string
	Pattern     *regexp.Regexp
	Replacement string
	Rationale   string
	Confidence  string // "high" | "medium" | "low"
	Category    string // "iac" | "secrets" | "container" | "code"
}

// templates is the authoritative registry of auto-fix patterns.
// Keyed by rule_id (lowercased, stable across scanner versions).
var templates = map[string]FixTemplate{
	// ─── kics: IaC misconfig (12 templates) ───
	"kics-security-field-empty": {
		RuleID:      "kics-security-field-empty",
		Pattern:     regexp.MustCompile(`(?m)^(\s*)security:\s*\[\s*\]\s*$`),
		Replacement: "${1}security:\n${1}  - bearerAuth: []",
		Rationale:   "Empty security array means endpoint is publicly accessible. Add bearerAuth requirement to enforce authentication per OpenAPI spec.",
		Confidence:  "high",
		Category:    "iac",
	},
	"kics-s3-acl-public-read": {
		RuleID:      "kics-s3-acl-public-read",
		Pattern:     regexp.MustCompile(`acl\s*=\s*"public-read(-write)?"`),
		Replacement: `acl = "private"`,
		Rationale:   "Public S3 ACL allows anyone to read bucket contents. Set to private and use bucket policies for granular access.",
		Confidence:  "high",
		Category:    "iac",
	},
	"kics-s3-no-encryption": {
		RuleID:      "kics-s3-no-encryption",
		Pattern:     regexp.MustCompile(`resource\s+"aws_s3_bucket"\s+"\w+"\s*\{[^}]*\}`),
		Replacement: "${0}\n\nresource \"aws_s3_bucket_server_side_encryption_configuration\" \"this\" {\n  bucket = aws_s3_bucket.this.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = \"AES256\"\n    }\n  }\n}",
		Rationale:   "S3 bucket lacks default encryption. Adding AES256 server-side encryption protects data at rest per CMMC SC-28.",
		Confidence:  "medium",
		Category:    "iac",
	},
	"kics-security-group-open-cidr": {
		RuleID:      "kics-security-group-open-cidr",
		Pattern:     regexp.MustCompile(`cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]`),
		Replacement: `cidr_blocks = ["10.0.0.0/8"]  # TODO: replace with your VPC CIDR`,
		Rationale:   "0.0.0.0/0 allows ingress from entire internet. Restrict to your VPC CIDR or specific bastion ranges.",
		Confidence:  "medium",
		Category:    "iac",
	},
	"kics-iam-wildcard-action": {
		RuleID:      "kics-iam-wildcard-action",
		Pattern:     regexp.MustCompile(`"Action":\s*"\*"`),
		Replacement: `"Action": ["s3:GetObject", "s3:PutObject"]  // TODO: scope to actual permissions needed`,
		Rationale:   "IAM wildcard actions violate least privilege. Replace with specific action list.",
		Confidence:  "low",
		Category:    "iac",
	},
	"kics-k8s-privileged-container": {
		RuleID:      "kics-k8s-privileged-container",
		Pattern:     regexp.MustCompile(`(?m)^(\s*)privileged:\s*true\s*$`),
		Replacement: "${1}privileged: false",
		Rationale:   "Privileged containers bypass kernel security boundaries. Use specific capabilities instead.",
		Confidence:  "high",
		Category:    "container",
	},
	"kics-k8s-no-resource-limits": {
		RuleID:      "kics-k8s-no-resource-limits",
		Pattern:     regexp.MustCompile(`(?m)^(\s*)containers:\s*\n(\s*-\s*name:.*?)(\n\s+image:)`),
		Replacement: "${1}containers:\n${2}${3}\n${1}  resources:\n${1}    limits:\n${1}      cpu: \"500m\"\n${1}      memory: \"512Mi\"",
		Rationale:   "Containers without resource limits can consume all node resources. Setting limits prevents noisy-neighbor impact.",
		Confidence:  "medium",
		Category:    "container",
	},
	"kics-k8s-host-network": {
		RuleID:      "kics-k8s-host-network",
		Pattern:     regexp.MustCompile(`(?m)^(\s*)hostNetwork:\s*true\s*$`),
		Replacement: "${1}hostNetwork: false",
		Rationale:   "hostNetwork: true gives pod access to node network namespace, exposing host services.",
		Confidence:  "high",
		Category:    "container",
	},
	"kics-k8s-allow-privilege-escalation": {
		RuleID:      "kics-k8s-allow-privilege-escalation",
		Pattern:     regexp.MustCompile(`(?m)^(\s*)allowPrivilegeEscalation:\s*true\s*$`),
		Replacement: "${1}allowPrivilegeEscalation: false",
		Rationale:   "allowPrivilegeEscalation lets process gain more privileges than its parent. Disable per CIS Kubernetes Benchmark 5.2.5.",
		Confidence:  "high",
		Category:    "container",
	},
	"kics-volume-host-path-sensitive": {
		RuleID:      "kics-volume-host-path-sensitive",
		Pattern:     regexp.MustCompile(`(?m)^(\s*)path:\s*"?(/etc|/proc|/sys|/var/run/docker\.sock)"?\s*$`),
		Replacement: "${1}# REMOVED: ${0} — sensitive host directory mount\n${1}path: /opt/myapp/data  # TODO: use app-specific directory",
		Rationale:   "Mounting sensitive host directories like /etc, /proc, /sys, or docker.sock provides container-escape vectors.",
		Confidence:  "high",
		Category:    "container",
	},
	"kics-dockerfile-root-user": {
		RuleID:      "kics-dockerfile-root-user",
		Pattern:     regexp.MustCompile(`(?m)^(FROM\s+\S+(?:\s+AS\s+\S+)?)\s*$`),
		Replacement: "${1}\n\nRUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser",
		Rationale:   "Containers running as root violate least privilege. Add non-root user per CIS Docker Benchmark 4.1.",
		Confidence:  "medium",
		Category:    "container",
	},
	"kics-tls-min-version": {
		RuleID:      "kics-tls-min-version",
		Pattern:     regexp.MustCompile(`min_tls_version\s*=\s*"TLS_?1[._]?[01]"`),
		Replacement: `min_tls_version = "TLS1_2"`,
		Rationale:   "TLS 1.0/1.1 are deprecated and have known vulnerabilities. Require TLS 1.2 minimum per NIST SP 800-52r2.",
		Confidence:  "high",
		Category:    "iac",
	},

	// ─── gitleaks: secrets exposed (4 templates) ───
	"gitleaks-generic-api-key": {
		RuleID:      "gitleaks-generic-api-key",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']`),
		Replacement: `${1} = os.Getenv("APP_${1}")  // moved to environment variable`,
		Rationale:   "Hardcoded secrets in source code can leak via VCS history. Move to environment variable or secret manager.",
		Confidence:  "high",
		Category:    "secrets",
	},
	"gitleaks-aws-access-key": {
		RuleID:      "gitleaks-aws-access-key",
		Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Replacement: `// REMOVED: hardcoded AWS access key — use IAM role or AWS SDK default credential chain`,
		Rationale:   "Hardcoded AWS access key exposes account. Rotate immediately and use IAM roles.",
		Confidence:  "high",
		Category:    "secrets",
	},
	"gitleaks-private-key": {
		RuleID:      "gitleaks-private-key",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----`),
		Replacement: `// REMOVED: private key in source — load from KMS/Vault at runtime`,
		Rationale:   "Private keys in source = credential breach. Rotate and load from secret manager.",
		Confidence:  "high",
		Category:    "secrets",
	},
	"gitleaks-jwt-token": {
		RuleID:      "gitleaks-jwt-token",
		Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		Replacement: `os.Getenv("JWT_TOKEN")  // moved to env`,
		Rationale:   "JWT tokens in source code often grant API access. Move to environment.",
		Confidence:  "high",
		Category:    "secrets",
	},

	// ─── trivy: SCA / dependency CVEs (2 templates) ───
	"trivy-cve-go-mod": {
		RuleID:      "trivy-cve-go-mod",
		Pattern:     regexp.MustCompile(`(\S+)\s+v(\d+\.\d+\.\d+)`),
		Replacement: "${1} v${2}  // TODO: run `go get -u ${1}` to update to patched version",
		Rationale:   "Dependency has known CVE. Check trivy report for patched version and bump in go.mod.",
		Confidence:  "low",
		Category:    "code",
	},
	"trivy-cve-package-json": {
		RuleID:      "trivy-cve-package-json",
		Pattern:     regexp.MustCompile(`"(\S+)":\s*"\^?(\d+\.\d+\.\d+)"`),
		Replacement: `"${1}": "latest"  // TODO: pin to specific patched version after npm audit`,
		Rationale:   "npm package has known CVE. Run npm audit fix or bump to patched version.",
		Confidence:  "low",
		Category:    "code",
	},

	// ─── checkov / bandit (2 templates) ───
	"checkov-cloudtrail-encryption": {
		RuleID:      "checkov-cloudtrail-encryption",
		Pattern:     regexp.MustCompile(`resource\s+"aws_cloudtrail"\s+"\w+"\s*\{`),
		Replacement: "${0}\n  kms_key_id = aws_kms_key.cloudtrail.arn  // CMMC AU-9: Protection of Audit Information",
		Rationale:   "CloudTrail logs without KMS encryption violate CMMC AU-9 audit information protection.",
		Confidence:  "medium",
		Category:    "iac",
	},
	"bandit-hardcoded-password": {
		RuleID:      "bandit-hardcoded-password",
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*["']([^"']{4,})["']`),
		Replacement: `${1} = os.environ.get("${1}_ENV")  # moved to environment variable`,
		Rationale:   "Hardcoded password in Python source. Use os.environ.get() and load from secrets manager.",
		Confidence:  "high",
		Category:    "code",
	},
}

// Lookup returns the template for a rule, or nil if no template is registered.
// Lookup is case-insensitive on rule_id and tolerant of common scanner prefixes.
func Lookup(ruleID string) *FixTemplate {
	key := strings.ToLower(strings.TrimSpace(ruleID))
	if t, ok := templates[key]; ok {
		return &t
	}
	// Try fuzzy: strip common scanner prefixes/suffixes
	stripped := strings.TrimPrefix(key, "kics_")
	stripped = strings.TrimPrefix(stripped, "kics-")
	stripped = strings.ReplaceAll(stripped, "_", "-")
	if t, ok := templates[stripped]; ok {
		return &t
	}
	return nil
}

// Apply runs the template's regex replacement against input source.
// Returns the modified source and a bool indicating whether any change was made.
func (t *FixTemplate) Apply(source string) (string, bool) {
	if t == nil || t.Pattern == nil {
		return source, false
	}
	result := t.Pattern.ReplaceAllString(source, t.Replacement)
	return result, result != source
}

// Categories returns all distinct categories in the registry.
// Useful for UI grouping.
func Categories() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range templates {
		if !seen[t.Category] {
			seen[t.Category] = true
			out = append(out, t.Category)
		}
	}
	return out
}

// Count returns the total number of registered templates.
func Count() int { return len(templates) }
