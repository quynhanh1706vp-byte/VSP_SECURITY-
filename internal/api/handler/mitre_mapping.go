// Package handler — static mapping from VSP finding signatures to MITRE
// ATT&CK Enterprise (v15) tactics + techniques.
//
// We deliberately keep this as Go data rather than a DB table. The mapping
// is small, audit-reviewed, and changing it should be a code review (with
// the CODEOWNERS rules attached) rather than runtime config. When the map
// grows past ~150 entries we'll move it to YAML in /docs.
//
// Match precedence per finding (first match wins):
//   1. Exact (tool, rule_id) hit
//   2. CWE-id hit
//   3. tool family default (e.g. "trivy" → T1190 Initial Access default)
//
// References:
//   https://attack.mitre.org/versions/v15/
//   ENISA "Threat Modelling Practical Guide" §4 (2024)
package handler

import "strings"

// MITRE Enterprise tactics in the canonical kill-chain order.
var mitreTactics = []mitreTactic{
	{ID: "TA0043", Name: "Reconnaissance"},
	{ID: "TA0042", Name: "Resource Development"},
	{ID: "TA0001", Name: "Initial Access"},
	{ID: "TA0002", Name: "Execution"},
	{ID: "TA0003", Name: "Persistence"},
	{ID: "TA0004", Name: "Privilege Escalation"},
	{ID: "TA0005", Name: "Defense Evasion"},
	{ID: "TA0006", Name: "Credential Access"},
	{ID: "TA0007", Name: "Discovery"},
	{ID: "TA0008", Name: "Lateral Movement"},
	{ID: "TA0009", Name: "Collection"},
	{ID: "TA0011", Name: "Command and Control"},
	{ID: "TA0010", Name: "Exfiltration"},
	{ID: "TA0040", Name: "Impact"},
}

type mitreTactic struct {
	ID   string
	Name string
}

// techniqueInfo defines a single ATT&CK technique we map to.
type techniqueInfo struct {
	ID      string // e.g. "T1190"
	Name    string // e.g. "Exploit Public-Facing Application"
	Tactic  string // tactic ID, e.g. "TA0001"
}

var techniqueCatalog = map[string]techniqueInfo{
	"T1190": {ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "TA0001"},
	"T1189": {ID: "T1189", Name: "Drive-by Compromise", Tactic: "TA0001"},
	"T1133": {ID: "T1133", Name: "External Remote Services", Tactic: "TA0001"},
	"T1059": {ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "TA0002"},
	"T1059.007": {ID: "T1059.007", Name: "JavaScript", Tactic: "TA0002"},
	"T1505.003": {ID: "T1505.003", Name: "Web Shell", Tactic: "TA0003"},
	"T1574": {ID: "T1574", Name: "Hijack Execution Flow", Tactic: "TA0004"},
	"T1068": {ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "TA0004"},
	"T1027": {ID: "T1027", Name: "Obfuscated Files or Information", Tactic: "TA0005"},
	"T1552": {ID: "T1552", Name: "Unsecured Credentials", Tactic: "TA0006"},
	"T1552.001": {ID: "T1552.001", Name: "Credentials In Files", Tactic: "TA0006"},
	"T1552.004": {ID: "T1552.004", Name: "Private Keys", Tactic: "TA0006"},
	"T1110": {ID: "T1110", Name: "Brute Force", Tactic: "TA0006"},
	"T1556": {ID: "T1556", Name: "Modify Authentication Process", Tactic: "TA0006"},
	"T1083": {ID: "T1083", Name: "File and Directory Discovery", Tactic: "TA0007"},
	"T1213": {ID: "T1213", Name: "Data from Information Repositories", Tactic: "TA0009"},
	"T1071": {ID: "T1071", Name: "Application Layer Protocol", Tactic: "TA0011"},
	"T1041": {ID: "T1041", Name: "Exfiltration Over C2 Channel", Tactic: "TA0010"},
	"T1499": {ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "TA0040"},
	"T1485": {ID: "T1485", Name: "Data Destruction", Tactic: "TA0040"},
	"T1486": {ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "TA0040"},
	"T1565": {ID: "T1565", Name: "Data Manipulation", Tactic: "TA0040"},
}

// cweToTechnique maps CWE → most-likely ATT&CK technique. Multi-mapping is
// possible in MITRE's reference model but we pick the canonical one to keep
// the heatmap legible. Add to this list as new CWEs surface in findings.
var cweToTechnique = map[string]string{
	"CWE-22":  "T1083",     // Path traversal → Discovery
	"CWE-78":  "T1059",     // OS command injection → Execution
	"CWE-79":  "T1059.007", // XSS → JavaScript execution
	"CWE-89":  "T1190",     // SQLi → Initial Access via app
	"CWE-94":  "T1059",     // Code injection
	"CWE-200": "T1213",     // Information disclosure
	"CWE-269": "T1068",     // Improper privilege management
	"CWE-287": "T1556",     // Improper authentication
	"CWE-295": "T1556",     // Cert validation
	"CWE-306": "T1190",     // Missing auth for critical function
	"CWE-307": "T1110",     // Improper restriction of excessive auth attempts
	"CWE-321": "T1552.004", // Hardcoded crypto key
	"CWE-326": "T1552",     // Inadequate encryption
	"CWE-327": "T1552",     // Broken/risky crypto
	"CWE-352": "T1190",     // CSRF → public app exploit
	"CWE-400": "T1499",     // Resource exhaustion → DoS
	"CWE-434": "T1505.003", // Unrestricted upload → web shell
	"CWE-502": "T1059",     // Deserialisation → Execution
	"CWE-522": "T1552",     // Insufficiently protected credentials
	"CWE-611": "T1213",     // XXE → data exfil
	"CWE-732": "T1574",     // Incorrect permission assignment
	"CWE-770": "T1499",     // Allocation without limits → DoS
	"CWE-798": "T1552.001", // Hardcoded credentials
	"CWE-862": "T1190",     // Missing authorisation
	"CWE-863": "T1190",     // Incorrect authorisation
	"CWE-918": "T1071",     // SSRF → C2/lateral
	"CWE-1004": "T1539",    // Insecure cookie (session hijacking — fallback)
}

// ruleToTechnique allows tool-specific rule IDs to override the CWE mapping
// when a rule is more specific than its CWE. e.g. "gosec.G101" is hardcoded
// secrets — we map directly to T1552.001 even if the CWE is missing.
var ruleToTechnique = map[string]string{
	"gosec/G101":           "T1552.001",
	"gosec/G201":           "T1190", // SQL injection
	"gosec/G203":           "T1059.007",
	"gosec/G204":           "T1059",
	"gosec/G304":           "T1083",
	"gosec/G401":           "T1552",
	"semgrep/hardcoded":    "T1552.001",
	"semgrep/sqli":         "T1190",
	"semgrep/xss":          "T1059.007",
	"semgrep/path-traversal":"T1083",
	"trivy/CVE":            "T1190", // generic CVE in dep ≈ exploitable surface
	"nuclei/exposure":      "T1213",
	"nuclei/default-creds": "T1110",
	"zap/sqli":             "T1190",
	"zap/xss":              "T1059.007",
	"zap/csrf":             "T1190",
}

// classifyFinding picks the technique ID for one finding. Returns "" when
// nothing matches — the caller drops these from the heatmap.
func classifyFinding(tool, ruleID, cwe string) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	cwe = strings.ToUpper(strings.TrimSpace(cwe))
	if !strings.HasPrefix(cwe, "CWE-") && cwe != "" {
		cwe = "CWE-" + cwe
	}
	rule := strings.TrimSpace(ruleID)

	// 1. Exact tool/rule.
	if rule != "" {
		if t, ok := ruleToTechnique[tool+"/"+rule]; ok {
			return t
		}
	}
	// 2. Tool family + rule prefix (e.g. "trivy/CVE-2024-...").
	if rule != "" {
		// most-specific prefix per tool
		families := []string{"CVE", "exposure", "default-creds", "sqli", "xss",
			"path-traversal", "hardcoded", "csrf"}
		for _, fam := range families {
			if strings.HasPrefix(strings.ToLower(rule), strings.ToLower(fam)) {
				if t, ok := ruleToTechnique[tool+"/"+fam]; ok {
					return t
				}
			}
		}
	}
	// 3. CWE.
	if cwe != "" {
		if t, ok := cweToTechnique[cwe]; ok {
			return t
		}
	}
	// 4. Tool-default fallback.
	switch tool {
	case "trivy", "nuclei", "zap", "nikto":
		return "T1190"
	case "gosec", "semgrep", "bandit", "eslint":
		return "T1059"
	case "gitleaks", "trufflehog":
		return "T1552.001"
	}
	return ""
}
