package scanner

import "strings"

func EnrichFinding(tool, ruleID, severity, message string) (cwe string, cvss float64) {
	cvssDefault := map[string]float64{"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}
	switch tool {
	case "kics", "checkov":
		cwe, cvss = enrichIaC(message, severity)
		if cvss == 0 {
			cvss = cvssDefault[severity]
		}
	case "gitleaks", "trufflehog":
		cwe = enrichSecrets(ruleID, message)
		cvss = cvssDefault[severity]
	case "bandit":
		cwe = enrichBandit(ruleID)
		cvss = cvssDefault[severity]
	case "semgrep":
		cwe = enrichSemgrep(ruleID, message)
		cvss = cvssDefault[severity]
	}
	return
}

func enrichIaC(message, severity string) (string, float64) {
	msg := strings.ToLower(message)
	switch {
	case strings.Contains(msg, "s3") && strings.Contains(msg, "public"):
		return "CWE-732", 9.1
	case strings.Contains(msg, "s3") && strings.Contains(msg, "acl"):
		return "CWE-732", 9.1
	case strings.Contains(msg, "unrestricted") && strings.Contains(msg, "ingress"):
		return "CWE-732", 7.8
	case strings.Contains(msg, "0.0.0.0/0"):
		return "CWE-732", 7.8
	case strings.Contains(msg, "iam") && strings.Contains(msg, "wildcard"):
		return "CWE-269", 8.0
	case strings.Contains(msg, "publicly accessible"):
		return "CWE-284", 8.5
	case strings.Contains(msg, "not encrypt") || strings.Contains(msg, "unencrypt"):
		return "CWE-311", 6.5
	case strings.Contains(msg, "cloudtrail"):
		return "CWE-778", 5.0
	case strings.Contains(msg, "root") && strings.Contains(msg, "container"):
		return "CWE-250", 7.5
	case strings.Contains(msg, "privileged") && strings.Contains(msg, "container"):
		return "CWE-250", 7.5
	case strings.Contains(msg, "mfa"):
		return "CWE-308", 7.0
	default:
		if severity == "CRITICAL" || severity == "HIGH" {
			return "CWE-284", 0
		}
		if severity == "MEDIUM" {
			return "CWE-16", 0
		}
		return "CWE-1188", 0
	}
}

func enrichSecrets(ruleID, message string) string {
	if strings.Contains(strings.ToLower(ruleID), "private-key") {
		return "CWE-321"
	}
	if strings.Contains(strings.ToLower(message), "private key") {
		return "CWE-321"
	}
	return "CWE-798"
}

func enrichBandit(ruleID string) string {
	m := map[string]string{"B102": "CWE-78", "B105": "CWE-259", "B301": "CWE-502", "B303": "CWE-327", "B311": "CWE-338", "B321": "CWE-319", "B501": "CWE-295", "B601": "CWE-78", "B608": "CWE-89", "B701": "CWE-94"}
	if cwe, ok := m[strings.ToUpper(ruleID)]; ok {
		return cwe
	}
	return "CWE-676"
}

func enrichSemgrep(ruleID, message string) string {
	msg, rID := strings.ToLower(message), strings.ToLower(ruleID)
	switch {
	case strings.Contains(rID, "sql") || strings.Contains(msg, "sql injection"):
		return "CWE-89"
	case strings.Contains(rID, "xss") || strings.Contains(msg, "cross-site"):
		return "CWE-79"
	case strings.Contains(rID, "jwt") || strings.Contains(msg, "jwt"):
		return "CWE-798"
	case strings.Contains(rID, "rate-limit"):
		return "CWE-307"
	case strings.Contains(rID, "hardcode") || strings.Contains(msg, "hardcoded"):
		return "CWE-798"
	default:
		return "CWE-693"
	}
}
