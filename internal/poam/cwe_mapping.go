// Package poam provides POA&M auto-generation worker.
package poam

// cweToControl maps CWE IDs to NIST 800-53 controls.
// Used by the auto-gen worker to enrich POAM items beyond tool-only mapping.
// References: NIST SP 800-53 Rev. 5, MITRE CWE.
var cweToControl = map[string]string{
	// Injection
	"CWE-79": "SI-10", // XSS → Information Input Validation
	"CWE-89": "SI-10", // SQL Injection
	"CWE-78": "SI-10", // OS Command Injection
	"CWE-90": "SI-10", // LDAP Injection
	"CWE-91": "SI-10", // XML Injection
	"CWE-94": "SI-10", // Code Injection
	"CWE-95": "SI-10", // eval() Injection
	"CWE-77": "SI-10", // Generic Command Injection

	// Path / Resource
	"CWE-22":  "AC-3", // Path Traversal → Access Enforcement
	"CWE-23":  "AC-3", // Relative Path Traversal
	"CWE-36":  "AC-3", // Absolute Path Traversal
	"CWE-73":  "AC-3", // External Control of File Path
	"CWE-434": "SI-3", // Unrestricted File Upload → Malicious Code Protection
	"CWE-552": "AC-3", // Files Accessible to External Parties

	// Authentication / Authorization
	"CWE-287": "IA-2", // Improper Authentication → Identification & Auth
	"CWE-306": "IA-2", // Missing Authentication
	"CWE-862": "AC-3", // Missing Authorization
	"CWE-863": "AC-3", // Incorrect Authorization
	"CWE-285": "AC-3", // Improper Authorization
	"CWE-269": "AC-6", // Improper Privilege Management → Least Privilege
	"CWE-264": "AC-6", // Permissions/Privileges
	"CWE-732": "AC-3", // Incorrect Permission Assignment

	// Credentials / Secrets
	"CWE-798": "IA-5", // Hardcoded Credentials → Authenticator Management
	"CWE-259": "IA-5", // Hardcoded Password
	"CWE-256": "IA-5", // Plaintext Storage of Password
	"CWE-321": "IA-5", // Hardcoded Cryptographic Key
	"CWE-522": "IA-5", // Insufficiently Protected Credentials
	"CWE-916": "IA-5", // Use of Password Hash With Insufficient Effort

	// Cryptography
	"CWE-327": "SC-13", // Broken/Risky Crypto → Cryptographic Protection
	"CWE-326": "SC-13", // Inadequate Encryption Strength
	"CWE-328": "SC-13", // Reversible One-Way Hash
	"CWE-330": "SC-13", // Insufficient Randomness
	"CWE-338": "SC-13", // Cryptographically Weak PRNG
	"CWE-311": "SC-8",  // Missing Encryption → Transmission Confidentiality
	"CWE-312": "SC-28", // Cleartext Storage → Protection of Info at Rest
	"CWE-319": "SC-8",  // Cleartext Transmission

	// Session / CSRF / Open Redirect
	"CWE-352": "SC-8",  // CSRF → Boundary Protection
	"CWE-384": "SC-23", // Session Fixation → Session Authenticity
	"CWE-613": "AC-12", // Insufficient Session Expiration → Session Termination
	"CWE-601": "SI-10", // Open Redirect

	// Information Exposure
	"CWE-200": "SC-4",  // Info Disclosure → Information in Shared Resources
	"CWE-209": "SI-11", // Error Message Info Leak → Error Handling
	"CWE-532": "AU-9",  // Log Info Leak → Protection of Audit Information
	"CWE-538": "SC-4",  // File/Dir Info Leak

	// Resource Consumption / DoS
	"CWE-400": "SC-5", // Uncontrolled Resource Consumption → DoS Protection
	"CWE-770": "SC-5", // Allocation Without Limits

	// Deserialization / XXE
	"CWE-502": "SI-10", // Deserialization of Untrusted Data
	"CWE-611": "SI-10", // XXE
	"CWE-918": "SC-7",  // SSRF → Boundary Protection

	// Configuration / Hardening
	"CWE-16":   "CM-6", // Configuration → Configuration Settings
	"CWE-1004": "CM-6", // Sensitive Cookie Without HttpOnly
	"CWE-693":  "CM-6", // Protection Mechanism Failure

	// Vulnerable Components
	"CWE-1104": "SA-11", // Unmaintained 3rd-Party Component → Developer Testing
	"CWE-937":  "SA-11", // OWASP Top 10 — Vulnerable Components

	// Memory / C-family
	"CWE-119": "SI-16", // Buffer Overflow → Memory Protection
	"CWE-120": "SI-16", // Classic Buffer Overflow
	"CWE-125": "SI-16", // Out-of-bounds Read
	"CWE-787": "SI-16", // Out-of-bounds Write
	"CWE-416": "SI-16", // Use After Free
}

// MapCWEToControl returns the NIST 800-53 control ID for a given CWE.
// Returns "SI-2" (Flaw Remediation, generic) for unmapped CWEs.
func MapCWEToControl(cwe string) string {
	if c, ok := cweToControl[cwe]; ok {
		return c
	}
	return "SI-2"
}

// MappingCount returns the total CWE entries (for stats/observability).
func MappingCount() int {
	return len(cweToControl)
}
