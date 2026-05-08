package handler

import "testing"

// TestValidFeatures_RecentMigrationsCovered pins the validFeatures map
// to the migrations that extend feature_config's CHECK constraint.
// Adding a new migration without updating the Go map = PUT returns
// 400 unknown feature_id (the pre-Sprint-12.4 bug). This test catches
// that drift at CI time.
func TestValidFeatures_RecentMigrationsCovered(t *testing.T) {
	mustHave := []string{
		"cato",            // migration 031 — Sprint 3
		"grafana",         // migration 033 — Sprint 4
		"system_toggles",  // migration 045 — Sprint 12
	}
	for _, id := range mustHave {
		if !validFeatures[id] {
			t.Errorf("validFeatures missing %q — DB CHECK was extended without updating Go map", id)
		}
	}
}

// TestAdminOnlyFeatures_GatesSystemToggles ensures the admin role
// enforcement applies to features that affect system-level
// behaviour. Without the gate, the UI's "Admin role required" hint
// is unenforced and any authenticated user can flip SSE / session
// timer / Vault requirements.
func TestAdminOnlyFeatures_GatesSystemToggles(t *testing.T) {
	mustGate := []string{
		"system_toggles",
		"cato",
		"grafana",
		"settings_security",
		"settings_apikeys",
	}
	for _, id := range mustGate {
		if !adminOnlyFeatures[id] {
			t.Errorf("adminOnlyFeatures missing %q — non-admin users could mutate this system-level config", id)
		}
		if !validFeatures[id] {
			t.Errorf("adminOnlyFeatures lists %q but validFeatures doesn't — gate would never fire because PUT 400s first", id)
		}
	}
}

// TestAdminOnlyFeatures_DoesNotOvergate verifies that ordinary panel
// configs (analyst self-service) stay role-free. If we accidentally
// promoted these to admin-only, analysts would lose the ability to
// save their own panel preferences.
func TestAdminOnlyFeatures_DoesNotOvergate(t *testing.T) {
	mustNotGate := []string{
		"ai_analyst",
		"correlation",
		"ueba",
		"threat_hunt",
		"vuln_mgmt",
	}
	for _, id := range mustNotGate {
		if adminOnlyFeatures[id] {
			t.Errorf("adminOnlyFeatures unexpectedly contains %q — would block analyst self-service", id)
		}
	}
}
