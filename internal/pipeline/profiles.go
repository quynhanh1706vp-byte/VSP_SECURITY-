package pipeline

import "github.com/vsp/platform/internal/scanner"

type ProfileConfig struct {
	TimeoutSec  int
	Description string
}

var Profiles = map[Profile]ProfileConfig{
	ProfileFast:    {TimeoutSec: 120,  Description: "Fast — core tools, 2min"},
	ProfileExt:     {TimeoutSec: 300,  Description: "Extended — all tools, 5min"},
	ProfileAggr:    {TimeoutSec: 600,  Description: "Aggressive — fail on any HIGH"},
	ProfilePremium: {TimeoutSec: 900,  Description: "Premium — deep scan 15min"},
	ProfileFull:    {TimeoutSec: 1200, Description: "Full — all tools 20min"},
	ProfileFullSOC: {TimeoutSec: 1800, Description: "Full SOC — max depth"},
}

func RunnersForProfile(mode Mode, profile Profile) []scanner.Runner {
	runners := RunnersFor(mode)
	if profile == ProfileFast && (mode == ModeSAST || mode == ModeFull) {
		filtered := make([]scanner.Runner, 0)
		for _, r := range runners {
			if r.Name() != "codeql" {
				filtered = append(filtered, r)
			}
		}
		return filtered
	}
	return runners
}

func TimeoutForProfile(profile Profile) int {
	if cfg, ok := Profiles[profile]; ok {
		return cfg.TimeoutSec
	}
	return 120
}
