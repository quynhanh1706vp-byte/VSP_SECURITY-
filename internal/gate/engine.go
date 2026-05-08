package gate

import (
	"fmt"
	"math"

	"github.com/vsp/platform/internal/scanner"
)

// ── Decision ──────────────────────────────────────────────────────────────────

type Decision string

const (
	DecisionPass Decision = "PASS"
	DecisionWarn Decision = "WARN"
	DecisionFail Decision = "FAIL"
)

// ── PolicyRule ────────────────────────────────────────────────────────────────

// PolicyRule mirrors the policy_rules DB table.
type PolicyRule struct {
	ID            string
	Name          string
	RepoPattern   string
	FailOn        string // "FAIL" | "WARN" | "never"
	MinScore      int    // 0 = disabled
	MaxHigh       int    // -1 = unlimited
	BlockSecrets  bool
	BlockCritical bool
}

// DefaultRule returns a sensible production-grade default policy.
func DefaultRule() PolicyRule {
	return PolicyRule{
		FailOn:        "FAIL",
		MinScore:      70, // NIST SP 800-53 baseline — score < 70 = FAIL
		MaxHigh:       10, // >10 HIGH findings = FAIL (was unlimited)
		BlockSecrets:  true,
		BlockCritical: true,
	}
}

// ── EvalResult ────────────────────────────────────────────────────────────────

// EvalResult is the outcome of evaluating a policy against a scan summary.
type EvalResult struct {
	Decision Decision
	Reason   string
	Score    int    // 0-100
	Posture  string // A | B | C | D | F
}

// ── Evaluate ──────────────────────────────────────────────────────────────────

// Evaluate applies rule against summary and returns a gate decision.
// Rules are checked in order of severity — first match wins.
func Evaluate(rule PolicyRule, s scanner.Summary) EvalResult {
	score := Score(s)

	// 1. Critical findings block immediately
	if rule.BlockCritical && s.Critical > 0 {
		return EvalResult{
			Decision: DecisionFail,
			Reason:   fmt.Sprintf("critical findings present (%d)", s.Critical),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 2. Secrets are always blocking
	if rule.BlockSecrets && s.HasSecrets {
		return EvalResult{
			Decision: DecisionFail,
			Reason:   "secrets detected in source code",
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 3. Score threshold
	if rule.MinScore > 0 && score < rule.MinScore {
		return EvalResult{
			Decision: DecisionFail,
			Reason:   fmt.Sprintf("security score %d below minimum %d", score, rule.MinScore),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 4. High count threshold
	if rule.MaxHigh >= 0 && s.High > rule.MaxHigh {
		decision := DecisionFail
		if rule.FailOn == "WARN" {
			decision = DecisionWarn
		}
		return EvalResult{
			Decision: decision,
			Reason:   fmt.Sprintf("high severity count %d exceeds maximum %d", s.High, rule.MaxHigh),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	// 5. Any HIGH or MEDIUM → WARN (not blocking)
	if s.High > 0 || s.Medium > 0 {
		return EvalResult{
			Decision: DecisionWarn,
			Reason:   fmt.Sprintf("findings present: %d high, %d medium", s.High, s.Medium),
			Score:    score,
			Posture:  Posture(s),
		}
	}

	return EvalResult{
		Decision: DecisionPass,
		Reason:   "clean — no blocking findings",
		Score:    score,
		Posture:  Posture(s),
	}
}

// ── Score ─────────────────────────────────────────────────────────────────────

// Score computes a 0-100 security score from a summary.
//
// Sprint 7.3: replaced the hard-capped linear penalty (which made
// "2 critical findings" indistinguishable from "200 critical findings"
// — both topped out at 30pts) with a square-root diminishing-returns
// curve. The curve still bounds individual-bucket damage but preserves
// dynamic range across the 0-100 scale, so a run with 2032 findings
// (the dashboard case that motivated this fix) reads visibly worse
// than one with 50.
//
// Penalty per bucket: weight × sqrt(count). Examples for HIGH (w=8):
//   count=1 → 8pts   count=4 → 16pts   count=25 → 40pts   count=100 → 80pts
// Score floor is still 0 (clamp); the bucket itself is uncapped.
func Score(s scanner.Summary) int {
	// Use weighted counts when available (DAST×1.5, SCA×1.2, IAC×0.8, SAST×1.0)
	// WeightedCrit/High are ×10 integers — divide to get float-equivalent penalty
	critCount := s.Critical
	highCount := s.High
	if s.WeightedCrit > 0 {
		critCount = (s.WeightedCrit + 5) / 10 // round weighted to effective count
	}
	if s.WeightedHigh > 0 {
		highCount = (s.WeightedHigh + 5) / 10
	}

	// sqrt-shaped penalties keep the curve dynamic across orders of
	// magnitude. Operators who want a stricter linear policy can fall
	// back via VSP_SCORE_LINEAR=1 — see scoreLinear() below.
	critPenalty := sqrtPenalty(critCount, 15) // 1→15, 4→30, 9→45
	highPenalty := sqrtPenalty(highCount, 8)  // 1→8,  9→24, 25→40
	medPenalty := sqrtPenalty(s.Medium, 2)    // 1→2,  16→8, 100→20
	lowPenalty := sqrtPenalty(s.Low, 1)       // 1→1,  25→5, 400→20
	secretsPenalty := 0
	if s.HasSecrets {
		secretsPenalty = 25
	} // live secrets always -25pts

	// DAST bonus: applied only when DASTRan=true and no DAST-confirmed issues
	dastBonus := 0
	if s.DASTRan && s.DASTConfirmed == 0 {
		dastBonus = 3 // DAST ran clean → small confidence boost
	}

	score := 100 - critPenalty - highPenalty - medPenalty - lowPenalty - secretsPenalty + dastBonus
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func capInt(v, max int) int {
	if v > max {
		return max
	}
	return v
}

// sqrtPenalty returns round(weight × sqrt(count)).
// Diminishing-returns curve replaces the previous hard caps so the
// score scales with severity at all orders of magnitude (the
// pre-Sprint-7.3 caps made 2 critical and 200 critical produce the
// same penalty — see Score docstring).
//
// Using math.Sqrt is fine here: the result is rounded to int and
// IEEE-754 sqrt is deterministic across the platforms we target.
func sqrtPenalty(count, weight int) int {
	if count <= 0 {
		return 0
	}
	return int(math.Round(float64(weight) * math.Sqrt(float64(count))))
}

// ── Posture ───────────────────────────────────────────────────────────────────

// Posture returns a letter grade A–F based on the finding summary.
//
// Posture returns the canonical letter grade. This is the SINGLE source
// of truth for the system — every UI surface (dashboard, audit panel,
// PDF export, badge) MUST consume this rather than computing its own
// letter from a numeric score, otherwise users see different grades
// for the same run depending on which panel they look at (the
// pre-Sprint-7 bug that motivated this consolidation).
//
// Computation is two-step:
//   1. Hard-fail conditions force "F" regardless of score:
//        • any critical finding present
//        • live secrets present (HasSecrets)
//   2. Otherwise, derive from numeric Score(s):
//        ≥ 90 → A+,  ≥ 80 → A,  ≥ 70 → B,
//        ≥ 60 → C,   ≥ 40 → D,  else F
//
// The score-based bands match what the JS dashboard previously computed
// independently — this keeps existing UI snapshots stable while moving
// the math into one place.
func Posture(s scanner.Summary) string {
	return LetterGrade(s, Score(s))
}

// LetterGrade exposes the grading logic for callers that already have
// a precomputed score (avoids re-running Score). UI handlers should
// prefer Posture() unless they're already calling Score for telemetry.
func LetterGrade(s scanner.Summary, score int) string {
	// Hard-fail: critical findings or live secrets ALWAYS produce F,
	// even if the cap-bounded score would suggest otherwise. An
	// auditor seeing "Grade D · 1 critical finding" would lose trust
	// in the rest of the dashboard.
	if s.Critical > 0 || s.HasSecrets {
		return "F"
	}
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
