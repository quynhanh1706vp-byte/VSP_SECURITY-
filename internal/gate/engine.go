package gate

import (
	"fmt"

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
		MaxHigh:       -1,
		BlockSecrets:  true,
		BlockCritical: true,
	}
}

// ── EvalResult ────────────────────────────────────────────────────────────────

// EvalResult is the outcome of evaluating a policy against a scan summary.
type EvalResult struct {
	Decision Decision
	Reason   string
	Score    int // 0-100
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
// Formula: start at 100, deduct weighted penalty per severity bucket.
func Score(s scanner.Summary) int {
	const (
		penaltyCritical = 25
		penaltyHigh     = 10
		penaltyMedium   = 3
		penaltyLow      = 1
	)

	deduction := s.Critical*penaltyCritical +
		s.High*penaltyHigh +
		s.Medium*penaltyMedium +
		s.Low*penaltyLow

	score := 100 - deduction
	if score < 0 {
		return 0
	}
	return score
}

// ── Posture ───────────────────────────────────────────────────────────────────

// Posture returns a letter grade A–F based on the finding summary.
//
//	A = zero critical/high/medium
//	B = some medium/low but no high/critical
//	C = 1-2 high findings
//	D = 3-10 high findings OR any critical
//	F = critical present
func Posture(s scanner.Summary) string {
	switch {
	case s.Critical > 0:
		return "F"
	case s.High > 10:
		return "D"
	case s.High > 2 || s.Medium > 5:
		return "C"
	case s.High > 0 || s.Medium > 0:
		return "B"
	default:
		return "A"
	}
}
