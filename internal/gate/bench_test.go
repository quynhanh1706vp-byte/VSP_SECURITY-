package gate

import (
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func BenchmarkScore_Empty(b *testing.B) {
	s := scanner.Summary{}
	for i := 0; i < b.N; i++ {
		_ = Score(s)
	}
}

func BenchmarkScore_WithFindings(b *testing.B) {
	s := scanner.Summary{Critical: 2, High: 10, Medium: 30, Low: 50}
	for i := 0; i < b.N; i++ {
		_ = Score(s)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	rule := DefaultRule()
	s := scanner.Summary{Critical: 1, High: 5, Medium: 10}
	for i := 0; i < b.N; i++ {
		_ = Evaluate(rule, s)
	}
}

func BenchmarkPosture(b *testing.B) {
	s := scanner.Summary{High: 3, Medium: 8}
	for i := 0; i < b.N; i++ {
		_ = Posture(s)
	}
}
