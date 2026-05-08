package auth

import (
	"testing"
	"time"
)

func TestIPLockout_TripsAtLimit(t *testing.T) {
	l := NewIPLockout()
	ip := "1.2.3.4"
	for i := 0; i < ipFailLimit-1; i++ {
		newly, _ := l.RecordFail(ip)
		if newly {
			t.Fatalf("locked too early at fail %d", i+1)
		}
	}
	if l.IsLocked(ip) {
		t.Fatal("should not be locked yet")
	}
	newly, total := l.RecordFail(ip)
	if !newly {
		t.Fatal("did not lock at threshold")
	}
	if total != ipFailLimit {
		t.Fatalf("total = %d, want %d", total, ipFailLimit)
	}
	if !l.IsLocked(ip) {
		t.Fatal("should be locked now")
	}
}

func TestIPLockout_WindowSlides(t *testing.T) {
	l := NewIPLockout()
	ip := "1.2.3.5"
	// Insert fake-old entries directly via internal state (test-only).
	l.mu.Lock()
	old := time.Now().Add(-(ipWindow + time.Minute))
	l.buckets[ip] = &ipBucket{fails: []time.Time{old, old, old}}
	l.mu.Unlock()
	// One fresh fail — old entries should be trimmed, total=1.
	_, total := l.RecordFail(ip)
	if total != 1 {
		t.Fatalf("expected window to drop stale entries, got total=%d", total)
	}
}

func TestIPLockout_ClearOnSuccess(t *testing.T) {
	l := NewIPLockout()
	ip := "1.2.3.6"
	l.RecordFail(ip)
	l.RecordFail(ip)
	l.Clear(ip)
	if l.IsLocked(ip) {
		t.Fatal("Clear should remove the bucket")
	}
}

func TestCompareDummyPassword_AlwaysErrors(t *testing.T) {
	if err := CompareDummyPassword("anything"); err == nil {
		t.Fatal("dummy compare should always error")
	}
}

func TestBackoffSleep_Caps(t *testing.T) {
	start := time.Now()
	BackoffSleep(10) // would be 1s × 2^9 = 512s if uncapped
	if d := time.Since(start); d > 9*time.Second {
		t.Fatalf("sleep should be capped at 8s, took %v", d)
	}
}
