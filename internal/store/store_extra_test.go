package store

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestIsPasswordReused_Logic tests logic không cần DB
// bằng cách test bcrypt comparison trực tiếp
func TestBcryptComparison(t *testing.T) {
	password := "mySecurePassword123!"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}

	// Correct password
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		t.Error("expected correct password to match")
	}

	// Wrong password
	if err := bcrypt.CompareHashAndPassword(hash, []byte("wrongpassword")); err == nil {
		t.Error("expected wrong password to not match")
	}
}

func TestBcryptCost(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Cost: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Errorf("expected cost %d, got %d", bcrypt.DefaultCost, cost)
	}
}
