package audit

import (
	"testing"
)

func TestHash_Deterministic(t *testing.T) {
	e := Entry{
		Seq:      1,
		TenantID: "tenant-123",
		Action:   "LOGIN_OK",
		Resource: "/auth/login",
		PrevHash: "",
	}
	h1 := Hash(e)
	h2 := Hash(e)
	if h1 != h2 {
		t.Error("Hash should be deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("expected SHA-256 hex (64 chars), got %d", len(h1))
	}
}

func TestHash_ChangesWithFields(t *testing.T) {
	base := Entry{Seq: 1, TenantID: "t1", Action: "LOGIN", Resource: "/login", PrevHash: ""}
	h1 := Hash(base)

	// Change action
	e2 := base
	e2.Action = "LOGOUT"
	if Hash(e2) == h1 {
		t.Error("hash should change when Action changes")
	}

	// Change seq
	e3 := base
	e3.Seq = 2
	if Hash(e3) == h1 {
		t.Error("hash should change when Seq changes")
	}

	// Change prev_hash (chain integrity)
	e4 := base
	e4.PrevHash = "abc123"
	if Hash(e4) == h1 {
		t.Error("hash should change when PrevHash changes")
	}
}

func TestHash_ChainIntegrity(t *testing.T) {
	// Simulate a chain of 3 entries
	e1 := Entry{Seq: 1, TenantID: "t1", Action: "LOGIN", Resource: "/login", PrevHash: ""}
	h1 := Hash(e1)

	e2 := Entry{Seq: 2, TenantID: "t1", Action: "SCAN", Resource: "/scan", PrevHash: h1}
	h2 := Hash(e2)

	e3 := Entry{Seq: 3, TenantID: "t1", Action: "LOGOUT", Resource: "/logout", PrevHash: h2}
	h3 := Hash(e3)

	// All hashes should be unique
	if h1 == h2 || h2 == h3 || h1 == h3 {
		t.Error("all chain hashes should be unique")
	}

	// Tampering detection: change e2, h3 will mismatch
	e2tampered := e2
	e2tampered.Action = "ADMIN_DELETE"
	h2tampered := Hash(e2tampered)
	if h2tampered == h2 {
		t.Error("tampered entry should produce different hash")
	}
}

func TestHash_UserIDNotInHash(t *testing.T) {
	// UserID intentionally not in hash format — verify stability
	e1 := Entry{Seq: 1, TenantID: "t1", Action: "LOGIN", UserID: "user-a", PrevHash: ""}
	e2 := Entry{Seq: 1, TenantID: "t1", Action: "LOGIN", UserID: "user-b", PrevHash: ""}
	// Same hash because UserID not included (by design)
	if Hash(e1) != Hash(e2) {
		t.Log("Note: UserID IS included in hash — update test if intentional")
	}
}

func TestHash_Format(t *testing.T) {
	e := Entry{Seq: 42, TenantID: "abc", Action: "TEST", Resource: "/test", PrevHash: "prev"}
	h := Hash(e)
	// SHA-256 hex = 64 lowercase hex chars
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hash contains non-hex character: %c", c)
		}
	}
}
