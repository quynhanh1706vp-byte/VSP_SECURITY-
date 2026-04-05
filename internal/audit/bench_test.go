package audit

import (
	"testing"
)

func BenchmarkHash(b *testing.B) {
	e := Entry{
		Seq:      42,
		TenantID: "tenant-abc-123",
		Action:   "LOGIN_OK",
		Resource: "/api/v1/auth/login",
		PrevHash: "abc123def456",
	}
	for i := 0; i < b.N; i++ {
		_ = Hash(e)
	}
}

func BenchmarkHashChain(b *testing.B) {
	prevHash := ""
	for i := 0; i < b.N; i++ {
		e := Entry{
			Seq:      int64(i),
			TenantID: "tenant-1",
			Action:   "ACTION",
			PrevHash: prevHash,
		}
		prevHash = Hash(e)
	}
}
