package cosign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDockerfile(t *testing.T) {
	dir := t.TempDir()
	content := `
# Multi-stage build
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN go build

FROM alpine:3.19
COPY --from=builder /src/app /usr/bin/app
CMD ["app"]

FROM scratch
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	imgs, err := extractImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Should pick up golang:1.22-alpine + alpine:3.19 (skip scratch)
	if len(imgs) != 2 {
		t.Fatalf("expected 2 images, got %d: %v", len(imgs), imgs)
	}
	want := map[string]bool{"golang:1.22-alpine": true, "alpine:3.19": true}
	for _, img := range imgs {
		if !want[img] {
			t.Errorf("unexpected image: %s", img)
		}
	}
}

func TestParseCompose(t *testing.T) {
	dir := t.TempDir()
	content := `version: '3.8'
services:
  web:
    image: nginx:1.25
    ports:
      - "80:80"
  db:
    image: postgres:16-alpine
  cache:
    image: "redis:7"  # quoted
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	imgs, err := extractImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 3 {
		t.Fatalf("expected 3 images, got %d: %v", len(imgs), imgs)
	}
}

func TestCountArtifacts(t *testing.T) {
	output := `📦 Supply Chain Security Related artifacts for an image: alpine:3.19
└── 🍒 Signatures for an image tag
   └── 🔐 sha256:abcd1234
   └── 🔐 sha256:efgh5678
└── 💾 Attestations for an image tag
   └── 🔍 sha256:ijkl9012
`
	sig, att, sbom := countArtifacts(output)
	if sig != 2 {
		t.Errorf("expected 2 signatures, got %d", sig)
	}
	if att != 1 {
		t.Errorf("expected 1 attestation, got %d", att)
	}
	if sbom != 0 {
		t.Errorf("expected 0 SBOMs, got %d", sbom)
	}
}

func TestAdapterName(t *testing.T) {
	if New().Name() != "cosign" {
		t.Error("wrong name")
	}
}

func TestExtractImagesSkipsBackupDirs(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, ".phase1_backup_123")
	os.MkdirAll(backup, 0755)
	os.WriteFile(filepath.Join(backup, "Dockerfile"), []byte("FROM should-not-be-scanned:1.0"), 0644)

	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM legitimate:1.0"), 0644)

	imgs, err := extractImages(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range imgs {
		if img == "should-not-be-scanned:1.0" {
			t.Error("backup dir was scanned")
		}
	}
}
