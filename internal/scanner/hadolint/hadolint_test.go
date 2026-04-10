package hadolint

import (
	"context"
	"os"
	"path/filepath"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsp/platform/internal/scanner"
)

func TestAdapter_Name(t *testing.T) {
	a := New()
	assert.Equal(t, "hadolint", a.Name())
}

func TestAdapter_NoSrc(t *testing.T) {
	a := New()
	findings, err := a.Run(context.Background(), scanner.RunOpts{})
	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func TestAdapter_NoDockerfiles(t *testing.T) {
	tmp := t.TempDir()
	a := New()
	findings, err := a.Run(context.Background(), scanner.RunOpts{Src: tmp})
	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func TestAdapter_FindsDockerfile(t *testing.T) {
	if _, err := exec.LookPath("hadolint"); err != nil {
		t.Skip("hadolint not installed")
	}
	tmp := t.TempDir()
	df := filepath.Join(tmp, "Dockerfile")
	os.WriteFile(df, []byte("FROM ubuntu:latest\nRUN apt-get install curl\n"), 0644)
	a := New()
	findings, err := a.Run(context.Background(), scanner.RunOpts{Src: tmp})
	assert.NoError(t, err)
	// :latest → DL3007, no pin → DL3008
	assert.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "hadolint", f.Tool)
		assert.Equal(t, scanner.SourceIAC, f.Category)
	}
}

func TestParseJSON_Valid(t *testing.T) {
	data := `[{"line":1,"column":1,"level":"warning","code":"DL3007","message":"Using latest is bad","file":"Dockerfile"}]`
	findings, err := parseJSON([]byte(data), "Dockerfile")
	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "DL3007", findings[0].RuleID)
	assert.Equal(t, scanner.SevMedium, findings[0].Severity)
	assert.Equal(t, scanner.SourceIAC, findings[0].Category)
}

func TestParseJSON_SkipsStyle(t *testing.T) {
	data := `[{"line":1,"level":"style","code":"DL3040","message":"style issue","file":"Dockerfile"}]`
	findings, _ := parseJSON([]byte(data), "Dockerfile")
	assert.Empty(t, findings) // style findings skipped
}
