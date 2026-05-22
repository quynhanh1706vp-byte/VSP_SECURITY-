package racedetect

import (
	"strings"
	"testing"
)

func TestParseRaceBlock(t *testing.T) {
	block := `
Read at 0x00c000123456 by goroutine 7:
  main.handler()
      /home/test/main.go:42

Previous write at 0x00c000123456 by goroutine 6:
  main.writer()
      /home/test/main.go:35
`
	f := parseRaceBlock(block)
	if !strings.Contains(f.Title, "Data race") {
		t.Errorf("expected Data race title, got: %s", f.Title)
	}
}
