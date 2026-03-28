package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ExecResult holds the raw output from a tool invocation.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// Run executes binary with args under ctx.
// It returns an error only for fatal failures (binary not found, context
// cancelled). Non-zero exit codes from security tools are NOT treated as
// errors because most tools exit non-zero when they find issues.
func Run(ctx context.Context, binary string, args ...string) (ExecResult, error) {
	// Verify tool exists before spawning
	if _, err := exec.LookPath(binary); err != nil {
		return ExecResult{}, ErrToolNotFound{Tool: binary}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	res := ExecResult{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if cmd.ProcessState != nil {
		res.Exit = cmd.ProcessState.ExitCode()
	}

	// Context cancellation is a hard error
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s: %w (stderr: %s)", binary, ctx.Err(), truncate(stderr.String(), 200))
	}

	// Binary not found / permission error
	if err != nil && res.Exit == -1 {
		return res, fmt.Errorf("%s: failed to start: %w", binary, err)
	}

	return res, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
