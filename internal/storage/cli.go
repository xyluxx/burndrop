package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runner executes an external command. Backends that drive a vendor CLI use
// it so tests can substitute a fake. Secret values are only ever passed on
// standard input or through files with mode 0600, never as arguments, because
// arguments are visible to every process on the machine.
type Runner interface {
	// Run executes name with args. stdin is written to the process (nil for
	// none). extraEnv entries are added to the inherited environment.
	Run(ctx context.Context, name string, args []string, stdin []byte, extraEnv []string) (stdout []byte, err error)
	// LookPath reports the absolute path of a command or an error.
	LookPath(name string) (string, error)
}

// ExitError is returned when the command exits non-zero. Stderr is truncated
// and is never fed back through a secret value.
type ExitError struct {
	Command string
	Code    int
	Stderr  string
}

func (e *ExitError) Error() string {
	msg := fmt.Sprintf("%s exited with code %d", e.Command, e.Code)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

// ExecRunner runs real commands with a timeout.
type ExecRunner struct {
	Timeout time.Duration // 0 means 60 seconds
}

const maxStderr = 2000

func (r ExecRunner) Run(ctx context.Context, name string, args []string, stdin []byte, extraEnv []string) ([]byte, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > maxStderr {
			msg = msg[:maxStderr] + "..."
		}
		return stdout.Bytes(), &ExitError{Command: name, Code: exit.ExitCode(), Stderr: msg}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return nil, fmt.Errorf("%s: %w", name, err)
}

func (ExecRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// classifyExit turns a vendor CLI failure into a storage error where the
// stderr text makes the cause clear, and otherwise wraps it.
func classifyExit(err error, notFoundHints ...string) error {
	if err == nil {
		return nil
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		low := strings.ToLower(exit.Stderr)
		for _, h := range notFoundHints {
			if h != "" && strings.Contains(low, strings.ToLower(h)) {
				return ErrNotFound
			}
		}
		switch {
		case strings.Contains(low, "not signed in"), strings.Contains(low, "unauthorized"), strings.Contains(low, "unauthenticated"),
			strings.Contains(low, "access denied"), strings.Contains(low, "accessdenied"), strings.Contains(low, "permission denied"),
			strings.Contains(low, "forbidden"), strings.Contains(low, "vault is locked"), strings.Contains(low, "not logged in"):
			return fmt.Errorf("%w: %v", ErrPermission, err)
		}
	}
	return err
}
