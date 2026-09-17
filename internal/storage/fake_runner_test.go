package storage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeCall records one command execution made through fakeRunner.
type fakeCall struct {
	Name  string
	Args  []string
	Stdin []byte
	Env   []string
}

// fakeRunner is the Runner used by backend tests. A handler simulates the
// vendor CLI; every call is recorded so tests can assert that no secret
// value was ever passed as an argument.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []fakeCall
	missing map[string]bool
	handler func(call fakeCall) ([]byte, error)
}

func newFakeRunner(handler func(call fakeCall) ([]byte, error)) *fakeRunner {
	return &fakeRunner{handler: handler, missing: map[string]bool{}}
}

// setMissing makes LookPath fail for name, simulating an uninstalled CLI.
func (f *fakeRunner) setMissing(name string, missing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.missing[name] = missing
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing[name] {
		return "", errors.New("executable file not found in PATH")
	}
	return "/usr/local/bin/" + name, nil
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin []byte, extraEnv []string) ([]byte, error) {
	call := fakeCall{Name: name, Args: append([]string(nil), args...), Stdin: append([]byte(nil), stdin...), Env: append([]string(nil), extraEnv...)}
	f.mu.Lock()
	if f.missing[name] {
		f.mu.Unlock()
		return nil, errors.New("executable file not found in PATH")
	}
	f.calls = append(f.calls, call)
	handler := f.handler
	f.mu.Unlock()
	return handler(call)
}

// Calls returns a copy of every recorded call.
func (f *fakeRunner) Calls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// assertNoSecretInArgs fails the test if any recorded call carried secret
// (or its standard base64 form) in its arguments or environment.
func (f *fakeRunner) assertNoSecretInArgs(t *testing.T, secret []byte) {
	t.Helper()
	if len(secret) == 0 {
		return
	}
	for _, c := range f.Calls() {
		for _, a := range c.Args {
			if bytes.Contains([]byte(a), secret) {
				t.Fatalf("secret value passed as an argument to %s: %q", c.Name, strings.Join(c.Args, " "))
			}
		}
		for _, e := range c.Env {
			if bytes.Contains([]byte(e), secret) {
				t.Fatalf("secret value passed in the environment of %s", c.Name)
			}
		}
	}
}

// exitError builds the error ExecRunner would return for a failed command.
func exitError(name string, code int, stderr string) error {
	return &ExitError{Command: name, Code: code, Stderr: stderr}
}
