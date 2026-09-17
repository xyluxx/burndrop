package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xyluxx/burndrop/internal/storage"
)

// shell returns a command prefix that runs a script string on this platform.
func shell(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err == nil {
		return []string{"sh", "-c"}
	}
	if _, err := exec.LookPath("cmd"); err == nil {
		return []string{"cmd", "/c"}
	}
	t.Skip("no shell available")
	return nil
}

func TestRunWithSecret(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent
	sh := shell(t)
	unix := sh[0] == "sh"
	if _, err := a.Store.Put(ctx, "api-key", []byte("super-secret-value"), storage.Metadata{Retention: storage.RetentionUntilRevoked}); err != nil {
		t.Fatal(err)
	}

	// Validation.
	if _, err := a.Run(ctx, RunInput{}); err == nil {
		t.Fatal("empty command")
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"x"}, Env: map[string]string{"1BAD": "api-key"}}); err == nil {
		t.Fatal("bad env name")
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"x"}, Env: map[string]string{"K": "missing"}}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"x"}, CaptureAs: &CaptureSpec{Name: "bad name"}}); !errors.Is(err, storage.ErrInvalidName) {
		t.Fatalf("capture name: %v", err)
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"x"}, CaptureAs: &CaptureSpec{Name: "c", Pattern: "("}}); err == nil {
		t.Fatal("bad pattern")
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"x"}, CaptureAs: &CaptureSpec{Name: "c", Pattern: "no group"}}); err == nil {
		t.Fatal("pattern without group")
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"x"}, CaptureAs: &CaptureSpec{Name: "c", Retention: "never"}}); !errors.Is(err, storage.ErrRetention) {
		t.Fatalf("capture retention: %v", err)
	}
	if _, err := a.Run(ctx, RunInput{Command: []string{"definitely-not-a-program-xyz"}}); err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("start failure: %v", err)
	}

	// The secret reaches the child and is redacted on the way back.
	echo := "echo key=$API_KEY; echo err=$API_KEY 1>&2"
	if !unix {
		echo = "echo key=%API_KEY%& echo err=%API_KEY% 1>&2"
	}
	out, err := a.Run(ctx, RunInput{Command: append(sh, echo), Env: map[string]string{"API_KEY": "api-key"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 || !strings.Contains(out.Stdout, "key=[redacted:api-key]") || !strings.Contains(out.Stderr, "err=[redacted:api-key]") || strings.Contains(out.Stdout, "super-secret") {
		t.Fatalf("run output: %+v", out)
	}
	// Base64 of the value is redacted too.
	b64 := "c3VwZXItc2VjcmV0LXZhbHVl"
	out, _ = a.Run(ctx, RunInput{Command: append(sh, "echo "+b64), Env: map[string]string{"API_KEY": "api-key"}})
	if strings.Contains(out.Stdout, b64) {
		t.Fatalf("base64 form leaked: %s", out.Stdout)
	}
	// Exit codes and discard_output.
	out, err = a.Run(ctx, RunInput{Command: append(sh, "exit 3"), DiscardOutput: true})
	if err != nil || out.ExitCode != 3 || out.Stdout != "" {
		t.Fatalf("exit code: %v %+v", err, out)
	}
	// Output truncation.
	a.Config.RunWithSecret.MaxOutputBytes = 50
	big := "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	out, _ = a.Run(ctx, RunInput{Command: append(sh, big)})
	if !out.Truncated || len(out.Stdout) > 70 {
		t.Fatalf("truncate: %+v", out)
	}
	a.Config.RunWithSecret.MaxOutputBytes = 0
	// Timeout.
	sleep := "sleep 5"
	if !unix {
		sleep = "ping -n 6 127.0.0.1 > nul"
	}
	out, err = a.Run(ctx, RunInput{Command: append(sh, sleep), TimeoutSeconds: 1})
	if err != nil || !out.TimedOut || out.ExitCode == 0 && !out.TimedOut {
		t.Fatalf("timeout: %v %+v", err, out)
	}
	// Allowed commands.
	a.Config.RunWithSecret.AllowedCommands = []string{"git"}
	if _, err := a.Run(ctx, RunInput{Command: append(sh, "echo hi")}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("allowlist: %v", err)
	}
	a.Config.RunWithSecret.AllowedCommands = []string{sh[0]}
	if _, err := a.Run(ctx, RunInput{Command: append(sh, "echo hi")}); err != nil {
		t.Fatalf("allowlisted: %v", err)
	}
	a.Config.RunWithSecret.AllowedCommands = nil

	// capture_as stores the output and returns none of it.
	gen := "echo generated-token-abc123"
	out, err = a.Run(ctx, RunInput{Command: append(sh, gen), CaptureAs: &CaptureSpec{Name: "new-token", Purpose: "made by the test"}})
	if err != nil || out.StoredAs != "new-token" || out.Stdout != "" || !strings.Contains(out.Message, "sendable") {
		t.Fatalf("capture: %v %+v", err, out)
	}
	v, meta, err := a.Store.Get(ctx, "new-token")
	if err != nil || string(v) != "generated-token-abc123" || !meta.Sendable || meta.Source != storage.SourceCapture || meta.Purpose != "made by the test" {
		t.Fatalf("captured value: %v %q %+v", err, v, meta)
	}
	if got := a.Redactor.Redact("generated-token-abc123"); got != "[redacted:new-token]" {
		t.Fatalf("captured value not redacted: %q", got)
	}
	// capture_as with a pattern.
	out, err = a.Run(ctx, RunInput{Command: append(sh, "echo AccessKeyId: AKIAEXAMPLE1234567 done"), CaptureAs: &CaptureSpec{Name: "aws-key", Pattern: `AccessKeyId: (\S+)`, Retention: storage.RetentionSession}})
	if err != nil || out.StoredAs != "aws-key" {
		t.Fatalf("pattern capture: %v %+v", err, out)
	}
	if v, meta, _ := a.Store.Get(ctx, "aws-key"); string(v) != "AKIAEXAMPLE1234567" || meta.Retention != storage.RetentionSession {
		t.Fatalf("pattern value: %q %+v", v, meta)
	}
	// No match stores nothing.
	out, err = a.Run(ctx, RunInput{Command: append(sh, "echo nothing here"), CaptureAs: &CaptureSpec{Name: "none", Pattern: `Key=(\d+)`}})
	if err != nil || out.StoredAs != "" || !strings.Contains(out.Message, "nothing matched") {
		t.Fatalf("no match: %v %+v", err, out)
	}
	if _, _, err := a.Store.Get(ctx, "none"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("stored on no match")
	}
	out, _ = a.Run(ctx, RunInput{Command: append(sh, "exit 0"), CaptureAs: &CaptureSpec{Name: "empty"}})
	if out.StoredAs != "" {
		t.Fatal("empty output captured")
	}
	// consume deletes the used secrets afterwards.
	_, _ = a.Store.Put(ctx, "once", []byte("one-time-value"), storage.Metadata{Retention: storage.RetentionSession})
	if _, err := a.Run(ctx, RunInput{Command: append(sh, "exit 0"), Env: map[string]string{"ONCE": "once"}, Consume: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Store.Get(ctx, "once"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("consumed secret still present")
	}
	// Pending records cannot be injected.
	r, _ := a.Request(ctx, RequestInput{Name: "req", Purpose: "p"})
	if _, err := a.Run(ctx, RunInput{Command: append(sh, "exit 0"), Env: map[string]string{"P": "pending." + r.RequestID}}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("pending injected: %v", err)
	}
	// Working directory and stdin.
	dir := t.TempDir()
	pwd := "pwd"
	if !unix {
		pwd = "cd"
	}
	out, err = a.Run(ctx, RunInput{Command: append(sh, pwd), Cwd: dir})
	if err != nil || !strings.Contains(out.Stdout, filepath.Base(dir)) || !strings.Contains(out.Stdout, filepath.Base(filepath.Dir(dir))) {
		t.Fatalf("cwd: %v %+v", err, out)
	}
	if unix {
		out, err = a.Run(ctx, RunInput{Command: append(sh, "cat"), Stdin: "from stdin"})
		if err != nil || !strings.Contains(out.Stdout, "from stdin") {
			t.Fatalf("stdin: %v %+v", err, out)
		}
	}
	// The audit log never contains values.
	raw, _ := os.ReadFile(h.audit.Path())
	for _, secret := range []string{"super-secret", "generated-token", "AKIAEXAMPLE", "one-time-value"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
	if !strings.Contains(string(raw), `"run_with_secret"`) {
		t.Fatal("audit missing run events")
	}
}

func TestLimitedBufferAndExtract(t *testing.T) {
	b := &limitedBuffer{max: 5}
	n, _ := b.Write([]byte("hello world"))
	if n != 11 || b.String() != "hello" {
		t.Fatalf("limited buffer: %d %q", n, b.String())
	}
	if _, err := extractCapture([]byte("   \n"), ""); err == nil {
		t.Fatal("blank output")
	}
	if v, err := extractCapture([]byte("  token \n"), ""); err != nil || string(v) != "token" {
		t.Fatalf("trim: %v %q", err, v)
	}
	if _, err := extractCapture(make([]byte, storage.MaxValueBytes+10), ""); !errors.Is(err, storage.ErrTooLarge) {
		t.Fatal("too large")
	}
	if _, err := extractCapture([]byte("k=v"), `k=(\d+)`); err == nil {
		t.Fatal("no match")
	}
}
