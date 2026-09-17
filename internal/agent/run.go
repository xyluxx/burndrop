package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xyluxx/burndrop/internal/storage"
)

// RunInput is the run_with_secret input.
type RunInput struct {
	Command        []string          `json:"command" jsonschema:"the program and its arguments, for example [\"aws\",\"sts\",\"get-caller-identity\"]"`
	Env            map[string]string `json:"env,omitempty" jsonschema:"environment variable name to secret name, for example {\"OPENAI_API_KEY\":\"openai-api-key\"}"`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"working directory"`
	Stdin          string            `json:"stdin,omitempty" jsonschema:"text to write to the program's standard input"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"default 120, maximum 3600"`
	CaptureAs      *CaptureSpec      `json:"capture_as,omitempty" jsonschema:"store the program's output as a new secret instead of returning it"`
	DiscardOutput  bool              `json:"discard_output,omitempty" jsonschema:"return only the exit code"`
	Consume        bool              `json:"consume,omitempty" jsonschema:"delete the used secrets after the run"`
}

// CaptureSpec describes how to turn command output into a stored secret.
type CaptureSpec struct {
	Name      string `json:"name" jsonschema:"name for the new secret"`
	Pattern   string `json:"pattern,omitempty" jsonschema:"optional regular expression with one capture group applied to standard output; default is the whole trimmed output"`
	Retention string `json:"retention,omitempty" jsonschema:"session, until-revoked, or until:<date>; default from the config file"`
	Purpose   string `json:"purpose,omitempty" jsonschema:"what the captured secret is"`
}

// RunOutput is the run_with_secret output.
type RunOutput struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	StoredAs   string `json:"stored_as,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Message    string `json:"message,omitempty"`
}

const (
	defaultRunTimeout = 120 * time.Second
	maxRunTimeout     = time.Hour
	maxCapturedBytes  = 1 << 20
)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)

// Run executes a command with secrets injected as environment variables.
// The model receives redacted, truncated output; with capture_as it
// receives no output at all.
func (a *Agent) Run(ctx context.Context, in RunInput) (RunOutput, error) {
	if len(in.Command) == 0 || strings.TrimSpace(in.Command[0]) == "" {
		return RunOutput{}, errors.New("command must have at least the program name")
	}
	if err := a.allowed(in.Command[0]); err != nil {
		return RunOutput{}, err
	}
	if in.CaptureAs != nil {
		if err := storage.ValidateName(in.CaptureAs.Name); err != nil {
			return RunOutput{}, err
		}
		if in.CaptureAs.Pattern != "" {
			re, err := regexp.Compile(in.CaptureAs.Pattern)
			if err != nil {
				return RunOutput{}, fmt.Errorf("capture_as.pattern: %w", err)
			}
			if re.NumSubexp() != 1 {
				return RunOutput{}, errors.New("capture_as.pattern must have exactly one capture group")
			}
		}
		retention := in.CaptureAs.Retention
		if retention == "" {
			retention = a.Config.Retention()
		}
		if _, err := storage.ParseRetention(retention, a.Now()); err != nil {
			return RunOutput{}, err
		}
	}
	timeout := defaultRunTimeout
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	if timeout > maxRunTimeout {
		timeout = maxRunTimeout
	}
	// Resolve secrets before starting anything.
	names := make([]string, 0, len(in.Env))
	injected := make([]string, 0, len(in.Env))
	for envName, secretName := range in.Env {
		if !envNameRe.MatchString(envName) {
			return RunOutput{}, fmt.Errorf("%q is not a valid environment variable name", envName)
		}
		if err := storage.ValidateName(secretName); err != nil {
			return RunOutput{}, err
		}
		value, meta, err := a.Store.Get(ctx, secretName)
		if err != nil {
			return RunOutput{}, fmt.Errorf("secret %s: %w", secretName, err)
		}
		if isInternalKind(meta.Kind) {
			storage.Zero(value)
			return RunOutput{}, fmt.Errorf("secret %s: %w", secretName, storage.ErrNotFound)
		}
		a.Redactor.Add(secretName, value)
		injected = append(injected, envName+"="+string(value))
		storage.Zero(value)
		names = append(names, secretName)
	}
	env := make([]string, 0, len(os.Environ())+len(injected))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if _, override := in.Env[k]; !override {
			env = append(env, kv)
		}
	}
	env = append(env, injected...)

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(rctx, in.Command[0], in.Command[1:]...)
	cmd.Env = env
	cmd.Dir = in.Cwd
	if in.Stdin != "" {
		cmd.Stdin = strings.NewReader(in.Stdin)
	}
	stdout := &limitedBuffer{max: maxCapturedBytes}
	stderr := &limitedBuffer{max: maxCapturedBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	start := a.Now()
	runErr := cmd.Run()
	out := RunOutput{DurationMs: a.Now().Sub(start).Milliseconds()}
	for i := range injected {
		injected[i] = ""
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		out.ExitCode = 0
	case errors.As(runErr, &exitErr):
		out.ExitCode = exitErr.ExitCode()
	case errors.Is(rctx.Err(), context.DeadlineExceeded):
		out.ExitCode = -1
		out.TimedOut = true
	default:
		a.log(Event{Event: "run_with_secret", Name: filepath.Base(in.Command[0]), Result: "start_failed", Detail: a.Redactor.Redact(runErr.Error()), Fields: map[string]string{"secrets": strings.Join(names, ",")}})
		return RunOutput{}, fmt.Errorf("could not start %s: %s", in.Command[0], a.Redactor.Redact(runErr.Error()))
	}
	if errors.Is(rctx.Err(), context.DeadlineExceeded) {
		out.TimedOut = true
	}
	if in.Consume {
		for _, n := range names {
			_ = a.Store.Delete(ctx, n)
		}
	}
	fields := map[string]string{"exit_code": fmt.Sprint(out.ExitCode), "secrets": strings.Join(names, ","), "duration_ms": fmt.Sprint(out.DurationMs)}
	if in.CaptureAs != nil {
		raw := stdout.Bytes()
		captured, err := extractCapture(raw, in.CaptureAs.Pattern)
		if err != nil {
			a.log(Event{Event: "run_with_secret", Name: filepath.Base(in.Command[0]), Result: "capture_failed", Detail: err.Error(), Fields: fields})
			out.Message = "The command ran but nothing matched capture_as.pattern; nothing was stored."
			out.Stderr = a.truncate(a.Redactor.Redact(stderr.String()), &out.Truncated)
			return out, nil
		}
		retention := in.CaptureAs.Retention
		if retention == "" {
			retention = a.Config.Retention()
		}
		meta, err := a.Store.Put(ctx, in.CaptureAs.Name, captured, storage.Metadata{Retention: retention, Purpose: in.CaptureAs.Purpose, Source: storage.SourceCapture, Sendable: true})
		if err != nil {
			storage.Zero(captured)
			return RunOutput{}, fmt.Errorf("could not store the captured output: %w", err)
		}
		a.Redactor.Add(in.CaptureAs.Name, captured)
		storage.Zero(captured)
		out.StoredAs = in.CaptureAs.Name
		out.Message = fmt.Sprintf("Stored the command output as %s (%d bytes) in %s. It is marked sendable, so send_secret can hand it to a human.", in.CaptureAs.Name, meta.SizeBytes, meta.Backend)
		fields["stored_as"] = in.CaptureAs.Name
		out.Stderr = a.truncate(a.Redactor.Redact(stderr.String()), &out.Truncated)
		a.log(Event{Event: "run_with_secret", Name: filepath.Base(in.Command[0]), Result: "captured", Fields: fields})
		return out, nil
	}
	if !in.DiscardOutput {
		out.Stdout = a.truncate(a.Redactor.Redact(stdout.String()), &out.Truncated)
		out.Stderr = a.truncate(a.Redactor.Redact(stderr.String()), &out.Truncated)
	}
	if out.TimedOut {
		out.Message = fmt.Sprintf("The command was stopped after %s.", timeout)
	}
	a.log(Event{Event: "run_with_secret", Name: filepath.Base(in.Command[0]), Result: "ran", Fields: fields})
	return out, nil
}

func (a *Agent) allowed(program string) error {
	allowed := a.Config.RunWithSecret.AllowedCommands
	if len(allowed) == 0 {
		return nil
	}
	base := filepath.Base(program)
	for _, p := range allowed {
		if p == program || p == base || strings.TrimSuffix(base, filepath.Ext(base)) == p {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrNotAllowed, base)
}

func (a *Agent) truncate(s string, flag *bool) string {
	max := a.Config.MaxOutput()
	if len(s) > max {
		*flag = true
		return s[:max] + "\n[truncated]"
	}
	return s
}

func extractCapture(raw []byte, pattern string) ([]byte, error) {
	if pattern == "" {
		v := bytes.TrimSpace(raw)
		if len(v) == 0 {
			return nil, errors.New("the command printed nothing")
		}
		if len(v) > storage.MaxValueBytes {
			return nil, storage.ErrTooLarge
		}
		return append([]byte(nil), v...), nil
	}
	re := regexp.MustCompile(pattern)
	m := re.FindSubmatch(raw)
	if m == nil || len(m) < 2 || len(m[1]) == 0 {
		return nil, errors.New("no match")
	}
	if len(m[1]) > storage.MaxValueBytes {
		return nil, storage.ErrTooLarge
	}
	return append([]byte(nil), m[1]...), nil
}

// limitedBuffer keeps the first max bytes and drops the rest.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		l.buf.Write(p)
	}
	return n, nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }
func (l *limitedBuffer) Bytes() []byte  { return l.buf.Bytes() }
