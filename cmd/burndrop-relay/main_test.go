package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/relay"
)

// capture returns a file to use as stdout or stderr and a function that
// reads what was written to it.
func capture(t *testing.T) (*os.File, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, func() string {
		_ = f.Sync()
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestRunDispatch(t *testing.T) {
	stdout, out := capture(t)
	stderr, errOut := capture(t)
	if code := run([]string{"version"}, envOf(nil), stdout, stderr); code != 0 || !strings.Contains(out(), "burndrop-relay dev") {
		t.Fatalf("version: %d %q", code, out())
	}
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		stdout, out := capture(t)
		if code := run(args, envOf(nil), stdout, stderr); code != 0 || !strings.Contains(out(), "Commands:") {
			t.Fatalf("%v: %d %q", args, code, out())
		}
	}
	if code := run([]string{"bogus"}, envOf(nil), stdout, stderr); code != 2 || !strings.Contains(errOut(), "unknown command") {
		t.Fatalf("unknown: %d %q", code, errOut())
	}
	// A flag as the first argument means the default command.
	if code := run([]string{"-x"}, envOf(nil), stdout, stderr); code != 2 {
		t.Fatalf("serve with bad flag: %d", code)
	}
}

func TestKeygen(t *testing.T) {
	stdout, out := capture(t)
	stderr, errOut := capture(t)
	if code := keygen([]string{"-id", "ops"}, stdout, stderr); code != 0 {
		t.Fatalf("keygen: %d %s", code, errOut())
	}
	text := out()
	if !strings.Contains(text, `Agent key for "ops"`) || !strings.Contains(text, "BURNDROP_AGENT_KEYS=ops:sha256:") {
		t.Fatalf("keygen output: %q", text)
	}
	// The printed config entry parses and matches the printed key.
	var key, entry string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "BURNDROP_AGENT_KEYS="):
			entry = strings.TrimPrefix(line, "BURNDROP_AGENT_KEYS=")
		case len(line) == 43 && !strings.ContainsAny(line, " :"):
			key = line
		}
	}
	if key == "" || entry == "" {
		t.Fatalf("could not find key and entry in %q", text)
	}
	keys, err := relay.ParseAgentKeys(entry)
	if err != nil || len(keys) != 1 || relay.FormatAgentKey("ops", key) != entry {
		t.Fatalf("entry %q does not match key: %v", entry, err)
	}
	for _, bad := range [][]string{{"-id", ""}, {"-id", "a:b"}, {"-id", "a b"}, {"-bogus"}} {
		if code := keygen(bad, stdout, stderr); code != 2 {
			t.Fatalf("keygen %v: %d", bad, code)
		}
	}
}

func TestServeBadConfig(t *testing.T) {
	stderr, errOut := capture(t)
	if code := serveContext(context.Background(), nil, envOf(nil), stderr); code != 2 || !strings.Contains(errOut(), "PUBLIC_ORIGIN") {
		t.Fatalf("missing origin: %d %q", code, errOut())
	}
	env := map[string]string{"BURNDROP_PUBLIC_ORIGIN": "https://relay.example", "BURNDROP_AGENT_AUTH": "off", "BURNDROP_STORE": "redis", "BURNDROP_REDIS_URL": "redis://127.0.0.1:1/0"}
	stderr, errOut = capture(t)
	if code := serveContext(context.Background(), nil, envOf(env), stderr); code != 1 {
		t.Fatalf("unreachable redis must fail to start: %d %q", code, errOut())
	}
	if code := serveContext(context.Background(), []string{"-nope"}, envOf(env), stderr); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
}

func TestServeAndHealthcheck(t *testing.T) {
	addr := freePort(t)
	env := map[string]string{
		"BURNDROP_LISTEN":        addr,
		"BURNDROP_PUBLIC_ORIGIN": "http://localhost",
		"BURNDROP_AGENT_AUTH":    "off",
		"BURNDROP_LOG_FORMAT":    "json",
		"BURNDROP_LOG_LEVEL":     "debug",
	}
	stderr, errOut := capture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- serveContext(ctx, nil, envOf(env), stderr) }()

	// Wait for the listener, using the healthcheck subcommand itself.
	hcErr, hcOut := capture(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if healthcheck(envOf(env), hcErr) == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("relay never became healthy: %s\n%s", hcOut(), errOut())
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp, err := http.Get("http://" + addr + "/drop")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("page status %d", resp.StatusCode)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d: %s", code, errOut())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
	log := errOut()
	if !strings.Contains(log, "relay started") || !strings.Contains(log, "shutting down") {
		t.Fatalf("log: %s", log)
	}
	// The listener is gone, so the probe fails, and other error paths report.
	if code := healthcheck(envOf(env), hcErr); code != 1 {
		t.Fatalf("healthcheck after stop: %d", code)
	}
	if code := healthcheck(envOf(map[string]string{"BURNDROP_LISTEN": "nonsense"}), hcErr); code != 2 {
		t.Fatalf("healthcheck bad listen: %d", code)
	}
	// A wildcard listen address probes the loopback interface; nothing listens there.
	if code := healthcheck(envOf(map[string]string{"BURNDROP_LISTEN": ":" + strings.TrimPrefix(addr, "127.0.0.1:")}), hcErr); code != 1 {
		t.Fatalf("healthcheck wildcard: %d", code)
	}
	// A server that answers but not with 200 is unhealthy.
	bad := &http.Server{Addr: freePort(t), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })}
	go func() { _ = bad.ListenAndServe() }()
	defer func() { _ = bad.Close() }()
	time.Sleep(100 * time.Millisecond)
	if code := healthcheck(envOf(map[string]string{"BURNDROP_LISTEN": bad.Addr}), hcErr); code != 1 || !strings.Contains(hcOut(), "status") {
		t.Fatalf("healthcheck 503: %d %s", code, hcOut())
	}
}

func TestListenFailure(t *testing.T) {
	// Occupy a port, then ask the relay to listen on it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	env := map[string]string{"BURNDROP_LISTEN": l.Addr().String(), "BURNDROP_PUBLIC_ORIGIN": "http://localhost", "BURNDROP_AGENT_AUTH": "off"}
	stderr, errOut := capture(t)
	if code := serveContext(context.Background(), nil, envOf(env), stderr); code != 1 || !strings.Contains(errOut(), "listen") {
		t.Fatalf("busy port: %d %s", code, errOut())
	}
}

func TestNewLoggerLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		for _, format := range []string{"text", "json"} {
			cfg := relay.DefaultConfig()
			cfg.LogLevel = level
			cfg.LogFormat = format
			f, out := capture(t)
			logger := newLogger(cfg, f)
			logger.Error("probe", "k", "v")
			if !strings.Contains(out(), "probe") {
				t.Fatalf("%s/%s: %q", level, format, out())
			}
			if format == "json" && !strings.HasPrefix(strings.TrimSpace(out()), "{") {
				t.Fatalf("json format: %q", out())
			}
		}
	}
}
