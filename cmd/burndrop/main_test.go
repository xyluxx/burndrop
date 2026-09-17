package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/internal/relay"
)

const testKey = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

type cli struct {
	t      *testing.T
	env    map[string]string
	relay  *httptest.Server
	dir    string
	stdin  string
	secret string // answer for hidden prompts
	yes    bool   // answer for confirmations
	term   bool
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	return newCLIWith(t, nil)
}

// newCLIWith lets a test adjust the relay configuration, for example to run
// the relay without agent auth.
func newCLIWith(t *testing.T, mutate func(*relay.Config)) *cli {
	t.Helper()
	keyring.MockInit()
	cfg := relay.DefaultConfig()
	cfg.PublicOrigin = "http://127.0.0.1"
	cfg.AgentKeys = []relay.AgentKey{{ID: "test", Hash: crypto.HashToken(testKey)}}
	cfg.RateAgentPerMin = 10000
	cfg.RatePagePerMin = 10000
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := relay.NewStore(cfg, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.New(cfg, store, relay.Options{Version: "test"}).Handler())
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	c := &cli{t: t, relay: srv, dir: dir, env: map[string]string{
		"BURNDROP_CONFIG":    filepath.Join(dir, "config.toml"),
		"BURNDROP_STATE_DIR": filepath.Join(dir, "state"),
		"BURNDROP_API_KEY":   testKey,
		"PATH":               os.Getenv("PATH"),
		"OS":                 os.Getenv("OS"),
	}}
	return c
}

// run executes one command and returns exit code, stdout, stderr.
func (c *cli) run(args ...string) (int, string, string) {
	c.t.Helper()
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(c.stdin), &stdout, &stderr, func(k string) string { return c.env[k] })
	a.version = "test"
	a.isTerminal = func() bool { return c.term }
	a.readSecret = func(string) ([]byte, error) { return []byte(c.secret), nil }
	kc := map[string]string{}
	a.keychainGet = func(_, entry string) (string, error) {
		v, ok := kc[entry]
		if !ok {
			return "", os.ErrNotExist
		}
		return v, nil
	}
	a.keychainSet = func(_, entry, value string) error { kc[entry] = value; return nil }
	if c.yes {
		c.stdin = "y\n"
	}
	code := a.run(args)
	return code, stdout.String(), stderr.String()
}

func (c *cli) mustRun(args ...string) string {
	c.t.Helper()
	code, out, errOut := c.run(args...)
	if code != 0 {
		c.t.Fatalf("burndrop %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

func (c *cli) initialized() *cli {
	c.t.Helper()
	c.mustRun("init", "-relay", c.relay.URL, "-storage", "keychain", "-agent-key-from", "env", "-yes")
	return c
}

func shellArgs(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err == nil {
		return []string{"sh", "-c"}
	}
	if _, err := exec.LookPath("cmd"); err == nil {
		return []string{"cmd", "/c"}
	}
	t.Skip("no shell")
	return nil
}

func TestHelpAndVersion(t *testing.T) {
	c := newCLI(t)
	if code, out, _ := c.run(); code != 2 || !strings.Contains(out, "Agent side") {
		t.Fatalf("no args: %d %s", code, out)
	}
	if code, out, _ := c.run("help"); code != 0 || !strings.Contains(out, "verify-page") {
		t.Fatalf("help: %d", code)
	}
	if code, out, _ := c.run("version"); code != 0 || !strings.Contains(out, "burndrop test") {
		t.Fatalf("version: %d %s", code, out)
	}
	if code, _, errOut := c.run("bogus"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown: %d %s", code, errOut)
	}
	if code, _, _ := c.run("list", "-h"); code != 0 {
		t.Fatalf("flag help: %d", code)
	}
	if code, _, _ := c.run("list", "-bogus"); code != 2 {
		t.Fatalf("bad flag: %d", code)
	}
	if code, _, errOut := c.run("list"); code != 1 || !strings.Contains(errOut, "init") {
		t.Fatalf("before init: %d %s", code, errOut)
	}
	if code, _, _ := c.run("instructions", "-format", "mcp-json"); code != 0 {
		t.Fatal("instructions")
	}
	for _, f := range []string{"text", "claude", "cursor", "agents"} {
		if code, out, _ := c.run("instructions", "-format", f); code != 0 || !strings.Contains(out, "Never ask a human") {
			t.Fatalf("instructions %s", f)
		}
	}
	if code, _, _ := c.run("instructions", "-format", "nope"); code != 2 {
		t.Fatal("bad format")
	}
}

func TestInit(t *testing.T) {
	c := newCLI(t)
	if code, _, _ := c.run("init"); code != 2 {
		t.Fatal("init without relay must fail with usage")
	}
	if code, _, errOut := c.run("init", "-relay", "http://127.0.0.1:1", "-yes"); code != 1 || !strings.Contains(errOut, "did not answer") {
		t.Fatalf("unreachable relay: %d %s", code, errOut)
	}
	// Key stored in the keychain through the hidden prompt.
	c.secret = testKey
	out := c.mustRun("init", "-relay", c.relay.URL, "-storage", "keychain", "-yes")
	if !strings.Contains(out, "BACKEND") || !strings.Contains(out, "keychain") || !strings.Contains(out, "agent key stored in the keychain") {
		t.Fatalf("init output: %s", out)
	}
	cfgBytes, err := os.ReadFile(c.env["BURNDROP_CONFIG"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfgBytes), `storage = "keychain"`) || !strings.Contains(string(cfgBytes), `agent_key = "keychain:burndrop/agent-key"`) || strings.Contains(string(cfgBytes), testKey) {
		t.Fatalf("config:\n%s", cfgBytes)
	}
	// Explicit unknown backend and dotenv without the flag are refused.
	if code, _, errOut := c.run("init", "-relay", c.relay.URL, "-storage", "floppy", "-yes"); code != 1 || !strings.Contains(errOut, "unknown storage") {
		t.Fatalf("unknown backend: %d %s", code, errOut)
	}
	if code, _, errOut := c.run("init", "-relay", c.relay.URL, "-storage", "dotenv", "-agent-key-from", "env", "-yes"); code != 1 || !strings.Contains(errOut, "allow-dotenv") {
		t.Fatalf("dotenv guard: %d %s", code, errOut)
	}
	c.mustRun("init", "-relay", c.relay.URL, "-storage", "dotenv", "-allow-dotenv", "-agent-key-from", "env", "-yes")
	if code, _, _ := c.run("init", "-relay", c.relay.URL, "-storage", "memory", "-agent-key-from", "elsewhere", "-yes"); code != 1 {
		t.Fatal("bad key source")
	}
	c.secret = ""
	if code, _, errOut := c.run("init", "-relay", c.relay.URL, "-storage", "memory", "-yes"); code != 1 || !strings.Contains(errOut, "agent key is required") {
		t.Fatalf("empty key: %d %s", code, errOut)
	}
	// Recommendation path without -storage needs confirmation when interactive.
	c.term = true
	c.stdin = "n\n"
	c.secret = testKey
	if code, _, errOut := c.run("init", "-relay", c.relay.URL); code != 1 || !strings.Contains(errOut, "cancelled") {
		t.Fatalf("declined recommendation: %d %s", code, errOut)
	}
	c.stdin = "y\n"
	out = c.mustRun("init", "-relay", c.relay.URL)
	if !strings.Contains(out, "recommended:") {
		t.Fatalf("recommendation: %s", out)
	}
}

func TestAgentCommands(t *testing.T) {
	c := newCLI(t).initialized()
	sh := shellArgs(t)

	// request
	if code, _, _ := c.run("request"); code != 2 {
		t.Fatal("request without flags")
	}
	out := c.mustRun("request", "-name", "openai-api-key", "-purpose", "Call the OpenAI API", "-ttl", "30m", "-json")
	var req map[string]any
	if err := json.Unmarshal([]byte(out), &req); err != nil {
		t.Fatalf("request json: %v\n%s", err, out)
	}
	link, _ := req["link"].(string)
	reqID, _ := req["request_id"].(string)
	if !strings.HasPrefix(link, c.relay.URL+"/drop#") || reqID == "" {
		t.Fatalf("request output: %s", out)
	}
	if !strings.Contains(out, "&") || strings.Contains(out, "\\u0026") {
		t.Fatalf("json output must keep the link copyable: %s", out)
	}
	out = c.mustRun("request", "-name", "second", "-purpose", "Another one")
	if !strings.Contains(out, "request id:") || !strings.Contains(out, "/drop#") {
		t.Fatalf("request text: %s", out)
	}
	out = c.mustRun("pending")
	if !strings.Contains(out, "openai-api-key") || !strings.Contains(out, "second") {
		t.Fatalf("pending: %s", out)
	}
	c.mustRun("pending", "-json")

	// fetch while waiting exits non-zero so scripts can loop.
	if code, out, _ := c.run("fetch", reqID, "-wait", "1"); code != 1 || !strings.Contains(out, "waiting") {
		t.Fatalf("fetch waiting: %d %s", code, out)
	}
	// The human submits with the CLI, reading the value from stdin.
	c.stdin = "sk-live-value-42\n"
	out = c.mustRun("drop", link, "-yes")
	if !strings.Contains(out, "submitted openai-api-key") {
		t.Fatalf("drop: %s", out)
	}
	c.stdin = ""
	if code, _, errOut := c.run("drop", link, "-yes"); code != 1 || !strings.Contains(errOut, "no longer be used") {
		t.Fatalf("drop twice: %d %s", code, errOut)
	}
	if code, _, errOut := c.run("drop", "https://x.example/drop#garbage", "-yes"); code != 1 || !strings.Contains(errOut, "not a valid drop link") {
		t.Fatalf("bad link: %d %s", code, errOut)
	}
	if code, _, _ := c.run("drop"); code != 2 {
		t.Fatal("drop without link")
	}
	out = c.mustRun("fetch", reqID)
	if !strings.Contains(out, "stored:") {
		t.Fatalf("fetch: %s", out)
	}
	out = c.mustRun("list")
	if !strings.Contains(out, "openai-api-key") || strings.Contains(out, "sk-live") {
		t.Fatalf("list: %s", out)
	}
	c.mustRun("list", "-json")

	// run with the secret injected and redacted.
	echo := "echo key=$OPENAI_API_KEY"
	if sh[0] == "cmd" {
		echo = "echo key=%OPENAI_API_KEY%"
	}
	code, out, _ := c.run(append([]string{"run", "-env", "OPENAI_API_KEY=openai-api-key", "--"}, append(sh, echo)...)...)
	if code != 0 || !strings.Contains(out, "key=[redacted:openai-api-key]") {
		t.Fatalf("run: %d %s", code, out)
	}
	if code, _, _ := c.run(append([]string{"run", "--"}, append(sh, "exit 7")...)...); code != 7 {
		t.Fatalf("exit code passthrough: %d", code)
	}
	// Without "--" the program's own flags are not parsed by burndrop.
	if code, _, _ := c.run(append([]string{"run"}, append(sh, "exit 5")...)...); code != 5 {
		t.Fatalf("exit code without separator: %d", code)
	}
	if code, _, _ := c.run("run", "-env", "BAD"); code != 2 {
		t.Fatal("bad env flag")
	}
	if code, _, _ := c.run("run"); code != 2 {
		t.Fatal("run without command")
	}
	if code, _, errOut := c.run(append([]string{"run", "-env", "X=missing", "--"}, append(sh, "exit 0")...)...); code != 1 || !strings.Contains(errOut, "not found") {
		t.Fatalf("missing secret: %d %s", code, errOut)
	}
	// capture and send.
	code, out, errOut := c.run(append([]string{"run", "-capture-as", "gen-token", "--"}, append(sh, "echo generated-token-777")...)...)
	if code != 0 || strings.Contains(out, "generated") || !strings.Contains(errOut, "Stored the command output as gen-token") {
		t.Fatalf("capture: %d %s %s", code, out, errOut)
	}
	if code, _, errOut := c.run("send", "openai-api-key", "-yes"); code != 1 || !strings.Contains(errOut, "not marked sendable") {
		t.Fatalf("send non-sendable: %d %s", code, errOut)
	}
	if code, _, errOut := c.run("send", "gen-token"); code != 1 || !strings.Contains(errOut, "confirmation needed") {
		t.Fatalf("send without -yes non-interactive: %d %s", code, errOut)
	}
	out = c.mustRun("send", "gen-token", "-yes", "-json")
	var sent map[string]any
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatal(err)
	}
	revealLink, _ := sent["link"].(string)
	if !strings.Contains(revealLink, "/reveal#") {
		t.Fatalf("send: %s", out)
	}
	// The human opens it with the CLI.
	code, out, errOut = c.run("open", revealLink, "-yes")
	if code != 0 || strings.TrimSpace(out) != "generated-token-777" || !strings.Contains(errOut, "deleted") {
		t.Fatalf("open: %d %q %s", code, out, errOut)
	}
	if code, _, errOut := c.run("open", revealLink, "-yes"); code != 1 || !strings.Contains(errOut, "already used") {
		t.Fatalf("open twice: %d %s", code, errOut)
	}
	if code, _, _ := c.run("open"); code != 2 {
		t.Fatal("open without link")
	}
	if code, _, errOut := c.run("open", "https://x.example/reveal#v=2", "-yes"); code != 1 || !strings.Contains(errOut, "not a valid reveal link") {
		t.Fatalf("bad reveal link: %d %s", code, errOut)
	}
	out = c.mustRun("send", "gen-token", "-yes", "-delete-after")
	if !strings.Contains(out, "deleted my copy") {
		t.Fatalf("delete after: %s", out)
	}
	// delete, revoke, audit.
	c.mustRun("delete", "openai-api-key")
	if code, _, _ := c.run("delete", "openai-api-key"); code != 1 {
		t.Fatal("delete twice")
	}
	if code, _, _ := c.run("delete"); code != 2 {
		t.Fatal("delete without name")
	}
	pendingOut := c.mustRun("pending", "-json")
	var pending []map[string]any
	_ = json.Unmarshal([]byte(pendingOut), &pending)
	if len(pending) != 1 {
		t.Fatalf("pending after fetch: %s", pendingOut)
	}
	out = c.mustRun("revoke", pending[0]["request_id"].(string))
	if !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %s", out)
	}
	if code, _, _ := c.run("revoke"); code != 2 {
		t.Fatal("revoke without id")
	}
	if code, _, _ := c.run("revoke", "MTIzNDU2Nzg5MGFiY2RlZg"); code != 1 {
		t.Fatal("revoke unknown")
	}
	out = c.mustRun("audit")
	if !strings.Contains(out, "request_secret") || strings.Contains(out, "sk-live") || strings.Contains(out, "generated-token") {
		t.Fatalf("audit: %s", out)
	}
	c.mustRun("audit", "-json", "-n", "2")
	if out := c.mustRun("list"); !strings.Contains(out, "no stored secrets") {
		t.Fatalf("empty list: %s", out)
	}
	// doctor and verify-page (no page is embedded or served in tests).
	code, out, _ = c.run("doctor")
	if !strings.Contains(out, "ok    relay") || !strings.Contains(out, "backend probe") {
		t.Fatalf("doctor: %d %s", code, out)
	}
	if code, _, errOut := c.run("verify-page"); code != 1 || !strings.Contains(errOut, "could not fetch the page") {
		t.Fatalf("verify-page without a page: %d %s", code, errOut)
	}
	if code, _, _ := c.run("verify-page", "-relay", "not a url"); code != 1 {
		t.Fatal("verify-page bad relay")
	}
}

func TestVerifyPageWithServedPage(t *testing.T) {
	c := newCLI(t)
	page := []byte("<!doctype html><title>burndrop</title>")
	hash := hexSHA256(page)
	cfg := relay.DefaultConfig()
	cfg.PublicOrigin = "http://127.0.0.1"
	cfg.AgentAuth = "off"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, _ := relay.NewStore(cfg, time.Now)
	srv := httptest.NewServer(relay.New(cfg, store, relay.Options{Version: "test", Page: testPage(page, hash)}).Handler())
	defer srv.Close()
	out := c.mustRun("verify-page", "-relay", srv.URL, "-expect", hash)
	if !strings.Contains(out, "ok") || !strings.Contains(out, hash) {
		t.Fatalf("verify: %s", out)
	}
	if code, out, _ := c.run("verify-page", "-relay", srv.URL, "-expect", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); code != 1 || !strings.Contains(out, "MISMATCH") {
		t.Fatalf("mismatch: %d %s", code, out)
	}
	// Doctor with a served page checks the hash too.
	c.mustRun("init", "-relay", srv.URL, "-storage", "memory", "-yes")
	code, out, _ := c.run("doctor")
	if code != 0 || !strings.Contains(out, "ok    page hash") {
		t.Fatalf("doctor page hash: %d %s", code, out)
	}
}

func TestMCPCommandStartsAndStops(t *testing.T) {
	c := newCLI(t).initialized()
	var stdout, stderr bytes.Buffer
	pr, pw := pipe()
	a := newApp(pr, &stdout, &stderr, func(k string) string { return c.env[k] })
	a.keychainGet = func(_, _ string) (string, error) { return "", os.ErrNotExist }
	done := make(chan int, 1)
	go func() { done <- a.run([]string{"mcp"}) }()
	time.Sleep(300 * time.Millisecond)
	_ = pw.Close()
	select {
	case code := <-done:
		if code != 0 && code != 1 {
			t.Fatalf("mcp exit %d: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mcp did not stop when stdin closed")
	}
	if !strings.Contains(stderr.String(), "MCP server on stdio") {
		t.Fatalf("banner: %s", stderr.String())
	}
	if code, _, _ := c.run("mcp", "-bogus"); code != 2 {
		t.Fatal("bad flag")
	}
	_ = context.Background()
}

// A relay that runs without agent auth (the local quickstart) needs no key:
// init records that, every agent command works, and doctor says why.
func TestAuthOffNeedsNoKey(t *testing.T) {
	c := newCLIWith(t, func(cfg *relay.Config) { cfg.AgentAuth = "off"; cfg.AgentKeys = nil })
	delete(c.env, "BURNDROP_API_KEY")
	out := c.mustRun("init", "-relay", c.relay.URL, "-storage", "keychain", "-yes")
	if !strings.Contains(out, "no agent key is needed") {
		t.Fatalf("init output: %s", out)
	}
	if out := c.mustRun("request", "-name", "openai-api-key", "-purpose", "Call the OpenAI API"); !strings.Contains(out, "/drop#") {
		t.Fatalf("request without a key: %s", out)
	}
	if out := c.mustRun("pending"); !strings.Contains(out, "openai-api-key") {
		t.Fatalf("pending without a key: %s", out)
	}
	out = c.mustRun("doctor")
	if strings.Contains(out, "FAIL agent key") || !strings.Contains(out, "none needed") {
		t.Fatalf("doctor: %s", out)
	}
}
