package agent

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/storage"
)

func TestRedactor(t *testing.T) {
	r := NewRedactor()
	r.Add("short", []byte("abc"))
	if r.Count() != 0 {
		t.Fatal("short values must not be registered")
	}
	secret := "p@ss word/ü+"
	r.Add("key", []byte(secret))
	std := base64.StdEncoding.EncodeToString([]byte(secret))
	raw := base64.RawStdEncoding.EncodeToString([]byte(secret))
	cases := map[string]string{
		secret:                             "[redacted:key]",
		std:                                "[redacted:key]",
		raw:                                "[redacted:key]",
		std + "!":                          "[redacted:key]!",
		url.QueryEscape(secret):            "[redacted:key]",
		url.PathEscape(secret):             "[redacted:key]",
		hex.EncodeToString([]byte(secret)): "[redacted:key]",
		`{"v":"` + secret + `"}`:           `{"v":"[redacted:key]"}`,
		"unrelated text stays":             "unrelated text stays",
		"twice " + secret + " " + secret:   "twice [redacted:key] [redacted:key]",
		"703073732077 6f72642fc3bc2b":      "703073732077 6f72642fc3bc2b",
	}
	for in, want := range cases {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	r.Add("other", []byte("  padded value  "))
	if got := r.Redact("x padded value y"); got != "x [redacted:other] y" {
		t.Fatalf("trimmed form: %q", got)
	}
	if got := string(r.RedactBytes([]byte(secret))); got != "[redacted:key]" {
		t.Fatal("redact bytes")
	}
	r.Remove("key")
	if got := r.Redact(secret); got != secret {
		t.Fatal("remove")
	}
	// Adding the same value under two names keeps the first name.
	r.Add("a", []byte("same-value-1"))
	r.Add("b", []byte("same-value-1"))
	if got := r.Redact("same-value-1"); got != "[redacted:a]" {
		t.Fatalf("duplicate: %q", got)
	}
	r.Add("quoted", []byte("say \"hi\"\n"))
	if got := r.Redact(`printed say \"hi\"\n end`); !strings.Contains(got, "[redacted:quoted]") {
		t.Fatalf("json escaped form: %q", got)
	}
}

func TestAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.log")
	now := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	a, err := NewAudit(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if a.Path() != path {
		t.Fatal("path")
	}
	if err := a.Log(Event{Event: "one", Name: "n"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Log(Event{Event: "two", Fields: map[string]string{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	ev, err := a.Read(0)
	if err != nil || len(ev) != 2 || ev[0].Event != "one" || !ev[0].Time.Equal(now) || ev[1].Fields["k"] != "v" {
		t.Fatalf("read: %v %+v", err, ev)
	}
	if ev, _ := a.Read(1); len(ev) != 1 || ev[0].Event != "two" {
		t.Fatal("tail")
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatal("permissions")
	}
	// Rotation when the file grows past the cap.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write(make([]byte, maxAuditBytes+1))
	_ = f.Close()
	if err := a.Log(Event{Event: "three"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("rotated file missing")
	}
	if ev, _ := a.Read(0); len(ev) != 1 || ev[0].Event != "three" {
		t.Fatalf("after rotation: %+v", ev)
	}
	// Disabled.
	off, _ := NewAudit("", nil)
	if err := off.Log(Event{Event: "x"}); err != nil || off.Path() != "" {
		t.Fatal("disabled audit")
	}
	if ev, err := off.Read(5); err != nil || ev != nil {
		t.Fatal("disabled read")
	}
	var nilAudit *Audit
	if err := nilAudit.Log(Event{}); err != nil {
		t.Fatal("nil audit")
	}
	// Corrupt trailing line is tolerated.
	_ = os.WriteFile(path, []byte("{\"event\":\"ok\"}\n{broken"), 0o600)
	if ev, _ := a.Read(0); len(ev) != 1 {
		t.Fatalf("corrupt tail: %+v", ev)
	}
	if _, err := NewAudit(filepath.Join(path, "impossible", "x.log"), nil); err == nil {
		t.Fatal("directory under a file")
	}
}

func TestPaths(t *testing.T) {
	env := map[string]string{"BURNDROP_CONFIG": "/x/config.toml", "BURNDROP_STATE_DIR": "/y/state"}
	getenv := func(k string) string { return env[k] }
	p, err := DefaultPaths(getenv)
	if err != nil || p.ConfigFile != "/x/config.toml" || p.StateDir != "/y/state" {
		t.Fatalf("overrides: %v %+v", err, p)
	}
	if p.IndexFile() != filepath.Join("/y/state", "index.json") || p.VaultFile() != filepath.Join("/y/state", "vault.age") || p.AuditFile() != filepath.Join("/y/state", "audit.log") || p.DotenvFile() != filepath.Join("/y/state", ".env") {
		t.Fatal("state files")
	}
	env = map[string]string{"HOME": "/home/u", "USERPROFILE": "C:\\Users\\u", "APPDATA": "C:\\Users\\u\\AppData\\Roaming", "LOCALAPPDATA": "C:\\Users\\u\\AppData\\Local", "XDG_CONFIG_HOME": "/home/u/.cfg", "XDG_STATE_HOME": "/home/u/.st"}
	p, err = DefaultPaths(getenv)
	if err != nil {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "windows":
		if p.ConfigFile != filepath.Join("C:\\Users\\u\\AppData\\Roaming", AppName, "config.toml") || p.StateDir != filepath.Join("C:\\Users\\u\\AppData\\Local", AppName) {
			t.Fatalf("windows paths: %+v", p)
		}
	case "darwin":
		if p.ConfigFile != filepath.Join("/home/u/Library/Application Support", AppName, "config.toml") {
			t.Fatalf("darwin paths: %+v", p)
		}
	default:
		if p.ConfigFile != filepath.Join("/home/u/.cfg", AppName, "config.toml") || p.StateDir != filepath.Join("/home/u/.st", AppName) {
			t.Fatalf("xdg paths: %+v", p)
		}
	}
	// Without XDG or APPDATA variables the home directory is used.
	env = map[string]string{"HOME": "/home/u", "USERPROFILE": "C:\\Users\\u"}
	p, err = DefaultPaths(getenv)
	if err != nil || !strings.Contains(p.ConfigFile, "u") || !strings.Contains(p.StateDir, "u") {
		t.Fatalf("home fallback: %v %+v", err, p)
	}
	dir := t.TempDir()
	p = Paths{StateDir: filepath.Join(dir, "a", "b")}
	if err := p.EnsureStateDir(); err != nil {
		t.Fatal(err)
	}
}

func TestConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.toml")
	if _, err := LoadConfig(path); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("missing: %v", err)
	}
	cfg := Config{Relay: "https://relay.example", Storage: "keychain", DefaultTTL: "45m", DefaultRetention: "session"}
	cfg.Backends.OnePassword.Vault = "Agents"
	cfg.RunWithSecret.AllowedCommands = []string{"aws"}
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `relay = "https://relay.example"`) || !strings.Contains(string(b), "[backends.onepassword]") || strings.Contains(string(b), "keys") && false {
		t.Fatalf("saved:\n%s", b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatal("permissions")
	}
	got, err := LoadConfig(path)
	if err != nil || got.Relay != cfg.Relay || got.Backends.OnePassword.Vault != "Agents" || got.RunWithSecret.AllowedCommands[0] != "aws" {
		t.Fatalf("load: %v %+v", err, got)
	}
	if ttl, _ := got.TTL(); ttl != 45*time.Minute || got.Retention() != "session" || got.MaxOutput() != DefaultMaxOutput {
		t.Fatal("derived values")
	}
	// Validation failures.
	bad := []Config{
		{},
		{Relay: "ftp://x", Storage: "memory"},
		{Relay: "https://r.example", Storage: ""},
		{Relay: "https://r.example", Storage: "floppy"},
		{Relay: "https://r.example", Storage: "memory", AgentKey: "plainvalue"},
		{Relay: "https://r.example", Storage: "memory", DefaultTTL: "-1h"},
		{Relay: "https://r.example", Storage: "memory", DefaultRetention: "never"},
		{Relay: "https://r.example", Storage: "memory", PageOrigin: "http://evil.example"},
		{Relay: "https://r.example", Storage: "memory", RunWithSecret: RunConfig{MaxOutputBytes: -1}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d validated: %+v", i, c)
		}
	}
	if err := SaveConfig(path, Config{}); err == nil {
		t.Fatal("save invalid")
	}
	// Unknown keys and parse errors.
	_ = os.WriteFile(path, []byte("relay = \"https://r.example\"\nstorage = \"memory\"\nsurprise = 1\n"), 0o600)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("unknown key: %v", err)
	}
	_ = os.WriteFile(path, []byte("relay = [broken"), 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("parse error")
	}
	// Agent key resolution.
	c := Config{Relay: "https://r.example", Storage: "memory"}
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	kc := func(service, entry string) (string, error) {
		if service == AppName && entry == "agent-key" {
			return " from-keychain \n", nil
		}
		return "", errors.New("not found")
	}
	if v, src, err := c.ResolveAgentKey(getenv, kc); err != nil || v != "from-keychain" || src != DefaultAgentKeyRef {
		t.Fatalf("keychain default: %v %q %q", err, v, src)
	}
	env[DefaultAgentKeyEnv] = "from-env"
	if v, src, err := c.ResolveAgentKey(getenv, kc); err != nil || v != "from-env" || src != "env:"+DefaultAgentKeyEnv {
		t.Fatalf("env default: %v %q %q", err, v, src)
	}
	c.AgentKey = "env:MY_KEY"
	if _, _, err := c.ResolveAgentKey(getenv, kc); err == nil {
		t.Fatal("empty variable")
	}
	env["MY_KEY"] = "custom"
	if v, _, err := c.ResolveAgentKey(getenv, kc); err != nil || v != "custom" {
		t.Fatal("custom env")
	}
	c.AgentKey = "keychain:svc/entry"
	if _, _, err := c.ResolveAgentKey(getenv, kc); err == nil {
		t.Fatal("missing keychain entry")
	}
	c.AgentKey = "keychain:broken"
	if _, _, err := c.ResolveAgentKey(getenv, kc); err == nil {
		t.Fatal("malformed keychain ref")
	}
	c.AgentKey = "keychain:a/b"
	if _, _, err := c.ResolveAgentKey(getenv, nil); err == nil {
		t.Fatal("no keychain function")
	}
	// Backend construction for the local backends.
	paths := Paths{StateDir: filepath.Join(dir, "state")}
	for _, name := range []string{"memory", "keychain", "dotenv"} {
		c := Config{Relay: "https://r.example", Storage: name}
		b, err := OpenBackend(c, paths, getenv)
		if err != nil || b.Name() != name {
			t.Fatalf("%s: %v", name, err)
		}
	}
	c = Config{Relay: "https://r.example", Storage: "agevault"}
	c.Backends.AgeVault.IdentityFile = filepath.Join(dir, "state", "vault.key")
	if b, err := OpenBackend(c, paths, getenv); err != nil || b.Name() != "agevault" {
		t.Fatalf("agevault: %v", err)
	}
	c.Backends.AgeVault.IdentityFile = ""
	c.Backends.AgeVault.PassphraseEnv = "VAULT_PASS"
	if _, err := OpenBackend(c, paths, getenv); err == nil {
		t.Fatal("empty passphrase variable")
	}
	env["VAULT_PASS"] = "pw"
	if b, err := OpenBackend(c, paths, getenv); err != nil || b.Name() != "agevault" {
		t.Fatalf("agevault passphrase: %v", err)
	}
	c = Config{Relay: "https://r.example", Storage: "onepassword"}
	if _, err := OpenBackend(c, paths, getenv); err == nil {
		t.Fatal("unregistered backend must fail clearly")
	}
	RegisterBackend("onepassword", func(Config, Paths, func(string) string) (storage.Backend, error) {
		return nil, errors.New("registered")
	})
	if _, err := OpenBackend(c, paths, getenv); err == nil || err.Error() != "registered" {
		t.Fatalf("registered backend: %v", err)
	}
	delete(externalBackends, "onepassword")
}

func TestMessages(t *testing.T) {
	for _, b := range KnownBackends {
		if describeStorage(b) == b && b != "" {
			t.Errorf("no description for %s", b)
		}
	}
	if describeStorage("") == "" || describeStorage("custom") != "custom" {
		t.Fatal("describe storage")
	}
	if describeRetention("session", time.Time{}) == "" || describeRetention("until-revoked", time.Time{}) == "" || !strings.Contains(describeRetention("until:2027-01-01T00:00:00Z", time.Time{}), "2027") || !strings.Contains(describeRetention("x", time.Date(2027, 2, 3, 4, 5, 0, 0, time.UTC)), "2027-02-03") || describeRetention("weird", time.Time{}) != "weird" {
		t.Fatal("describe retention")
	}
}
