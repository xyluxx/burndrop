package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
)

func TestGenerateThenCheck(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"gen", "-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("gen: %d %s", code, errOut.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "go.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || f.Producer != "go" || len(f.Drops) != 3 || len(f.Reveals) != 3 {
		t.Fatalf("unexpected file: %+v", f)
	}
	// The Go encoder reproduces its own plaintext byte for byte.
	for _, d := range f.Drops {
		plain, _ := crypto.Encoding.DecodeString(d.Plaintext)
		env, err := crypto.DecodeEnvelope(plain)
		if err != nil || !reencodes(env, plain) {
			t.Fatalf("%s: re-encoding differs: %v", d.Name, err)
		}
	}
	out.Reset()
	if code := run([]string{"check", "-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("check: %d\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "6 passed, 0 failed, 1 file(s)") {
		t.Fatalf("check output: %s", out.String())
	}
}

func TestCheckRepositoryFiles(t *testing.T) {
	dir := defaultDir()
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Skip("not inside the repository")
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"check", "-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("repository interop files fail: %d\n%s%s", code, out.String(), errOut.String())
	}
}

func TestCheckDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.json")
	if err := generate(path, rand.Reader, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var f file
	_ = json.Unmarshal(raw, &f)
	mutations := map[string]func(*file){
		"wrong fingerprint":   func(f *file) { f.Drops[0].Fingerprint = "0000-0000-0000-0000" },
		"wrong commitment":    func(f *file) { f.Drops[0].Commitment = f.Drops[1].Commitment },
		"wrong secret key":    func(f *file) { f.Drops[0].RecipientSecretKey = f.Drops[1].RecipientSecretKey },
		"tampered sealed":     func(f *file) { f.Drops[0].Sealed = f.Drops[1].Sealed },
		"wrong plaintext":     func(f *file) { f.Drops[0].Plaintext = f.Drops[1].Plaintext },
		"wrong envelope":      func(f *file) { f.Drops[0].Envelope = f.Drops[1].Envelope },
		"wrong secret":        func(f *file) { f.Drops[0].Secret = "AAAA" },
		"bad base64":          func(f *file) { f.Drops[0].Sealed = "***" },
		"reveal wrong aad":    func(f *file) { f.Reveals[0].KeepsCopy = !f.Reveals[0].KeepsCopy },
		"reveal wrong nonce":  func(f *file) { f.Reveals[0].Nonce = f.Reveals[1].Nonce },
		"reveal wrong key":    func(f *file) { f.Reveals[0].Key = f.Reveals[1].Key },
		"reveal wrong secret": func(f *file) { f.Reveals[0].Secret = "AAAA" },
		"reveal wrong plain":  func(f *file) { f.Reveals[0].Plaintext = f.Reveals[1].Plaintext },
		"reveal bad envelope": func(f *file) { f.Reveals[0].Envelope = json.RawMessage(`{"v":1}`) },
		"bad version":         func(f *file) { f.Version = 2 },
	}
	for name, mutate := range mutations {
		g := f
		g.Drops = append([]dropCase(nil), f.Drops...)
		g.Reveals = append([]revealCase(nil), f.Reveals...)
		mutate(&g)
		sub := t.TempDir()
		b, _ := json.Marshal(g)
		if err := os.WriteFile(filepath.Join(sub, "x.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if code := run([]string{"check", "-dir", sub}, &out, &errOut); code == 0 {
			t.Errorf("%s: check passed\n%s", name, out.String())
		}
	}
	// Junk files and empty directories are reported too.
	junk := t.TempDir()
	_ = os.WriteFile(filepath.Join(junk, "bad.json"), []byte("{"), 0o644)
	var out, errOut bytes.Buffer
	if code := run([]string{"check", "-dir", junk}, &out, &errOut); code != 1 {
		t.Fatalf("junk file: %d", code)
	}
	if code := run([]string{"check", "-dir", t.TempDir()}, &out, &errOut); code != 1 {
		t.Fatalf("empty dir: %d", code)
	}
	for _, args := range [][]string{{}, {"bogus"}, {"gen", "-nope"}} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
	if code := run([]string{"gen", "-dir", filepath.Join(t.TempDir(), "missing", "deeper")}, &out, &errOut); code != 1 {
		t.Fatalf("gen into a missing directory: %d", code)
	}
}
