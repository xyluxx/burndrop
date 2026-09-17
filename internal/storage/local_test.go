package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
)

func TestKeychainBackend(t *testing.T) {
	keyring.MockInit()
	runBackendSuite(t, func(t *testing.T) Backend { return NewKeychain("burndrop-test-" + t.Name()) }, 0)

	t.Run("chunking", func(t *testing.T) {
		k := NewKeychain("burndrop-chunk-test")
		k.chunkSize = 400
		ctx := context.Background()
		big := bytes.Repeat([]byte("abc"), 700)
		if err := k.Put(ctx, "big", big, Metadata{Retention: RetentionUntilRevoked}); err != nil {
			t.Fatal(err)
		}
		if v, _, err := k.Get(ctx, "big"); err != nil || !bytes.Equal(v, big) {
			t.Fatalf("chunked round trip: %v", err)
		}
		header, _ := keyring.Get("burndrop-chunk-test", "big")
		if !strings.HasPrefix(header, chunkHeader) {
			t.Fatalf("expected a chunk header, got %q", header)
		}
		// Shrinking the value removes the old chunks.
		if err := k.Put(ctx, "big", []byte("small"), Metadata{}); err != nil {
			t.Fatal(err)
		}
		if _, err := keyring.Get("burndrop-chunk-test", chunkUser("big", 0)); !errors.Is(err, keyring.ErrNotFound) {
			t.Fatal("stale chunk left behind")
		}
		if v, _, _ := k.Get(ctx, "big"); string(v) != "small" {
			t.Fatal("shrunk value")
		}
		// A missing chunk is reported, not silently truncated.
		_ = k.Put(ctx, "big", big, Metadata{})
		_ = keyring.Delete("burndrop-chunk-test", chunkUser("big", 3))
		if _, _, err := k.Get(ctx, "big"); err == nil || !strings.Contains(err.Error(), "chunk 3") {
			t.Fatalf("missing chunk: %v", err)
		}
		_ = keyring.Set("burndrop-chunk-test", "corrupt", chunkHeader+"x")
		if _, _, err := k.Get(ctx, "corrupt"); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Fatalf("corrupt header: %v", err)
		}
		_ = keyring.Set("burndrop-chunk-test", "notrecord", "hello")
		if _, _, err := k.Get(ctx, "notrecord"); err == nil {
			t.Fatal("non-record entry decoded")
		}
		if err := k.Delete(ctx, "big"); err != nil {
			t.Fatal(err)
		}
		if _, err := keyring.Get("burndrop-chunk-test", chunkUser("big", 0)); !errors.Is(err, keyring.ErrNotFound) {
			t.Fatal("chunks not deleted")
		}
		if _, err := k.List(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatal("keychain list must be unavailable")
		}
		if err := k.SetRaw("raw", "v"); err != nil {
			t.Fatal(err)
		}
		if v, err := k.GetRaw("raw"); err != nil || v != "v" {
			t.Fatal("raw")
		}
	})

	t.Run("errors", func(t *testing.T) {
		keyring.MockInitWithError(errors.New("no secret service"))
		defer keyring.MockInit()
		k := NewKeychain("")
		if p := k.Probe(context.Background()); p.Available || !strings.Contains(p.Reason, "no secret service") {
			t.Fatalf("probe: %+v", p)
		}
		if err := k.Put(context.Background(), "x", []byte("v"), Metadata{}); err == nil {
			t.Fatal("put must fail")
		}
		if wrapKeyring(keyring.ErrUnsupportedPlatform) == nil || !errors.Is(wrapKeyring(keyring.ErrUnsupportedPlatform), ErrUnavailable) {
			t.Fatal("unsupported platform mapping")
		}
	})
}

func TestDotenvBackend(t *testing.T) {
	runBackendSuite(t, func(t *testing.T) Backend {
		return NewDotenv(filepath.Join(t.TempDir(), ".env"))
	}, 0)

	t.Run("format", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		existing := "# my settings\nPORT=8080\nexport FOO='bar'\n\n"
		if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
		d := NewDotenv(path)
		ctx := context.Background()
		if err := d.Put(ctx, "openai-api-key", []byte("sk-1\n$HOME \"q\" \\"), Metadata{Retention: RetentionUntilRevoked, Purpose: "llm"}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		content := string(b)
		if !strings.HasPrefix(content, existing) {
			t.Fatalf("existing lines not preserved:\n%s", content)
		}
		if !strings.Contains(content, `OPENAI_API_KEY="sk-1\n\$HOME \"q\" \\"`) {
			t.Fatalf("value not quoted as expected:\n%s", content)
		}
		if !strings.Contains(content, `# burndrop: {"name":"openai-api-key"`) {
			t.Fatalf("metadata comment missing:\n%s", content)
		}
		if v, m, err := d.Get(ctx, "openai-api-key"); err != nil || string(v) != "sk-1\n$HOME \"q\" \\" || m.Purpose != "llm" {
			t.Fatalf("round trip: %v %q", err, v)
		}
		// Binary values are base64 encoded and flagged.
		if err := d.Put(ctx, "bin", []byte{0, 1, 255}, Metadata{}); err != nil {
			t.Fatal(err)
		}
		b, _ = os.ReadFile(path)
		if !strings.Contains(string(b), `"encoding":"base64"`) || !strings.Contains(string(b), `BIN="AAH/"`) {
			t.Fatalf("binary encoding:\n%s", b)
		}
		if v, _, err := d.Get(ctx, "bin"); err != nil || !bytes.Equal(v, []byte{0, 1, 255}) {
			t.Fatal("binary round trip")
		}
		// Colliding environment keys are refused.
		if err := d.Put(ctx, "openai_api_key", []byte("x"), Metadata{}); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("collision: %v", err)
		}
		if EnvKey("a-b.c") != "A_B_C" {
			t.Fatal("env key mapping")
		}
		// A marker whose next line is not ours is kept as text.
		if err := os.WriteFile(path, []byte(dotenvMarker+`{"name":"ghost","meta":{}}`+"\nOTHER=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if list, err := d.List(ctx); err != nil || len(list) != 0 {
			t.Fatalf("ghost entry: %v %+v", err, list)
		}
		_ = d.Put(ctx, "k", []byte("v"), Metadata{})
		b, _ = os.ReadFile(path)
		if !strings.Contains(string(b), `"ghost"`) || !strings.Contains(string(b), "OTHER=1") {
			t.Fatalf("plain lines lost:\n%s", b)
		}
		if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 && !isWindows() {
			t.Fatal("permissions")
		}
		for _, bad := range []string{`"abc`, `abc`, `"a\q"`, `"a\`} {
			if _, err := dotenvUnquote(bad); err == nil {
				t.Fatalf("unquote accepted %q", bad)
			}
		}
	})

	t.Run("git ignore", func(t *testing.T) {
		repo := t.TempDir()
		if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(repo, "app", ".env")
		d := NewDotenv(path)
		d.look = func(string) (string, error) { return "", errors.New("no git") }
		if p := d.Probe(context.Background()); p.Available || !strings.Contains(p.Reason, "not ignored") {
			t.Fatalf("unignored file accepted: %+v", p)
		}
		if err := d.Put(context.Background(), "x", []byte("v"), Metadata{}); !errors.Is(err, ErrPermission) {
			t.Fatalf("put into unignored file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("# comment\n!keep\n/.env\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if p := d.Probe(context.Background()); !p.Available {
			t.Fatalf("ignored file refused: %+v", p)
		}
		if err := d.Put(context.Background(), "x", []byte("v"), Metadata{}); err != nil {
			t.Fatal(err)
		}
		for _, rule := range []string{".env*", "*.env", ".env.*", "app/**"} {
			_ = os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(rule+"\n"), 0o600)
			ignored, _ := gitIgnored(d.look, repo, path)
			want := rule != ".env.*" && rule != "app/**"
			if ignored != want {
				t.Fatalf("rule %q: ignored=%v", rule, ignored)
			}
		}
		// With git available, git's own answer is used.
		if _, err := os.Stat(filepath.Join(repo, ".git")); err == nil {
			_ = os.RemoveAll(filepath.Join(repo, ".git"))
		}
		real := ExecRunner{}
		if _, err := real.LookPath("git"); err == nil {
			if out, err := real.Run(context.Background(), "git", []string{"-C", repo, "init", "-q"}, nil, nil); err != nil {
				t.Skipf("git init failed: %v %s", err, out)
			}
			d.look = real.LookPath
			_ = os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("nothing\n"), 0o600)
			if ignored, _ := gitIgnored(d.look, repo, path); ignored {
				t.Fatal("git says not ignored")
			}
			_ = os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(".env\n"), 0o600)
			if ignored, _ := gitIgnored(d.look, repo, path); !ignored {
				t.Fatal("git says ignored")
			}
		}
		outside := NewDotenv(filepath.Join(t.TempDir(), ".env"))
		if p := outside.Probe(context.Background()); !p.Available || p.Rank != 1 {
			t.Fatalf("outside a repo: %+v", p)
		}
	})
}

func TestAgeVaultBackend(t *testing.T) {
	keyring.MockInit()
	runBackendSuite(t, func(t *testing.T) Backend {
		v, err := OpenAgeVault(filepath.Join(t.TempDir(), "vault.age"), AgeVaultOptions{Keychain: NewKeychain("burndrop-vault-test-" + t.Name())})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}, 0)

	t.Run("key sources", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		// Identity file: created on first use, reused afterwards.
		idFile := filepath.Join(dir, "keys", "vault.key")
		v1, err := OpenAgeVault(filepath.Join(dir, "v1.age"), AgeVaultOptions{IdentityFile: idFile})
		if err != nil {
			t.Fatal(err)
		}
		if err := v1.Put(ctx, "a", []byte("1"), Metadata{}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(idFile)
		if !strings.Contains(string(b), "AGE-SECRET-KEY-1") || !strings.Contains(string(b), "public key: age1") {
			t.Fatalf("identity file: %s", b)
		}
		v1b, err := OpenAgeVault(filepath.Join(dir, "v1.age"), AgeVaultOptions{IdentityFile: idFile})
		if err != nil {
			t.Fatal(err)
		}
		if val, _, err := v1b.Get(ctx, "a"); err != nil || string(val) != "1" {
			t.Fatalf("reopen with identity file: %v", err)
		}
		// The encrypted file must not reveal names or values.
		enc, _ := os.ReadFile(filepath.Join(dir, "v1.age"))
		if !bytes.HasPrefix(enc, []byte("age-encryption.org/v1")) || bytes.Contains(enc, []byte(`"a"`)) {
			t.Fatal("vault file is not an age file or leaks plaintext")
		}
		// A different key cannot open it.
		other, _ := age.GenerateX25519Identity()
		_ = os.WriteFile(filepath.Join(dir, "other.key"), []byte(other.String()+"\n"), 0o600)
		v1c, err := OpenAgeVault(filepath.Join(dir, "v1.age"), AgeVaultOptions{IdentityFile: filepath.Join(dir, "other.key")})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := v1c.Get(ctx, "a"); !errors.Is(err, ErrPermission) {
			t.Fatalf("wrong key: %v", err)
		}
		if p := v1c.Probe(ctx); p.Available {
			t.Fatal("probe with wrong key")
		}
		// Passphrase.
		v2, err := OpenAgeVault(filepath.Join(dir, "v2.age"), AgeVaultOptions{Passphrase: "correct horse"})
		if err != nil {
			t.Fatal(err)
		}
		if err := v2.Put(ctx, "p", []byte("2"), Metadata{}); err != nil {
			t.Fatal(err)
		}
		v2b, _ := OpenAgeVault(filepath.Join(dir, "v2.age"), AgeVaultOptions{Passphrase: "wrong"})
		if _, _, err := v2b.Get(ctx, "p"); err == nil {
			t.Fatal("wrong passphrase opened the vault")
		}
		// Keychain: the key is generated once and reused.
		kc := NewKeychain("burndrop-vault-keysource")
		v3, err := OpenAgeVault(filepath.Join(dir, "v3.age"), AgeVaultOptions{Keychain: kc})
		if err != nil {
			t.Fatal(err)
		}
		_ = v3.Put(ctx, "k", []byte("3"), Metadata{})
		v3b, err := OpenAgeVault(filepath.Join(dir, "v3.age"), AgeVaultOptions{Keychain: kc})
		if err != nil {
			t.Fatal(err)
		}
		if val, _, err := v3b.Get(ctx, "k"); err != nil || string(val) != "3" {
			t.Fatalf("keychain key reuse: %v", err)
		}
		if p := v3b.Probe(ctx); !p.Available || p.Rank != 80 {
			t.Fatalf("probe: %+v", p)
		}
		_ = kc.SetRaw(KeychainVaultKeyEntry, "garbage")
		if _, err := OpenAgeVault(filepath.Join(dir, "v3.age"), AgeVaultOptions{Keychain: kc}); err == nil {
			t.Fatal("garbage key accepted")
		}
		if _, err := OpenAgeVault(filepath.Join(dir, "v4.age"), AgeVaultOptions{}); err == nil {
			t.Fatal("no key source accepted")
		}
		_ = os.WriteFile(filepath.Join(dir, "empty.key"), []byte("# nothing\n"), 0o600)
		if _, err := OpenAgeVault(filepath.Join(dir, "v5.age"), AgeVaultOptions{IdentityFile: filepath.Join(dir, "empty.key")}); err == nil {
			t.Fatal("identity file without a key accepted")
		}
		// Corrupt vault content.
		_ = os.WriteFile(filepath.Join(dir, "v6.age"), []byte("not age"), 0o600)
		v6, _ := OpenAgeVault(filepath.Join(dir, "v6.age"), AgeVaultOptions{Passphrase: "x"})
		if _, _, err := v6.Get(ctx, "a"); err == nil {
			t.Fatal("corrupt vault opened")
		}
		if err := v6.Put(ctx, "a", []byte("1"), Metadata{}); err == nil {
			t.Fatal("put over a corrupt vault must fail rather than overwrite")
		}
	})

	t.Run("lock", func(t *testing.T) {
		dir := t.TempDir()
		v, _ := OpenAgeVault(filepath.Join(dir, "v.age"), AgeVaultOptions{Passphrase: "x"})
		lock := filepath.Join(dir, "v.age.lock")
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		old := os.Chtimes(lock, time0(), time0())
		if old != nil {
			t.Fatal(old)
		}
		if err := v.Put(context.Background(), "a", []byte("1"), Metadata{}); err != nil {
			t.Fatalf("stale lock not reclaimed: %v", err)
		}
		if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("lock left behind")
		}
	})
}

func time0() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
