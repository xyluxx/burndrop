// Command interop is the Go side of the cross-language exchange described
// in spec/interop/README.md.
//
//	go run ./spec/interop/go gen     writes spec/interop/go.json
//	go run ./spec/interop/go check   verifies every spec/interop/*.json
//
// Both commands accept -dir to point at another directory.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/xyluxx/burndrop/internal/crypto"
)

type file struct {
	Version     int          `json:"version"`
	Producer    string       `json:"producer"`
	Library     string       `json:"library"`
	GeneratedAt string       `json:"generated_at"`
	Drops       []dropCase   `json:"drops"`
	Reveals     []revealCase `json:"reveals"`
}

type dropCase struct {
	Name               string          `json:"name"`
	RecipientPublicKey string          `json:"recipient_public_key"`
	RecipientSecretKey string          `json:"recipient_secret_key"`
	Fingerprint        string          `json:"fingerprint"`
	Commitment         string          `json:"commitment"`
	Sealed             string          `json:"sealed"`
	Plaintext          string          `json:"plaintext"`
	Envelope           json.RawMessage `json:"envelope"`
	Secret             string          `json:"secret"`
}

type revealCase struct {
	Name        string          `json:"name"`
	Key         string          `json:"key"`
	Nonce       string          `json:"nonce"`
	DisplayName string          `json:"display_name"`
	KeepsCopy   bool            `json:"keeps_copy"`
	Aad         string          `json:"aad"`
	Blob        string          `json:"blob"`
	Plaintext   string          `json:"plaintext"`
	Envelope    json.RawMessage `json:"envelope"`
	Secret      string          `json:"secret"`
	// Password and Salt are present for password-protected reveals: Key is
	// then the link key and the blob is encrypted under
	// reveal_key_with_password(key, password, salt) (crypto spec 4.1).
	Password string `json:"password,omitempty"`
	Salt     string `json:"salt,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: interop gen|check [-dir spec/interop]")
		return 2
	}
	fs := flag.NewFlagSet("interop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultDir(), "directory holding the interop files")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "gen":
		path := filepath.Join(*dir, "go.json")
		if err := generate(path, rand.Reader, time.Now()); err != nil {
			fmt.Fprintln(stderr, "gen:", err)
			return 1
		}
		fmt.Fprintln(stdout, "wrote", path)
		return 0
	case "check":
		ok, err := checkDir(*dir, stdout)
		if err != nil {
			fmt.Fprintln(stderr, "check:", err)
			return 1
		}
		if !ok {
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stderr, "usage: interop gen|check [-dir spec/interop]")
		return 2
	}
}

// defaultDir is spec/interop relative to the module root, found by walking
// up from the working directory to go.mod.
func defaultDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "spec/interop"
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(d, "spec", "interop")
		}
		if filepath.Dir(d) == d {
			return "spec/interop"
		}
	}
}

type dropInput struct {
	name                                string
	secretName, purpose, storage, reten string
	value                               []byte
}

type revealInput struct {
	name, displayName string
	keepsCopy         bool
	value             []byte
	password          string
}

// Cases mirror the Python and TypeScript generators: text, characters JSON
// must escape, binary, and for reveals an empty secret.
var (
	dropInputs = []dropInput{
		{"drop text", "openai-api-key", "Call the API from the billing script", "macOS Keychain", "until-revoked", []byte("sk-live-0123456789abcdef")},
		{"drop json characters", "quoteé key", "line one\nline two with \"quotes\" and <tags> & ampersands", "1Password", "session", []byte("value with \"quotes\", back\\slash, tab\t, and ünicode   separator")},
		{"drop binary", "tls-cert", "", "", "until:2027-01-02T03:04:05Z", []byte{0x00, 0xff, 0x10, 0x80, 0x7f, 0x01, 0xfe}},
	}
	revealInputs = []revealInput{
		{"reveal text", "staging-db-url", true, []byte("postgres://app:s3cret@db.staging.example:5432/app"), ""},
		{"reveal binary no copy", "session-key", false, []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}, ""},
		{"reveal empty secret", "empty", true, []byte{}, ""},
		{"reveal with password", "prod-signing-key", true, []byte("sk-signing-0123456789"), "correct horse battery staple"},
	}
)

func generate(path string, random io.Reader, now time.Time) error {
	out := file{Version: 1, Producer: "go", Library: "burndrop internal/crypto, golang.org/x/crypto", GeneratedAt: now.UTC().Format(time.RFC3339)}
	for _, in := range dropInputs {
		pub, priv, err := crypto.GenerateKeyPair(random)
		if err != nil {
			return err
		}
		env := crypto.Envelope{V: 1, Type: "drop", Name: in.secretName, Purpose: in.purpose, Storage: in.storage, Retention: in.reten, Fingerprint: crypto.Fingerprint(pub[:])}
		env.SetSecret(in.value)
		plain, err := env.Encode()
		if err != nil {
			return fmt.Errorf("%s: %w", in.name, err)
		}
		sealed, err := crypto.Seal(pub, crypto.Pad(plain, crypto.PadBlock), random)
		if err != nil {
			return err
		}
		out.Drops = append(out.Drops, dropCase{
			Name:               in.name,
			RecipientPublicKey: crypto.Encoding.EncodeToString(pub[:]),
			RecipientSecretKey: crypto.Encoding.EncodeToString(priv[:]),
			Fingerprint:        env.Fingerprint,
			Commitment:         crypto.Commitment(pub[:]),
			Sealed:             crypto.Encoding.EncodeToString(sealed),
			Plaintext:          crypto.Encoding.EncodeToString(plain),
			Envelope:           json.RawMessage(plain),
			Secret:             crypto.Encoding.EncodeToString(in.value),
		})
		crypto.ZeroKey(priv)
	}
	for _, in := range revealInputs {
		key, err := crypto.NewSymmetricKey(random)
		if err != nil {
			return err
		}
		env := crypto.Envelope{V: 1, Type: "reveal", Name: in.displayName}
		env.SetSecret(in.value)
		plain, err := env.Encode()
		if err != nil {
			return fmt.Errorf("%s: %w", in.name, err)
		}
		aad := crypto.RevealAAD(in.displayName, in.keepsCopy)
		encKey := key
		var salt []byte
		if in.password != "" {
			if salt, err = crypto.NewSalt(random); err != nil {
				return err
			}
			if encKey, err = crypto.RevealKeyWithPassword(key, []byte(in.password), salt); err != nil {
				return err
			}
		}
		blob, err := crypto.EncryptAEAD(encKey, crypto.Pad(plain, crypto.PadBlock), aad, random)
		if err != nil {
			return err
		}
		c := revealCase{
			Name:        in.name,
			Key:         crypto.Encoding.EncodeToString(key[:]),
			Nonce:       crypto.Encoding.EncodeToString(blob[:crypto.NonceSize]),
			DisplayName: in.displayName,
			KeepsCopy:   in.keepsCopy,
			Aad:         crypto.Encoding.EncodeToString(aad),
			Blob:        crypto.Encoding.EncodeToString(blob),
			Plaintext:   crypto.Encoding.EncodeToString(plain),
			Envelope:    json.RawMessage(plain),
			Secret:      crypto.Encoding.EncodeToString(in.value),
		}
		if salt != nil {
			c.Password = in.password
			c.Salt = crypto.Encoding.EncodeToString(salt)
			crypto.ZeroKey(encKey)
		}
		out.Reveals = append(out.Reveals, c)
		crypto.ZeroKey(key)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// checkDir verifies every *.json in dir and prints one line per case.
func checkDir(dir string, w io.Writer) (bool, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return false, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return false, fmt.Errorf("no interop files in %s", dir)
	}
	passed, failed := 0, 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		var f file
		if err := json.Unmarshal(raw, &f); err != nil {
			fmt.Fprintf(w, "FAIL %s: not a valid interop file: %v\n", filepath.Base(path), err)
			failed++
			continue
		}
		if f.Version != 1 {
			fmt.Fprintf(w, "FAIL %s: unsupported version %d\n", filepath.Base(path), f.Version)
			failed++
			continue
		}
		for _, d := range f.Drops {
			if err := checkDrop(d); err != nil {
				fmt.Fprintf(w, "FAIL %s [%s] drop %q: %v\n", filepath.Base(path), f.Producer, d.Name, err)
				failed++
			} else {
				fmt.Fprintf(w, "ok   %s [%s] drop %q\n", filepath.Base(path), f.Producer, d.Name)
				passed++
			}
		}
		for _, r := range f.Reveals {
			if err := checkReveal(r); err != nil {
				fmt.Fprintf(w, "FAIL %s [%s] reveal %q: %v\n", filepath.Base(path), f.Producer, r.Name, err)
				failed++
			} else {
				fmt.Fprintf(w, "ok   %s [%s] reveal %q\n", filepath.Base(path), f.Producer, r.Name)
				passed++
			}
		}
	}
	fmt.Fprintf(w, "%d passed, %d failed, %d file(s)\n", passed, failed, len(paths))
	return failed == 0, nil
}

func decode(field, s string) ([]byte, error) {
	b, err := crypto.Encoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: not base64url: %w", field, err)
	}
	return b, nil
}

func checkDrop(d dropCase) error {
	pubBytes, err := decode("recipient_public_key", d.RecipientPublicKey)
	if err != nil {
		return err
	}
	privBytes, err := decode("recipient_secret_key", d.RecipientSecretKey)
	if err != nil {
		return err
	}
	pub, err := crypto.KeyFromBytes(pubBytes)
	if err != nil {
		return fmt.Errorf("recipient_public_key: %w", err)
	}
	priv, err := crypto.KeyFromBytes(privBytes)
	if err != nil {
		return fmt.Errorf("recipient_secret_key: %w", err)
	}
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	if !bytes.Equal(derived, pub[:]) {
		return errors.New("public key does not match the secret key")
	}
	if crypto.Fingerprint(pub[:]) != d.Fingerprint {
		return errors.New("fingerprint mismatch")
	}
	if crypto.Commitment(pub[:]) != d.Commitment {
		return errors.New("commitment mismatch")
	}
	sealed, err := decode("sealed", d.Sealed)
	if err != nil {
		return err
	}
	padded, err := crypto.OpenSealed(pub, priv, sealed)
	if err != nil {
		return fmt.Errorf("open sealed box: %w", err)
	}
	plain, err := crypto.Unpad(padded, crypto.PadBlock)
	if err != nil {
		return fmt.Errorf("unpad: %w", err)
	}
	expectedPlain, err := decode("plaintext", d.Plaintext)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, expectedPlain) {
		return errors.New("decrypted plaintext differs from the plaintext field")
	}
	env, err := crypto.DecodeEnvelope(plain)
	if err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.Type != "drop" {
		return fmt.Errorf("envelope type %q", env.Type)
	}
	if env.Fingerprint != d.Fingerprint {
		return errors.New("envelope fingerprint differs from the case fingerprint")
	}
	if err := compareEnvelope(env, d.Envelope); err != nil {
		return err
	}
	return compareSecret(env, d.Secret)
}

func checkReveal(r revealCase) error {
	keyBytes, err := decode("key", r.Key)
	if err != nil {
		return err
	}
	key, err := crypto.KeyFromBytes(keyBytes)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	linkKey := key
	if r.Salt != "" {
		salt, err := decode("salt", r.Salt)
		if err != nil {
			return err
		}
		if key, err = crypto.RevealKeyWithPassword(linkKey, []byte(r.Password), salt); err != nil {
			return fmt.Errorf("password key: %w", err)
		}
	}
	aad, err := decode("aad", r.Aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(aad, crypto.RevealAAD(r.DisplayName, r.KeepsCopy)) {
		return errors.New("aad differs from reveal_aad(display_name, keeps_copy)")
	}
	nonce, err := decode("nonce", r.Nonce)
	if err != nil {
		return err
	}
	blob, err := decode("blob", r.Blob)
	if err != nil {
		return err
	}
	if len(blob) < crypto.NonceSize || !bytes.Equal(blob[:crypto.NonceSize], nonce) {
		return errors.New("blob does not start with the nonce")
	}
	padded, err := crypto.DecryptAEAD(key, blob, aad)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	plain, err := crypto.Unpad(padded, crypto.PadBlock)
	if err != nil {
		return fmt.Errorf("unpad: %w", err)
	}
	expectedPlain, err := decode("plaintext", r.Plaintext)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, expectedPlain) {
		return errors.New("decrypted plaintext differs from the plaintext field")
	}
	env, err := crypto.DecodeEnvelope(plain)
	if err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.Type != "reveal" {
		return fmt.Errorf("envelope type %q", env.Type)
	}
	if err := compareEnvelope(env, r.Envelope); err != nil {
		return err
	}
	if err := compareSecret(env, r.Secret); err != nil {
		return err
	}
	if _, err := crypto.DecryptAEAD(key, blob, crypto.RevealAAD(r.DisplayName, !r.KeepsCopy)); err == nil {
		return errors.New("decryption succeeded with the keeps_copy flag flipped")
	}
	if r.Salt != "" {
		if _, err := crypto.DecryptAEAD(linkKey, blob, aad); err == nil {
			return errors.New("decryption succeeded with the link key alone; the password is not mixed in")
		}
	}
	return nil
}

// compareEnvelope checks the decoded envelope against the envelope object
// of the case, field by field, and reports (without failing) whether the
// Go encoder reproduces the producer's bytes.
func compareEnvelope(env crypto.Envelope, raw json.RawMessage) error {
	var want crypto.Envelope
	if err := json.Unmarshal(raw, &want); err != nil {
		return fmt.Errorf("envelope object: %w", err)
	}
	if env != want {
		return fmt.Errorf("decoded envelope %+v differs from the envelope object %+v", env, want)
	}
	return nil
}

func compareSecret(env crypto.Envelope, secret string) error {
	want, err := decode("secret", secret)
	if err != nil {
		return err
	}
	got, err := env.SecretBytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("secret bytes differ")
	}
	return nil
}

// re-encoding note helper used by tests to confirm byte-identical output.
func reencodes(env crypto.Envelope, plain []byte) bool {
	b, err := env.Encode()
	return err == nil && bytes.Equal(b, plain) && !strings.Contains(string(b), "\n")
}
