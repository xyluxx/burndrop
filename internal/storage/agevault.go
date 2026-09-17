package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
)

// AgeVault keeps every secret in one file encrypted with age
// (https://age-encryption.org, X25519 plus ChaCha20-Poly1305). The vault
// key comes from the OS keychain when one is available, from an identity
// file, or from a passphrase. It is the recommended backend on machines
// without a usable credential store, such as headless Linux servers.
type AgeVault struct {
	path      string
	identity  age.Identity
	recipient age.Recipient
	desc      string
	mu        sync.Mutex
}

// KeychainVaultKeyEntry is the keychain user name that holds the vault key.
const KeychainVaultKeyEntry = "vault-identity"

// AgeVaultOptions selects where the vault key comes from. The first source
// that applies wins: IdentityFile, then Passphrase, then Keychain (created on
// first use).
type AgeVaultOptions struct {
	IdentityFile string
	Passphrase   string
	Keychain     *Keychain
}

// OpenAgeVault resolves the key per opts and returns a vault at path.
func OpenAgeVault(path string, opts AgeVaultOptions) (*AgeVault, error) {
	switch {
	case opts.IdentityFile != "":
		id, err := loadOrCreateIdentityFile(opts.IdentityFile)
		if err != nil {
			return nil, err
		}
		return &AgeVault{path: path, identity: id, recipient: id.Recipient(), desc: "age vault " + path + " (key in " + opts.IdentityFile + ")"}, nil
	case opts.Passphrase != "":
		id, err := age.NewScryptIdentity(opts.Passphrase)
		if err != nil {
			return nil, err
		}
		rcpt, err := age.NewScryptRecipient(opts.Passphrase)
		if err != nil {
			return nil, err
		}
		return &AgeVault{path: path, identity: id, recipient: rcpt, desc: "age vault " + path + " (passphrase)"}, nil
	case opts.Keychain != nil:
		s, err := opts.Keychain.GetRaw(KeychainVaultKeyEntry)
		if errors.Is(err, ErrNotFound) {
			gen, genErr := age.GenerateX25519Identity()
			if genErr != nil {
				return nil, genErr
			}
			if err := opts.Keychain.SetRaw(KeychainVaultKeyEntry, gen.String()); err != nil {
				return nil, fmt.Errorf("storage: could not save the vault key to the keychain: %w", err)
			}
			s = gen.String()
		} else if err != nil {
			return nil, fmt.Errorf("storage: could not read the vault key from the keychain: %w", err)
		}
		id, err := age.ParseX25519Identity(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("storage: the vault key in the keychain is not an age identity: %w", err)
		}
		return &AgeVault{path: path, identity: id, recipient: id.Recipient(), desc: "age vault " + path + " (key in the " + keychainDescription() + ")"}, nil
	default:
		return nil, errors.New("storage: the age vault needs an identity file, a passphrase, or a keychain for its key")
	}
}

func loadOrCreateIdentityFile(path string) (*age.X25519Identity, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		content := "# burndrop vault identity, created " + time.Now().UTC().Format(time.RFC3339) + "\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
		if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
			return nil, err
		}
		return id, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return age.ParseX25519Identity(line)
		}
	}
	return nil, fmt.Errorf("storage: %s holds no AGE-SECRET-KEY line", path)
}

func (v *AgeVault) Name() string { return "agevault" }

// Path returns the vault file location.
func (v *AgeVault) Path() string { return v.path }

func (v *AgeVault) Probe(context.Context) Probe {
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return Probe{Reason: "cannot create " + filepath.Dir(v.path) + ": " + shortErr(err)}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.load(); err != nil {
		return Probe{Reason: shortErr(err)}
	}
	return Probe{Available: true, Reason: v.desc, Rank: 80}
}

type vaultFile struct {
	V       int                    `json:"v"`
	Entries map[string]vaultRecord `json:"entries"`
}

type vaultRecord struct {
	Meta  Metadata `json:"meta"`
	Value []byte   `json:"value"`
}

func (v *AgeVault) load() (*vaultFile, error) {
	f := &vaultFile{V: 1, Entries: map[string]vaultRecord{}}
	enc, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: read vault: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(enc), v.identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, fmt.Errorf("%w: the vault at %s was encrypted with a different key", ErrPermission, v.path)
		}
		return nil, fmt.Errorf("storage: decrypt vault: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("storage: decrypt vault: %w", err)
	}
	if err := json.Unmarshal(plain, f); err != nil || f.V != 1 {
		return nil, fmt.Errorf("storage: vault content is not a burndrop vault")
	}
	Zero(plain)
	if f.Entries == nil {
		f.Entries = map[string]vaultRecord{}
	}
	return f, nil
}

func (v *AgeVault) save(f *vaultFile) error {
	plain, err := json.Marshal(f)
	if err != nil {
		return err
	}
	defer Zero(plain)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, v.recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return writeFileAtomic(v.path, buf.Bytes(), 0o600)
}

// withLock serializes writers across processes with a lock file. A lock
// older than a minute is treated as abandoned.
func (v *AgeVault) withLock(fn func() error) error {
	lock := v.path + ".lock"
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("storage: vault lock: %w", err)
		}
		if info, statErr := os.Stat(lock); statErr == nil && time.Since(info.ModTime()) > time.Minute {
			_ = os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("storage: vault is locked by another process (%s)", lock)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer os.Remove(lock)
	return fn()
}

func (v *AgeVault) Put(_ context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(value) > MaxValueBytes {
		return ErrTooLarge
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return fmt.Errorf("%w: %v", ErrPermission, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.withLock(func() error {
		f, err := v.load()
		if err != nil {
			return err
		}
		meta.Name = name
		meta.Backend = v.Name()
		meta.SizeBytes = len(value)
		f.Entries[name] = vaultRecord{Meta: meta, Value: append([]byte(nil), value...)}
		return v.save(f)
	})
}

func (v *AgeVault) Get(_ context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	f, err := v.load()
	if err != nil {
		return nil, Metadata{}, err
	}
	r, ok := f.Entries[name]
	if !ok {
		return nil, Metadata{}, ErrNotFound
	}
	if r.Value == nil {
		r.Value = []byte{}
	}
	return r.Value, r.Meta, nil
}

func (v *AgeVault) Delete(_ context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.withLock(func() error {
		f, err := v.load()
		if err != nil {
			return err
		}
		if _, ok := f.Entries[name]; !ok {
			return ErrNotFound
		}
		delete(f.Entries, name)
		return v.save(f)
	})
}

func (v *AgeVault) List(context.Context) ([]Metadata, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, err := v.load()
	if err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(f.Entries))
	for _, r := range f.Entries {
		out = append(out, r.Meta)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}
