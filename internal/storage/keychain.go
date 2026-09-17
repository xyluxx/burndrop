package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
)

// DefaultKeychainService is the service name entries are filed under.
const DefaultKeychainService = "burndrop"

// Keychain stores records in the operating system credential store: the
// macOS Keychain, the Windows Credential Manager, or a Linux Secret Service
// (GNOME Keyring, KWallet) over D-Bus.
//
// The Windows Credential Manager caps a blob at 2560 bytes, so records
// larger than the chunk size are split across numbered entries.
type Keychain struct {
	service   string
	chunkSize int
	mu        sync.Mutex // serializes store access; avoids parallel unlock prompts
}

// NewKeychain uses the given service name (DefaultKeychainService if empty).
func NewKeychain(service string) *Keychain {
	if service == "" {
		service = DefaultKeychainService
	}
	chunk := 1 << 20
	if runtime.GOOS == "windows" {
		chunk = 2000
	}
	return &Keychain{service: service, chunkSize: chunk}
}

func (k *Keychain) Name() string { return "keychain" }

func (k *Keychain) Probe(context.Context) Probe {
	k.mu.Lock()
	defer k.mu.Unlock()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Probe{Reason: "random source unavailable"}
	}
	user := "probe-" + hex.EncodeToString(nonce[:])
	if err := keyring.Set(k.service, user, "probe"); err != nil {
		return Probe{Reason: "credential store unavailable: " + shortErr(err)}
	}
	defer func() { _ = keyring.Delete(k.service, user) }()
	if v, err := keyring.Get(k.service, user); err != nil || v != "probe" {
		return Probe{Reason: "credential store could not read back a test entry"}
	}
	return Probe{Available: true, Reason: keychainDescription(), Rank: 90}
}

func keychainDescription() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS Keychain"
	case "windows":
		return "Windows Credential Manager"
	default:
		return "Secret Service (D-Bus) keyring"
	}
}

func (k *Keychain) Put(_ context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	meta.Name = name
	meta.Backend = k.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	// Remove stale chunks from a previous larger record first.
	_ = k.deleteChunks(name)
	if len(rec) <= k.chunkSize {
		return wrapKeyring(keyring.Set(k.service, name, string(rec)))
	}
	n := (len(rec) + k.chunkSize - 1) / k.chunkSize
	for i := 0; i < n; i++ {
		start, end := i*k.chunkSize, min((i+1)*k.chunkSize, len(rec))
		if err := keyring.Set(k.service, chunkUser(name, i), string(rec[start:end])); err != nil {
			_ = k.deleteChunks(name)
			return wrapKeyring(err)
		}
	}
	return wrapKeyring(keyring.Set(k.service, name, chunkHeader+strconv.Itoa(n)))
}

const chunkHeader = "burndrop-chunks:"

func chunkUser(name string, i int) string { return name + "#" + strconv.Itoa(i) }

func (k *Keychain) Get(_ context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := keyring.Get(k.service, name)
	if err != nil {
		return nil, Metadata{}, wrapKeyring(err)
	}
	if strings.HasPrefix(s, chunkHeader) {
		n, err := strconv.Atoi(strings.TrimPrefix(s, chunkHeader))
		if err != nil || n <= 0 || n > 1000 {
			return nil, Metadata{}, fmt.Errorf("storage: keychain entry %q has a corrupt chunk header", name)
		}
		var sb strings.Builder
		for i := 0; i < n; i++ {
			part, err := keyring.Get(k.service, chunkUser(name, i))
			if err != nil {
				return nil, Metadata{}, fmt.Errorf("storage: keychain entry %q is missing chunk %d: %w", name, i, wrapKeyring(err))
			}
			sb.WriteString(part)
		}
		s = sb.String()
	}
	value, meta, err := decodeRecord([]byte(s))
	if err != nil {
		return nil, Metadata{}, err
	}
	return value, meta, nil
}

func (k *Keychain) Delete(_ context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := keyring.Get(k.service, name)
	if err != nil {
		return wrapKeyring(err)
	}
	if strings.HasPrefix(s, chunkHeader) {
		_ = k.deleteChunks(name)
	}
	return wrapKeyring(keyring.Delete(k.service, name))
}

// deleteChunks removes numbered chunk entries until the first gap.
func (k *Keychain) deleteChunks(name string) error {
	for i := 0; i < 1000; i++ {
		if err := keyring.Delete(k.service, chunkUser(name, i)); err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return nil
			}
			return wrapKeyring(err)
		}
	}
	return nil
}

// List is not supported: credential stores cannot be enumerated portably.
func (k *Keychain) List(context.Context) ([]Metadata, error) {
	return nil, ErrUnavailable
}

// GetRaw and SetRaw expose one named string entry for the age vault key.
func (k *Keychain) GetRaw(user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := keyring.Get(k.service, user)
	return s, wrapKeyring(err)
}

func (k *Keychain) SetRaw(user, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return wrapKeyring(keyring.Set(k.service, user, value))
}

func wrapKeyring(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, keyring.ErrUnsupportedPlatform):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	default:
		return fmt.Errorf("storage: keychain: %w", err)
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
