// Package storage keeps the secrets an agent has received.
//
// One interface, Backend, with several implementations: the OS keychain, an
// age-encrypted vault file, external secret managers driven through their
// command line tools, process memory, and (opt-in, weakest) a .env file. A
// Manager sits in front of a backend to apply retention policies and to keep
// session-only secrets in memory.
//
// Values move between the relay client, this package, and subprocesses. They
// never pass through the language model.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Retention policies. See docs/design.md section 8.2.
const (
	RetentionSession      = "session"
	RetentionUntilRevoked = "until-revoked"
	RetentionUntilPrefix  = "until:"
)

// Where a stored value came from.
const (
	SourceDrop    = "drop"    // received from a human through a drop link
	SourceCapture = "capture" // captured from a subprocess with run_with_secret
	SourceImport  = "import"  // imported by the operator with the CLI
)

// MaxValueBytes is the largest value any backend must accept.
const MaxValueBytes = 64 * 1024

// Errors returned by backends and the Manager.
var (
	ErrNotFound    = errors.New("storage: secret not found")
	ErrUnavailable = errors.New("storage: backend unavailable")
	ErrInvalidName = errors.New("storage: invalid secret name")
	ErrTooLarge    = errors.New("storage: value too large")
	ErrPermission  = errors.New("storage: permission denied")
	ErrRetention   = errors.New("storage: invalid retention policy")
)

// Name rules: reference names are keys in external systems, so they are kept
// to a conservative character set.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// ValidateName reports whether name may be used as a secret reference.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: %q must be 1 to 100 characters of letters, digits, dot, underscore, or dash, starting with a letter or digit", ErrInvalidName, name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("%w: %q must not contain a double dot", ErrInvalidName, name)
	}
	return nil
}

// Metadata describes a stored secret without revealing its value. It is what
// list_secrets returns to the model.
type Metadata struct {
	Name        string    `json:"name"`
	Backend     string    `json:"backend"`
	Retention   string    `json:"retention"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	Purpose     string    `json:"purpose,omitempty"`
	Source      string    `json:"source"`
	Sendable    bool      `json:"sendable"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	SizeBytes   int       `json:"size_bytes"`
	// Kind distinguishes ordinary secrets ("" or "secret") from internal
	// records such as pending requests ("pending"), which list_secrets hides.
	Kind string `json:"kind,omitempty"`
}

// Record kinds.
const (
	KindSecret  = ""
	KindPending = "pending"
	// KindSent marks the record of an unopened reveal link: its revoke token
	// and expiry, never the key or the value.
	KindSent = "sent"
)

// Expired reports whether the entry has passed its expiry.
func (m Metadata) Expired(now time.Time) bool {
	return !m.ExpiresAt.IsZero() && !now.Before(m.ExpiresAt)
}

// ParseRetention validates a policy and returns the expiry it implies (zero
// for none).
func ParseRetention(policy string, now time.Time) (time.Time, error) {
	switch {
	case policy == RetentionSession, policy == RetentionUntilRevoked:
		return time.Time{}, nil
	case strings.HasPrefix(policy, RetentionUntilPrefix):
		t, err := time.Parse(time.RFC3339, strings.TrimPrefix(policy, RetentionUntilPrefix))
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: date must be RFC 3339, for example until:2027-01-31T00:00:00Z", ErrRetention)
		}
		if !t.After(now) {
			return time.Time{}, fmt.Errorf("%w: date is in the past", ErrRetention)
		}
		return t.UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("%w: %q (use session, until-revoked, or until:<RFC 3339 date>)", ErrRetention, policy)
	}
}

// Probe is the result of asking a backend whether it can be used here.
//
// Rank orders available backends when init recommends one. The ladder:
// password managers the user signed in to (onepassword 95, bitwarden 94),
// the OS credential store (keychain 90), team and cloud secret managers
// that happen to be logged in (infisical and doppler 86; vault, aws, gcp
// and azure 85), the age vault (80), memory (10), and a plain file (1).
// A logged-in cloud CLI must never outrank the local credential store: a
// laptop with an aws login should not be told to keep personal secrets in
// a cloud account it did not choose.
type Probe struct {
	Available bool
	Reason    string // one line for the operator, for example "signed in as ops@example.com"
	Rank      int    // higher means stronger; used to recommend a default
}

// Backend stores values with their metadata. Implementations must be safe for
// concurrent use and must return ErrNotFound for unknown names.
type Backend interface {
	// Name is the identifier used in configuration, for example "keychain".
	Name() string
	// Probe reports whether the backend is usable on this machine and why.
	Probe(ctx context.Context) Probe
	// Put stores or replaces a value. The backend stores value and meta
	// together so the value is never found without its context.
	Put(ctx context.Context, name string, value []byte, meta Metadata) error
	// Get returns the value and its metadata.
	Get(ctx context.Context, name string) ([]byte, Metadata, error)
	// Delete removes a secret. Deleting an unknown name returns ErrNotFound.
	Delete(ctx context.Context, name string) error
	// List returns metadata for every secret this backend holds, or
	// ErrUnavailable if the backend cannot enumerate (the Manager then falls
	// back to its local index).
	List(ctx context.Context) ([]Metadata, error)
}

// record is the JSON document a backend stores per secret.
type record struct {
	V     int      `json:"v"`
	Meta  Metadata `json:"meta"`
	Value []byte   `json:"value"`
}

func encodeRecord(meta Metadata, value []byte) ([]byte, error) {
	if len(value) > MaxValueBytes {
		return nil, ErrTooLarge
	}
	return json.Marshal(record{V: 1, Meta: meta, Value: value})
}

func decodeRecord(b []byte) ([]byte, Metadata, error) {
	var r record
	if err := json.Unmarshal(b, &r); err != nil || r.V != 1 {
		return nil, Metadata{}, fmt.Errorf("storage: stored record is not a burndrop record")
	}
	return r.Value, r.Meta, nil
}

// Zero overwrites b. Best effort in a garbage-collected language.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
