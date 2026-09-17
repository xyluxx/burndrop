// Package relay implements the burndrop relay: a zero-knowledge mailbox that
// stores ciphertext, token hashes, state, and expiry, and nothing else.
//
// Every state-changing operation is a POST with a JSON body. Identifiers and
// tokens never appear in URLs, so access logs contain no secrets by
// construction. See docs/design.md section 6 for the API and state machines.
package relay

import (
	"errors"
	"fmt"
	"time"

	"github.com/xyluxx/burndrop/internal/crypto"
)

// Kind distinguishes the two flows.
type Kind string

// Kinds.
const (
	KindDrop   Kind = "drop"   // human to agent
	KindReveal Kind = "reveal" // agent to human
)

// State is the lifecycle state of a slot.
type State string

// States. Drops go created, uploaded, fetched. Reveals go created, opened.
// Either can become revoked or expired from any live state.
const (
	StateCreated  State = "created"
	StateUploaded State = "uploaded"
	StateFetched  State = "fetched"
	StateOpened   State = "opened"
	StateRevoked  State = "revoked"
	StateExpired  State = "expired"
)

// Terminal reports whether no further transition is possible.
func (s State) Terminal() bool {
	switch s {
	case StateFetched, StateOpened, StateRevoked, StateExpired:
		return true
	}
	return false
}

// Drop is one slot. After a terminal transition it becomes a tombstone: the
// ciphertext and token hashes are cleared and only the state and timestamps
// remain, so both sides can render the distinct final state until expiry.
type Drop struct {
	ID         string
	Kind       Kind
	State      State
	Ciphertext []byte
	Commitment string      // SHA-256 of the recipient public key (drops only)
	TokenA     crypto.Hash // upload token (drop) or reveal token (reveal)
	TokenB     crypto.Hash // fetch token (drop) or revoke token (reveal)
	AgentKeyID string      // which agent key created it, for rate limiting
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UploadedAt time.Time
	FetchedAt  time.Time // fetch (drop) or open (reveal)
	RevokedAt  time.Time
}

// Status is what the status endpoint returns and what long polls wait on.
type Status struct {
	ID         string
	Kind       Kind
	State      State
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UploadedAt time.Time
	FetchedAt  time.Time
	RevokedAt  time.Time
}

// Stats describes store occupancy for limits and health.
type Stats struct {
	Live  int   // slots that are not tombstones
	Bytes int64 // ciphertext bytes held
	Total int   // slots including tombstones
}

// Errors returned by stores. Handlers map them to HTTP responses.
var (
	ErrNotFound   = errors.New("relay: not found")
	ErrBadToken   = errors.New("relay: bad token")
	ErrCommitment = errors.New("relay: commitment mismatch")
	ErrFull       = errors.New("relay: store full")
	ErrWrongKind  = errors.New("relay: wrong kind")
)

// StateError reports that an operation is not valid in the slot's current
// state, for example fetching before upload or opening twice.
type StateError struct {
	State State
	At    time.Time // when the state was entered, if known
}

func (e *StateError) Error() string {
	return fmt.Sprintf("relay: slot is %s", e.State)
}

// IsState reports whether err is a StateError for the given state.
func IsState(err error, s State) bool {
	var se *StateError
	return errors.As(err, &se) && se.State == s
}

func (d *Drop) status() Status {
	return Status{
		ID: d.ID, Kind: d.Kind, State: d.State,
		CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt,
		UploadedAt: d.UploadedAt, FetchedAt: d.FetchedAt, RevokedAt: d.RevokedAt,
	}
}

// stateError builds the error for the slot's current state.
func (d *Drop) stateError() *StateError {
	at := d.CreatedAt
	switch d.State {
	case StateUploaded:
		at = d.UploadedAt
	case StateFetched, StateOpened:
		at = d.FetchedAt
	case StateRevoked:
		at = d.RevokedAt
	case StateExpired:
		at = d.ExpiresAt
	}
	return &StateError{State: d.State, At: at}
}

// tombstone clears everything except state and timestamps.
func (d *Drop) tombstone(state State, at time.Time) {
	crypto.Zero(d.Ciphertext)
	d.Ciphertext = nil
	d.Commitment = ""
	d.TokenA = crypto.Hash{}
	d.TokenB = crypto.Hash{}
	d.State = state
	switch state {
	case StateFetched, StateOpened:
		d.FetchedAt = at
	case StateRevoked:
		d.RevokedAt = at
	}
}
