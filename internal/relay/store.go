package relay

import (
	"context"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
)

// Store is the slot storage contract. Every method that reads or changes a
// slot is atomic with respect to every other method on the same slot, which
// is what makes "read exactly once" hold under concurrent requests.
//
// Implementations must treat a slot whose expiry has passed as expired on
// every call, without waiting for Sweep.
type Store interface {
	// Create inserts a new slot in state created. It fails with ErrFull when a
	// capacity limit would be exceeded.
	Create(ctx context.Context, d *Drop) error

	// Upload stores ciphertext in a drop slot. It verifies the upload token and
	// the key commitment, consumes the token, and moves the slot to uploaded.
	Upload(ctx context.Context, id string, token crypto.Hash, commitment string, ciphertext []byte) error

	// Fetch returns and deletes a drop's ciphertext in one step, verifying the
	// fetch token. Before upload it returns a StateError for created.
	Fetch(ctx context.Context, id string, token crypto.Hash) (ciphertext []byte, uploadedAt time.Time, err error)

	// Open returns and deletes a reveal's ciphertext in one step, verifying the
	// reveal token.
	Open(ctx context.Context, id string, token crypto.Hash) (ciphertext []byte, createdAt time.Time, err error)

	// Revoke moves a live slot to revoked. Either of the slot's two tokens is
	// accepted, so both the human and the agent can cancel.
	Revoke(ctx context.Context, id string, token crypto.Hash) error

	// Status returns the current state of any known slot, tombstones included.
	Status(ctx context.Context, id string) (Status, error)

	// Wait returns as soon as the slot's state differs from current, or after
	// timeout, or when ctx is done. It never blocks longer than timeout.
	Wait(ctx context.Context, id string, current State, timeout time.Duration) (Status, error)

	// Sweep expires slots whose time has passed, frees their ciphertext, and
	// removes tombstones older than the grace period. It returns the number of
	// slots touched.
	Sweep() int

	// Stats reports occupancy.
	Stats() Stats

	// Close releases resources.
	Close() error
}

// StoreOptions configure capacity limits and the clock for any Store.
type StoreOptions struct {
	MaxLive        int           // maximum non-tombstone slots (0 means unlimited)
	MaxBytes       int64         // maximum total ciphertext bytes (0 means unlimited)
	TombstoneGrace time.Duration // how long terminal states stay visible after expiry
	Now            func() time.Time
}

func (o StoreOptions) withDefaults() StoreOptions {
	if o.TombstoneGrace == 0 {
		o.TombstoneGrace = 24 * time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}
