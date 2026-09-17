package relay

import (
	"container/heap"
	"context"
	"sync"
	"time"

	"github.com/xyluxx/burndrop/internal/crypto"
)

// Memory is the default store: a map guarded by one mutex. Nothing is ever
// written to disk. Atomicity of every operation is immediate because every
// method holds the lock for its whole duration.
type Memory struct {
	opts    StoreOptions
	mu      sync.Mutex
	drops   map[string]*Drop
	waiters map[string]map[chan struct{}]struct{}
	timers  expiryHeap
	live    int
	bytes   int64
}

// NewMemory creates an empty in-memory store.
func NewMemory(opts StoreOptions) *Memory {
	return &Memory{
		opts:    opts.withDefaults(),
		drops:   make(map[string]*Drop),
		waiters: make(map[string]map[chan struct{}]struct{}),
	}
}

// expiryEntry schedules either the expiry of a live slot or the removal of a
// tombstone.
type expiryEntry struct {
	at     time.Time
	id     string
	remove bool
}

type expiryHeap []expiryEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (m *Memory) Create(_ context.Context, d *Drop) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.drops[d.ID]; exists {
		return ErrFull // an ID collision is practically impossible; refuse rather than overwrite
	}
	if m.opts.MaxLive > 0 && m.live >= m.opts.MaxLive {
		return ErrFull
	}
	if m.opts.MaxBytes > 0 && m.bytes+int64(len(d.Ciphertext)) > m.opts.MaxBytes {
		return ErrFull
	}
	cp := *d
	cp.Ciphertext = append([]byte(nil), d.Ciphertext...)
	if cp.State == "" {
		cp.State = StateCreated
	}
	m.drops[cp.ID] = &cp
	m.live++
	m.bytes += int64(len(cp.Ciphertext))
	heap.Push(&m.timers, expiryEntry{at: cp.ExpiresAt, id: cp.ID})
	heap.Push(&m.timers, expiryEntry{at: cp.ExpiresAt.Add(m.opts.TombstoneGrace), id: cp.ID, remove: true})
	return nil
}

// get returns the slot, applying lazy expiry. Callers hold the lock.
func (m *Memory) get(id string) (*Drop, error) {
	d, ok := m.drops[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !d.State.Terminal() && !m.opts.Now().Before(d.ExpiresAt) {
		m.expire(d)
	}
	return d, nil
}

// expire moves a live slot to the expired tombstone state. Callers hold the lock.
func (m *Memory) expire(d *Drop) {
	m.bytes -= int64(len(d.Ciphertext))
	m.live--
	d.tombstone(StateExpired, d.ExpiresAt)
	m.notify(d.ID)
}

func (m *Memory) Upload(_ context.Context, id string, token crypto.Hash, commitment string, ciphertext []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.get(id)
	if err != nil {
		return err
	}
	if d.Kind != KindDrop {
		return ErrWrongKind
	}
	if d.State.Terminal() {
		return d.stateError()
	}
	if !crypto.HashEqual(d.TokenA, token) {
		return ErrBadToken
	}
	if d.State != StateCreated {
		return d.stateError()
	}
	if d.Commitment != commitment {
		return ErrCommitment
	}
	if m.opts.MaxBytes > 0 && m.bytes+int64(len(ciphertext)) > m.opts.MaxBytes {
		return ErrFull
	}
	d.Ciphertext = append([]byte(nil), ciphertext...)
	m.bytes += int64(len(d.Ciphertext))
	d.State = StateUploaded
	d.UploadedAt = m.opts.Now()
	// The upload token hash is kept so a replay with the right token is
	// reported as "already uploaded" rather than "bad token"; the state
	// check above makes it unusable either way.
	m.notify(id)
	return nil
}

func (m *Memory) Fetch(_ context.Context, id string, token crypto.Hash) ([]byte, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.get(id)
	if err != nil {
		return nil, time.Time{}, err
	}
	if d.Kind != KindDrop {
		return nil, time.Time{}, ErrWrongKind
	}
	if d.State.Terminal() {
		return nil, time.Time{}, d.stateError()
	}
	if !crypto.HashEqual(d.TokenB, token) {
		return nil, time.Time{}, ErrBadToken
	}
	if d.State != StateUploaded {
		return nil, time.Time{}, d.stateError()
	}
	ct := d.Ciphertext
	uploadedAt := d.UploadedAt
	m.bytes -= int64(len(ct))
	m.live--
	d.Ciphertext = nil // hand the only copy to the caller, then tombstone
	d.tombstone(StateFetched, m.opts.Now())
	m.notify(id)
	return ct, uploadedAt, nil
}

func (m *Memory) Open(_ context.Context, id string, token crypto.Hash) ([]byte, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.get(id)
	if err != nil {
		return nil, time.Time{}, err
	}
	if d.Kind != KindReveal {
		return nil, time.Time{}, ErrWrongKind
	}
	if d.State.Terminal() {
		return nil, time.Time{}, d.stateError()
	}
	if !crypto.HashEqual(d.TokenA, token) {
		return nil, time.Time{}, ErrBadToken
	}
	ct := d.Ciphertext
	createdAt := d.CreatedAt
	m.bytes -= int64(len(ct))
	m.live--
	d.Ciphertext = nil
	d.tombstone(StateOpened, m.opts.Now())
	m.notify(id)
	return ct, createdAt, nil
}

func (m *Memory) Revoke(_ context.Context, id string, token crypto.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.get(id)
	if err != nil {
		return err
	}
	if d.State.Terminal() {
		return d.stateError()
	}
	if !crypto.HashEqual(d.TokenA, token) && !crypto.HashEqual(d.TokenB, token) {
		return ErrBadToken
	}
	m.bytes -= int64(len(d.Ciphertext))
	m.live--
	d.tombstone(StateRevoked, m.opts.Now())
	m.notify(id)
	return nil
}

func (m *Memory) Status(_ context.Context, id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.get(id)
	if err != nil {
		return Status{}, err
	}
	return d.status(), nil
}

func (m *Memory) Wait(ctx context.Context, id string, current State, timeout time.Duration) (Status, error) {
	m.mu.Lock()
	d, err := m.get(id)
	if err != nil {
		m.mu.Unlock()
		return Status{}, err
	}
	if d.State != current || timeout <= 0 {
		st := d.status()
		m.mu.Unlock()
		return st, nil
	}
	ch := make(chan struct{}, 1)
	if m.waiters[id] == nil {
		m.waiters[id] = make(map[chan struct{}]struct{})
	}
	m.waiters[id][ch] = struct{}{}
	m.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	case <-ctx.Done():
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if ws := m.waiters[id]; ws != nil {
		delete(ws, ch)
		if len(ws) == 0 {
			delete(m.waiters, id)
		}
	}
	d, err = m.get(id)
	if err != nil {
		return Status{}, err
	}
	return d.status(), nil
}

// notify wakes every long poll on a slot. Callers hold the lock.
func (m *Memory) notify(id string) {
	for ch := range m.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (m *Memory) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.opts.Now()
	touched := 0
	for m.timers.Len() > 0 && !m.timers[0].at.After(now) {
		e := heap.Pop(&m.timers).(expiryEntry)
		d, ok := m.drops[e.id]
		if !ok {
			continue
		}
		if e.remove {
			delete(m.drops, e.id)
			delete(m.waiters, e.id)
			touched++
			continue
		}
		if !d.State.Terminal() {
			m.expire(d)
			touched++
		}
	}
	return touched
}

func (m *Memory) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{Live: m.live, Bytes: m.bytes, Total: len(m.drops)}
}

func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.drops {
		crypto.Zero(d.Ciphertext)
	}
	m.drops = make(map[string]*Drop)
	m.live, m.bytes = 0, 0
	return nil
}

// dump returns a copy of every slot for tests that verify nothing readable is
// stored. It is unexported on purpose: production code has no way to list slots.
func (m *Memory) dump() []Drop {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Drop, 0, len(m.drops))
	for _, d := range m.drops {
		cp := *d
		cp.Ciphertext = append([]byte(nil), d.Ciphertext...)
		out = append(out, cp)
	}
	return out
}
