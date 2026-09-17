package relay

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xyluxx/burndrop/internal/crypto"
)

// runStoreSuite checks the Store contract against fresh stores from newStore.
// The memory store always runs it; the Redis store runs it when a server is
// configured. Every assertion here must hold for every implementation.
func runStoreSuite(t *testing.T, newStore func(t *testing.T, opts StoreOptions) Store) {
	t.Run("lifecycle", func(t *testing.T) { storeLifecycle(t, newStore) })
	t.Run("expiry", func(t *testing.T) { storeExpiryAndSweep(t, newStore) })
	t.Run("wait", func(t *testing.T) { storeWait(t, newStore) })
	t.Run("race", func(t *testing.T) { storeRace(t, newStore) })
}

func storeLifecycle(t *testing.T, newStore func(*testing.T, StoreOptions) Store) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(t, StoreOptions{MaxLive: 2, MaxBytes: 100, TombstoneGrace: time.Hour, Now: clock.Now})
	ctx := context.Background()
	d, up, fetch := newDrop(KindDrop, clock.Now(), time.Minute)
	if err := s.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, d); !errors.Is(err, ErrFull) {
		t.Fatalf("duplicate id: %v", err)
	}
	if _, _, err := s.Fetch(ctx, d.ID, crypto.HashToken(fetch)); !IsState(err, StateCreated) {
		t.Fatalf("fetch before upload: %v", err)
	}
	if err := s.Upload(ctx, d.ID, crypto.HashToken(fetch), "c", []byte("ct")); !errors.Is(err, ErrBadToken) {
		t.Fatalf("upload with fetch token: %v", err)
	}
	if err := s.Upload(ctx, d.ID, crypto.HashToken(up), "wrong", []byte("ct")); !errors.Is(err, ErrCommitment) {
		t.Fatalf("commitment: %v", err)
	}
	if err := s.Upload(ctx, d.ID, crypto.HashToken(up), "c", make([]byte, 101)); !errors.Is(err, ErrFull) {
		t.Fatalf("byte cap on upload: %v", err)
	}
	if err := s.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ct")); err != nil {
		t.Fatal(err)
	}
	if err := s.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ct")); !IsState(err, StateUploaded) {
		t.Fatalf("second upload: %v", err)
	}
	if st := s.Stats(); st.Live != 1 || st.Bytes != 2 || st.Total != 1 {
		t.Fatalf("stats: %+v", st)
	}
	ct, at, err := s.Fetch(ctx, d.ID, crypto.HashToken(fetch))
	if err != nil || string(ct) != "ct" || !at.Equal(clock.Now()) {
		t.Fatalf("fetch: %v %q", err, ct)
	}
	if _, _, err := s.Fetch(ctx, d.ID, crypto.HashToken(fetch)); !IsState(err, StateFetched) {
		t.Fatalf("second fetch: %v", err)
	}
	if err := s.Revoke(ctx, d.ID, crypto.HashToken(fetch)); !IsState(err, StateFetched) {
		t.Fatalf("revoke after fetch: %v", err)
	}
	st, err := s.Status(ctx, d.ID)
	if err != nil || st.State != StateFetched || st.FetchedAt.IsZero() || st.UploadedAt.IsZero() {
		t.Fatalf("status: %v %+v", err, st)
	}
	// Reveals and wrong kinds.
	r, reveal, revoke := newDrop(KindReveal, clock.Now(), time.Minute)
	if err := s.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.Upload(ctx, r.ID, crypto.HashToken(reveal), "c", []byte("x")); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("upload to reveal: %v", err)
	}
	if _, _, err := s.Fetch(ctx, r.ID, crypto.HashToken(reveal)); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("fetch reveal: %v", err)
	}
	if _, _, err := s.Open(ctx, d.ID, crypto.HashToken(reveal)); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("open drop: %v", err)
	}
	if _, _, err := s.Open(ctx, r.ID, crypto.HashToken(revoke)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("open with revoke token: %v", err)
	}
	if err := s.Revoke(ctx, r.ID, crypto.HashToken(revoke)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(ctx, r.ID, crypto.HashToken(reveal)); !IsState(err, StateRevoked) {
		t.Fatalf("open after revoke: %v", err)
	}
	if _, err := s.Status(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing id")
	}
	// Capacity: two tombstones do not count as live.
	for i := 0; i < 2; i++ {
		x, _, _ := newDrop(KindDrop, clock.Now(), time.Minute)
		if err := s.Create(ctx, x); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	x, _, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	if err := s.Create(ctx, x); !errors.Is(err, ErrFull) {
		t.Fatalf("live cap: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func storeExpiryAndSweep(t *testing.T, newStore func(*testing.T, StoreOptions) Store) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(t, StoreOptions{TombstoneGrace: time.Hour, Now: clock.Now})
	ctx := context.Background()
	d, up, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	_ = s.Create(ctx, d)
	_ = s.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ciphertext"))
	r, _, _ := newDrop(KindReveal, clock.Now(), 2*time.Minute)
	_ = s.Create(ctx, r)
	if n := s.Sweep(); n != 0 {
		t.Fatalf("premature sweep: %d", n)
	}
	clock.Advance(time.Minute)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("sweep at expiry: %d", n)
	}
	if st := s.Stats(); st.Live != 1 || st.Bytes != int64(len("reveal-ciphertext")) || st.Total != 2 {
		t.Fatalf("after first expiry: %+v", st)
	}
	st, _ := s.Status(ctx, d.ID)
	if st.State != StateExpired {
		t.Fatal("not expired")
	}
	// Lazy expiry without a sweep.
	clock.Advance(time.Minute)
	st, _ = s.Status(ctx, r.ID)
	if st.State != StateExpired {
		t.Fatal("lazy expiry failed")
	}
	if st := s.Stats(); st.Live != 0 || st.Bytes != 0 {
		t.Fatalf("lazy expiry did not free: %+v", st)
	}
	// Tombstones removed after the grace period, oldest first: the drop
	// expired at one minute, the reveal at two, so at 61 minutes only the
	// drop's tombstone is due.
	clock.Advance(59 * time.Minute)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("grace sweep: %d", n)
	}
	clock.Advance(time.Minute)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("second grace sweep: %d", n)
	}
	if s.Stats().Total != 0 {
		t.Fatal("tombstones remain")
	}
}

func storeWait(t *testing.T, newStore func(*testing.T, StoreOptions) Store) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(t, StoreOptions{Now: clock.Now})
	ctx := context.Background()
	d, up, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	_ = s.Create(ctx, d)
	// Immediate return when the state already differs.
	if st, err := s.Wait(ctx, d.ID, StateUploaded, time.Second); err != nil || st.State != StateCreated {
		t.Fatalf("immediate: %v %+v", err, st)
	}
	// Zero timeout never blocks.
	if st, _ := s.Wait(ctx, d.ID, StateCreated, 0); st.State != StateCreated {
		t.Fatal("zero timeout")
	}
	// Wakes on change.
	done := make(chan Status, 1)
	go func() {
		st, _ := s.Wait(ctx, d.ID, StateCreated, 5*time.Second)
		done <- st
	}()
	time.Sleep(50 * time.Millisecond)
	_ = s.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("x"))
	select {
	case st := <-done:
		if st.State != StateUploaded {
			t.Fatalf("woke with %s", st.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not wake")
	}
	// Context cancellation returns promptly with the current state.
	cctx, cancel := context.WithCancel(ctx)
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	if st, err := s.Wait(cctx, d.ID, StateUploaded, 5*time.Second); err != nil || st.State != StateUploaded || time.Since(start) > time.Second {
		t.Fatalf("cancel: %v %+v", err, st)
	}
	// Expiry wakes waiters too.
	go func() { time.Sleep(50 * time.Millisecond); clock.Advance(2 * time.Minute); s.Sweep() }()
	if st, _ := s.Wait(ctx, d.ID, StateUploaded, 5*time.Second); st.State != StateExpired {
		t.Fatalf("expiry wake: %s", st.State)
	}
	// The timeout returns the unchanged state, and not much later.
	d2, _, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	_ = s.Create(ctx, d2)
	start = time.Now()
	if st, err := s.Wait(ctx, d2.ID, StateCreated, 300*time.Millisecond); err != nil || st.State != StateCreated || time.Since(start) < 300*time.Millisecond || time.Since(start) > 2*time.Second {
		t.Fatalf("timeout: %v %+v after %s", err, st, time.Since(start))
	}
	if _, err := s.Wait(ctx, "missing", StateCreated, time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing id")
	}
}

// storeRace has many callers contend for one slot at once: exactly one
// upload, one fetch, and one open succeed, and every loser sees the state
// the winner left behind.
func storeRace(t *testing.T, newStore func(*testing.T, StoreOptions) Store) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	s := newStore(t, StoreOptions{Now: clock.Now})
	ctx := context.Background()
	const n = 32
	d, up, fetch := newDrop(KindDrop, clock.Now(), time.Minute)
	if err := s.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	wins := contend(t, n, func() error {
		return s.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ct"))
	}, func(err error) bool { return IsState(err, StateUploaded) })
	if wins != 1 {
		t.Fatalf("%d uploads succeeded, want exactly 1", wins)
	}
	wins = contend(t, n, func() error {
		ct, _, err := s.Fetch(ctx, d.ID, crypto.HashToken(fetch))
		if err == nil && string(ct) != "ct" {
			return errors.New("wrong ciphertext")
		}
		return err
	}, func(err error) bool { return IsState(err, StateFetched) })
	if wins != 1 {
		t.Fatalf("%d fetches succeeded, want exactly 1", wins)
	}
	r, reveal, _ := newDrop(KindReveal, clock.Now(), time.Minute)
	if err := s.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	wins = contend(t, n, func() error {
		_, _, err := s.Open(ctx, r.ID, crypto.HashToken(reveal))
		return err
	}, func(err error) bool { return IsState(err, StateOpened) })
	if wins != 1 {
		t.Fatalf("%d opens succeeded, want exactly 1", wins)
	}
	if st := s.Stats(); st.Live != 0 || st.Bytes != 0 || st.Total != 2 {
		t.Fatalf("stats after races: %+v", st)
	}
}

// contend runs op from n goroutines at once and returns how many succeeded.
// Every failure must satisfy lost.
func contend(t *testing.T, n int, op func() error, lost func(error) bool) int {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := op()
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else if !lost(err) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	return wins
}
