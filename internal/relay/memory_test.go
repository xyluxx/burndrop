package relay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
)

func newDrop(kind Kind, now time.Time, ttl time.Duration) (*Drop, string, string) {
	id, _ := crypto.RandomToken()
	a, _ := crypto.RandomToken()
	b, _ := crypto.RandomToken()
	d := &Drop{ID: id, Kind: kind, State: StateCreated, TokenA: crypto.HashToken(a), TokenB: crypto.HashToken(b), CreatedAt: now, ExpiresAt: now.Add(ttl), Commitment: "c"}
	if kind == KindReveal {
		d.Ciphertext = []byte("reveal-ciphertext")
	}
	return d, a, b
}

func TestMemoryStoreLifecycle(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	m := NewMemory(StoreOptions{MaxLive: 2, MaxBytes: 100, TombstoneGrace: time.Hour, Now: clock.Now})
	ctx := context.Background()
	d, up, fetch := newDrop(KindDrop, clock.Now(), time.Minute)
	if err := m.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, d); !errors.Is(err, ErrFull) {
		t.Fatalf("duplicate id: %v", err)
	}
	if _, _, err := m.Fetch(ctx, d.ID, crypto.HashToken(fetch)); !IsState(err, StateCreated) {
		t.Fatalf("fetch before upload: %v", err)
	}
	if err := m.Upload(ctx, d.ID, crypto.HashToken(fetch), "c", []byte("ct")); !errors.Is(err, ErrBadToken) {
		t.Fatalf("upload with fetch token: %v", err)
	}
	if err := m.Upload(ctx, d.ID, crypto.HashToken(up), "wrong", []byte("ct")); !errors.Is(err, ErrCommitment) {
		t.Fatalf("commitment: %v", err)
	}
	if err := m.Upload(ctx, d.ID, crypto.HashToken(up), "c", make([]byte, 101)); !errors.Is(err, ErrFull) {
		t.Fatalf("byte cap on upload: %v", err)
	}
	if err := m.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ct")); err != nil {
		t.Fatal(err)
	}
	if err := m.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ct")); !IsState(err, StateUploaded) {
		t.Fatalf("second upload: %v", err)
	}
	if st := m.Stats(); st.Live != 1 || st.Bytes != 2 || st.Total != 1 {
		t.Fatalf("stats: %+v", st)
	}
	ct, at, err := m.Fetch(ctx, d.ID, crypto.HashToken(fetch))
	if err != nil || string(ct) != "ct" || !at.Equal(clock.Now()) {
		t.Fatalf("fetch: %v %q", err, ct)
	}
	if _, _, err := m.Fetch(ctx, d.ID, crypto.HashToken(fetch)); !IsState(err, StateFetched) {
		t.Fatalf("second fetch: %v", err)
	}
	if err := m.Revoke(ctx, d.ID, crypto.HashToken(fetch)); !IsState(err, StateFetched) {
		t.Fatalf("revoke after fetch: %v", err)
	}
	st, err := m.Status(ctx, d.ID)
	if err != nil || st.State != StateFetched || st.FetchedAt.IsZero() || st.UploadedAt.IsZero() {
		t.Fatalf("status: %v %+v", err, st)
	}
	// Reveals and wrong kinds.
	r, reveal, revoke := newDrop(KindReveal, clock.Now(), time.Minute)
	if err := m.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := m.Upload(ctx, r.ID, crypto.HashToken(reveal), "c", []byte("x")); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("upload to reveal: %v", err)
	}
	if _, _, err := m.Fetch(ctx, r.ID, crypto.HashToken(reveal)); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("fetch reveal: %v", err)
	}
	if _, _, err := m.Open(ctx, d.ID, crypto.HashToken(reveal)); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("open drop: %v", err)
	}
	if _, _, err := m.Open(ctx, r.ID, crypto.HashToken(revoke)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("open with revoke token: %v", err)
	}
	if err := m.Revoke(ctx, r.ID, crypto.HashToken(revoke)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Open(ctx, r.ID, crypto.HashToken(reveal)); !IsState(err, StateRevoked) {
		t.Fatalf("open after revoke: %v", err)
	}
	if _, err := m.Status(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing id")
	}
	// Capacity: two tombstones do not count as live.
	for i := 0; i < 2; i++ {
		x, _, _ := newDrop(KindDrop, clock.Now(), time.Minute)
		if err := m.Create(ctx, x); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	x, _, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	if err := m.Create(ctx, x); !errors.Is(err, ErrFull) {
		t.Fatalf("live cap: %v", err)
	}
	// Close zeroes and empties.
	if err := m.Close(); err != nil || m.Stats().Total != 0 {
		t.Fatal("close")
	}
}

func TestMemoryStoreExpiryAndSweep(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	m := NewMemory(StoreOptions{TombstoneGrace: time.Hour, Now: clock.Now})
	ctx := context.Background()
	d, up, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	_ = m.Create(ctx, d)
	_ = m.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("ciphertext"))
	r, _, _ := newDrop(KindReveal, clock.Now(), 2*time.Minute)
	_ = m.Create(ctx, r)
	if n := m.Sweep(); n != 0 {
		t.Fatalf("premature sweep: %d", n)
	}
	clock.Advance(time.Minute)
	if n := m.Sweep(); n != 1 {
		t.Fatalf("sweep at expiry: %d", n)
	}
	if st := m.Stats(); st.Live != 1 || st.Bytes != int64(len("reveal-ciphertext")) || st.Total != 2 {
		t.Fatalf("after first expiry: %+v", st)
	}
	st, _ := m.Status(ctx, d.ID)
	if st.State != StateExpired {
		t.Fatal("not expired")
	}
	// Lazy expiry without a sweep.
	clock.Advance(time.Minute)
	st, _ = m.Status(ctx, r.ID)
	if st.State != StateExpired {
		t.Fatal("lazy expiry failed")
	}
	if st := m.Stats(); st.Live != 0 || st.Bytes != 0 {
		t.Fatalf("lazy expiry did not free: %+v", st)
	}
	// Tombstones removed after the grace period, oldest first: the drop
	// expired at one minute, the reveal at two, so at 61 minutes only the
	// drop's tombstone is due.
	clock.Advance(59 * time.Minute)
	if n := m.Sweep(); n != 1 {
		t.Fatalf("grace sweep: %d", n)
	}
	clock.Advance(time.Minute)
	if n := m.Sweep(); n != 1 {
		t.Fatalf("second grace sweep: %d", n)
	}
	if m.Stats().Total != 0 {
		t.Fatal("tombstones remain")
	}
}

func TestMemoryStoreWait(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	m := NewMemory(StoreOptions{Now: clock.Now})
	ctx := context.Background()
	d, up, _ := newDrop(KindDrop, clock.Now(), time.Minute)
	_ = m.Create(ctx, d)
	// Immediate return when the state already differs.
	if st, err := m.Wait(ctx, d.ID, StateUploaded, time.Second); err != nil || st.State != StateCreated {
		t.Fatalf("immediate: %v %+v", err, st)
	}
	// Zero timeout never blocks.
	if st, _ := m.Wait(ctx, d.ID, StateCreated, 0); st.State != StateCreated {
		t.Fatal("zero timeout")
	}
	// Wakes on change.
	done := make(chan Status, 1)
	go func() {
		st, _ := m.Wait(ctx, d.ID, StateCreated, 5*time.Second)
		done <- st
	}()
	time.Sleep(50 * time.Millisecond)
	_ = m.Upload(ctx, d.ID, crypto.HashToken(up), "c", []byte("x"))
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
	if st, err := m.Wait(cctx, d.ID, StateUploaded, 5*time.Second); err != nil || st.State != StateUploaded || time.Since(start) > time.Second {
		t.Fatalf("cancel: %v %+v", err, st)
	}
	// Expiry wakes waiters too.
	go func() { time.Sleep(50 * time.Millisecond); clock.Advance(2 * time.Minute); m.Sweep() }()
	if st, _ := m.Wait(ctx, d.ID, StateUploaded, 5*time.Second); st.State != StateExpired {
		t.Fatalf("expiry wake: %s", st.State)
	}
	if _, err := m.Wait(ctx, "missing", StateCreated, time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing id")
	}
	if len(m.waiters) != 0 {
		t.Fatal("waiters leaked")
	}
}

func TestClientIP(t *testing.T) {
	_, proxy, _ := net.ParseCIDR("10.0.0.0/8")
	trusted := []*net.IPNet{proxy}
	req := func(remote, xff string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.5:1234", "", "203.0.113.5"},
		{"203.0.113.5:1234", "198.51.100.1", "203.0.113.5"}, // untrusted peer: header ignored
		{"10.1.2.3:1234", "", "10.1.2.3"},
		{"10.1.2.3:1234", "198.51.100.1", "198.51.100.1"},
		{"10.1.2.3:1234", "198.51.100.1, 10.9.9.9", "198.51.100.1"}, // proxies chain: rightmost untrusted
		{"10.1.2.3:1234", "1.1.1.1, 198.51.100.1, 10.9.9.9", "198.51.100.1"},
		{"10.1.2.3:1234", "garbage", "10.1.2.3"},
		{"10.1.2.3:1234", "10.5.5.5", "10.1.2.3"}, // only proxies in the chain
		{"[::1]:9", "", "::1"},
		{"bad", "", "bad"},
	}
	for _, c := range cases {
		if got := ClientIP(req(c.remote, c.xff), trusted); got != c.want {
			t.Fatalf("remote %q xff %q: got %q want %q", c.remote, c.xff, got, c.want)
		}
	}
}

func TestLimiter(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := NewLimiter(60, 2, clock.Now) // 1 per second, burst 2
	if !l.Allow("a") || !l.Allow("a") || l.Allow("a") {
		t.Fatal("burst not enforced")
	}
	if !l.Allow("b") {
		t.Fatal("keys must be independent")
	}
	clock.Advance(time.Second)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("refill wrong")
	}
	clock.Advance(20 * time.Minute)
	l.Allow("c")
	if _, ok := l.buckets["a"]; ok {
		t.Fatal("idle bucket not collected")
	}
	if NewLimiter(1, 0, nil).burst != 1 {
		t.Fatal("burst floor")
	}
	g := NewGlobal(1, clock.Now)
	if !g.Allow() || !g.Allow() || g.Allow() {
		t.Fatal("global burst")
	}
	if NewGlobal(0.1, nil).lim.Burst() != 1 {
		t.Fatal("global burst floor")
	}
}

func TestStateHelpers(t *testing.T) {
	for _, s := range []State{StateFetched, StateOpened, StateRevoked, StateExpired} {
		if !s.Terminal() {
			t.Fatal(s)
		}
	}
	for _, s := range []State{StateCreated, StateUploaded} {
		if s.Terminal() {
			t.Fatal(s)
		}
	}
	err := (&StateError{State: StateOpened}).Error()
	if err != "relay: slot is opened" {
		t.Fatal(err)
	}
	if IsState(errors.New("x"), StateOpened) {
		t.Fatal("IsState on plain error")
	}
}
