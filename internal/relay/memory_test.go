package relay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/xyluxx/burndrop/internal/crypto"
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

// TestMemoryStore runs the shared store suite and then checks what only the
// memory store promises: no leaked waiters, and Close discards everything.
func TestMemoryStore(t *testing.T) {
	var stores []*Memory
	runStoreSuite(t, func(t *testing.T, opts StoreOptions) Store {
		m := NewMemory(opts)
		stores = append(stores, m)
		return m
	})
	for _, m := range stores {
		m.mu.Lock()
		n := len(m.waiters)
		m.mu.Unlock()
		if n != 0 {
			t.Fatal("waiters leaked")
		}
	}
	m := NewMemory(StoreOptions{})
	d, _, _ := newDrop(KindReveal, time.Now(), time.Minute)
	if err := m.Create(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil || m.Stats().Total != 0 {
		t.Fatal("close must zero and empty the store")
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
