package relay

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a set of token buckets keyed by string (client IP or agent key
// ID). Idle buckets are dropped so memory stays bounded.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   rate.Limit
	burst   int
	now     func() time.Time
	lastGC  time.Time
	idleTTL time.Duration
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewLimiter allows perMinute events per key on average with the given burst.
func NewLimiter(perMinute float64, burst int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		limit:   rate.Limit(perMinute / 60),
		burst:   burst,
		now:     now,
		lastGC:  now(),
		idleTTL: 10 * time.Minute,
	}
}

// Allow reports whether one more event for key is within the limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	if now.Sub(l.lastGC) > l.idleTTL {
		l.gc(now)
	}
	return b.lim.AllowN(now, 1)
}

func (l *Limiter) gc(now time.Time) {
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > l.idleTTL {
			delete(l.buckets, k)
		}
	}
}

// Global is a single token bucket for the whole relay.
type Global struct {
	lim *rate.Limiter
	now func() time.Time
}

// NewGlobal allows perSecond events with a burst of twice that.
func NewGlobal(perSecond float64, now func() time.Time) *Global {
	if now == nil {
		now = time.Now
	}
	burst := int(perSecond * 2)
	if burst < 1 {
		burst = 1
	}
	return &Global{lim: rate.NewLimiter(rate.Limit(perSecond), burst), now: now}
}

// Allow reports whether one more event is within the limit.
func (g *Global) Allow() bool { return g.lim.AllowN(g.now(), 1) }

// ClientIP returns the caller's address. X-Forwarded-For is honored only when
// the direct peer is a trusted proxy, and then the rightmost address that is
// not itself a trusted proxy is used, which is the only entry a client cannot
// forge.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !ipIn(peerIP, trusted) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip := net.ParseIP(candidate)
		if ip == nil {
			return peer
		}
		if !ipIn(ip, trusted) {
			return ip.String()
		}
	}
	return peer
}

func ipIn(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
