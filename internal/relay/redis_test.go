package relay

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/burndrop/burndrop/internal/crypto"
)

// redisTestEnv names the variable that points these tests at a server, for
// example redis://127.0.0.1:6379/0. Without it they are skipped.
const redisTestEnv = "BURNDROP_TEST_REDIS_URL"

func redisTestURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv(redisTestEnv)
	if url == "" {
		t.Skipf("set %s to a redis:// URL to run the Redis store tests", redisTestEnv)
	}
	return url
}

// newRedisTestStore opens a store under a prefix unique to the test. Keys
// left under it by an earlier run are cleared first and again on cleanup;
// nothing else in the database is touched.
func newRedisTestStore(t *testing.T, opts StoreOptions) Store {
	t.Helper()
	url := redisTestURL(t)
	prefix := "burndroptest:" + strings.ReplaceAll(t.Name(), "/", ":") + ":"
	clearRedisPrefix(t, url, prefix)
	s, err := newRedis(url, prefix, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.Close()
		clearRedisPrefix(t, url, prefix)
	})
	return s
}

func clearRedisPrefix(t *testing.T, url, prefix string) {
	t.Helper()
	ro, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(ro)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	var cursor uint64
	for {
		keys, next, err := c.Scan(ctx, cursor, prefix+"*", 500).Result()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) > 0 {
			if err := c.Del(ctx, keys...).Err(); err != nil {
				t.Fatal(err)
			}
		}
		if cursor = next; cursor == 0 {
			return
		}
	}
}

func TestRedisStore(t *testing.T) {
	redisTestURL(t)
	runStoreSuite(t, newRedisTestStore)
}

// The constructor fails clearly, without echoing the URL, when the server is
// unreachable or the URL is malformed. This needs no server.
func TestRedisStoreUnavailable(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store, cfg.RedisURL = "redis", "redis://127.0.0.1:1/0"
	if _, err := NewStore(cfg, time.Now); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("unreachable server: %v", err)
	}
	if _, err := NewRedis("http://127.0.0.1:6379", StoreOptions{}); err == nil {
		t.Fatal("wrong scheme accepted")
	}
	if _, err := NewRedis("redis://user:hunter2%zz@127.0.0.1:6379/0", StoreOptions{}); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("malformed URL: %v", err)
	}
}

// TestRedisHandlerFlow drives the HTTP handlers against a relay backed by
// Redis: create, upload, fetch, the second fetch that finds the slot gone, a
// reveal opened twice, revoke, expiry on the relay clock, a long poll, and
// the single-read race.
func TestRedisHandlerFlow(t *testing.T) {
	redisTestURL(t)
	ts := newTestServerWith(t, nil, newRedisTestStore)
	fx := newSealedFixture(t, "sk-live-secret-value")
	d := ts.createDrop(fx.commitment, 600)
	if res := ts.fetch(d); res.Status != http.StatusNotFound || res.str("error") != "not_uploaded" {
		t.Fatalf("fetch before upload: %d %s", res.Status, res.Raw)
	}
	other := newSealedFixture(t, "x")
	if res := ts.upload(d, other.commitment, other.ciphertext); res.Status != http.StatusUnprocessableEntity {
		t.Fatalf("commitment mismatch: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != 200 || res.str("state") != "uploaded" {
		t.Fatalf("upload: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != http.StatusConflict || res.str("error") != "already_uploaded" {
		t.Fatalf("second upload: %d %s", res.Status, res.Raw)
	}
	res := ts.fetch(d)
	if res.Status != 200 || res.str("uploaded_at") == "" {
		t.Fatalf("fetch: %d %s", res.Status, res.Raw)
	}
	env, err := crypto.OpenEnvelope(fx.pub, fx.priv, decodeB64(t, res.str("ciphertext")))
	if err != nil || env != fx.envelope {
		t.Fatalf("agent could not open: %v", err)
	}
	if res := ts.fetch(d); res.Status != http.StatusGone || res.str("state") != "fetched" || res.str("at") == "" {
		t.Fatalf("second fetch: %d %s", res.Status, res.Raw)
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "fetched" || st.str("fetched_at") == "" || st.str("uploaded_at") == "" {
		t.Fatalf("status after fetch: %s", st.Raw)
	}
	// A reveal opens exactly once.
	key, ct := revealFixture(t, "postgres://app:pw@db/app")
	r := ts.createReveal(ct, 300)
	res = ts.open(r)
	if res.Status != 200 || res.str("created_at") == "" {
		t.Fatalf("open: %d %s", res.Status, res.Raw)
	}
	if env, err := crypto.DecryptEnvelope(key, decodeB64(t, res.str("ciphertext")), crypto.RevealAAD("staging-db-url", false)); err != nil || env.Secret != "postgres://app:pw@db/app" {
		t.Fatalf("browser could not decrypt: %v", err)
	}
	if res := ts.open(r); res.Status != http.StatusGone || res.str("state") != "opened" || res.str("at") == "" {
		t.Fatalf("second open: %d %s", res.Status, res.Raw)
	}
	// Revoked with the human's token, the slot accepts nothing afterwards.
	d2 := ts.createDrop(fx.commitment, 0)
	if res := ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": d2.ID, "token": d2.UploadToken}); res.Status != 200 || res.str("state") != "revoked" {
		t.Fatalf("revoke: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(d2, fx.commitment, fx.ciphertext); res.Status != http.StatusGone || res.str("state") != "revoked" {
		t.Fatalf("upload after revoke: %d %s", res.Status, res.Raw)
	}
	if st := ts.slots.Stats(); st.Live != 0 || st.Bytes != 0 || st.Total != 3 {
		t.Fatalf("stats: %+v", st)
	}
	// Expiry follows the relay clock, and the sweep removes the tombstone
	// once the grace period is over.
	d3 := ts.createDrop(fx.commitment, 60)
	ts.upload(d3, fx.commitment, fx.ciphertext)
	ts.clock.Advance(60 * time.Second)
	if st := ts.status(KindDrop, d3.ID); st.str("state") != "expired" {
		t.Fatalf("status at expiry: %s", st.Raw)
	}
	if res := ts.fetch(d3); res.Status != http.StatusGone || res.str("state") != "expired" {
		t.Fatalf("fetch after expiry: %d %s", res.Status, res.Raw)
	}
	ts.clock.Advance(24 * time.Hour)
	if n := ts.slots.Sweep(); n != 1 {
		t.Fatalf("sweep removed %d", n)
	}
	if st := ts.status(KindDrop, d3.ID); st.Status != http.StatusNotFound {
		t.Fatalf("tombstone still present: %d", st.Status)
	}
	// A long poll wakes when the upload arrives.
	d4 := ts.createDrop(fx.commitment, 0)
	var wg sync.WaitGroup
	var polled response
	wg.Add(1)
	go func() {
		defer wg.Done()
		polled = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d4.ID, "wait_seconds": 10, "wait_while": "created"})
	}()
	time.Sleep(150 * time.Millisecond)
	start := time.Now()
	ts.upload(d4, fx.commitment, fx.ciphertext)
	wg.Wait()
	if polled.Status != 200 || polled.str("state") != "uploaded" || time.Since(start) > 5*time.Second {
		t.Fatalf("long poll: %d %s after %s", polled.Status, polled.Raw, time.Since(start))
	}
	// Readers racing for one drop: exactly one gets it.
	d5 := ts.createDrop(fx.commitment, 0)
	ts.upload(d5, fx.commitment, fx.ciphertext)
	const n = 32
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = ts.fetch(d5).Status
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, s := range statuses {
		switch s {
		case 200:
			wins++
		case http.StatusGone:
		default:
			t.Fatalf("unexpected status %d", s)
		}
	}
	if wins != 1 {
		t.Fatalf("%d fetches succeeded, want exactly 1", wins)
	}
	// Nothing on this path logs an identifier, a token, or ciphertext.
	logs := ts.logText()
	for _, f := range []string{d.ID, d.UploadToken, d.FetchToken, r.ID, r.RevealToken, r.RevokeToken, crypto.Encoding.EncodeToString(fx.ciphertext)} {
		if strings.Contains(logs, f) {
			t.Fatalf("log contains %q", f)
		}
	}
}
