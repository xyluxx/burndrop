package relay

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
)

func TestDropFlow(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "sk-live-secret-value")
	d := ts.createDrop(fx.commitment, 600)
	if !crypto.ValidToken(d.ID) || !crypto.ValidToken(d.UploadToken) || !crypto.ValidToken(d.FetchToken) {
		t.Fatalf("malformed tokens: %+v", d)
	}
	if d.ExpiresAt != ts.clock.Now().Add(600*time.Second).Format(time.RFC3339) {
		t.Fatalf("expires_at %q", d.ExpiresAt)
	}
	if st := ts.status(KindDrop, d.ID); st.Status != 200 || st.str("state") != "created" || st.str("kind") != "drop" {
		t.Fatalf("status: %d %s", st.Status, st.Raw)
	}
	if res := ts.fetch(d); res.Status != http.StatusNotFound || res.str("error") != "not_uploaded" || res.str("state") != "created" {
		t.Fatalf("fetch before upload: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != 200 || res.str("state") != "uploaded" {
		t.Fatalf("upload: %d %s", res.Status, res.Raw)
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "uploaded" || st.str("uploaded_at") == "" {
		t.Fatalf("status after upload: %s", st.Raw)
	}
	res := ts.fetch(d)
	if res.Status != 200 {
		t.Fatalf("fetch: %d %s", res.Status, res.Raw)
	}
	got := decodeB64(t, res.str("ciphertext"))
	if !bytes.Equal(got, fx.ciphertext) {
		t.Fatal("ciphertext changed in transit")
	}
	env, err := crypto.OpenEnvelope(fx.pub, fx.priv, got)
	if err != nil || env != fx.envelope {
		t.Fatalf("agent could not open: %v", err)
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "fetched" || st.str("fetched_at") == "" {
		t.Fatalf("status after fetch: %s", st.Raw)
	}
	// Everything after the single fetch is gone.
	if res := ts.fetch(d); res.Status != http.StatusGone || res.str("error") != "gone" || res.str("state") != "fetched" || res.str("at") == "" {
		t.Fatalf("second fetch: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != http.StatusGone || res.str("state") != "fetched" {
		t.Fatalf("upload after fetch: %d %s", res.Status, res.Raw)
	}
	if res := ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": d.ID, "token": d.FetchToken}); res.Status != http.StatusGone {
		t.Fatalf("revoke after fetch: %d %s", res.Status, res.Raw)
	}
	if st := ts.store.Stats(); st.Live != 0 || st.Bytes != 0 || st.Total != 1 {
		t.Fatalf("stats after flow: %+v", st)
	}
}

func TestRevealFlow(t *testing.T) {
	ts := newTestServer(t, nil)
	key, ct := revealFixture(t, "postgres://app:pw@db/app")
	r := ts.createReveal(ct, 300)
	if st := ts.status(KindReveal, r.ID); st.str("state") != "created" || st.str("kind") != "reveal" {
		t.Fatalf("status: %s", st.Raw)
	}
	res := ts.open(r)
	if res.Status != 200 || res.str("created_at") == "" {
		t.Fatalf("open: %d %s", res.Status, res.Raw)
	}
	env, err := crypto.DecryptEnvelope(key, decodeB64(t, res.str("ciphertext")), crypto.RevealAAD("staging-db-url", false))
	if err != nil || env.Secret != "postgres://app:pw@db/app" {
		t.Fatalf("browser could not decrypt: %v", err)
	}
	if res := ts.open(r); res.Status != http.StatusGone || res.str("state") != "opened" || res.str("at") == "" {
		t.Fatalf("second open must report already opened: %d %s", res.Status, res.Raw)
	}
	if st := ts.status(KindReveal, r.ID); st.str("state") != "opened" || st.str("opened_at") == "" {
		t.Fatalf("status after open: %s", st.Raw)
	}
	if st := ts.store.Stats(); st.Live != 0 || st.Bytes != 0 {
		t.Fatalf("ciphertext not released: %+v", st)
	}
}

func TestUploadTwiceAndCommitment(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != 200 {
		t.Fatal(res.Status)
	}
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != http.StatusConflict || res.str("error") != "already_uploaded" {
		t.Fatalf("second upload: %d %s", res.Status, res.Raw)
	}
	// A link whose key was swapped produces a different commitment: rejected.
	other := newSealedFixture(t, "s")
	d2 := ts.createDrop(fx.commitment, 0)
	if res := ts.upload(d2, other.commitment, other.ciphertext); res.Status != http.StatusUnprocessableEntity || res.str("error") != "commitment_mismatch" {
		t.Fatalf("swapped key accepted: %d %s", res.Status, res.Raw)
	}
	// The slot is still usable by the honest page afterwards.
	if res := ts.upload(d2, fx.commitment, fx.ciphertext); res.Status != 200 {
		t.Fatalf("honest upload after mismatch: %d %s", res.Status, res.Raw)
	}
}

func TestBadTokens(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	wrong, _ := crypto.RandomToken()
	if res := ts.upload(dropSlot{ID: d.ID, UploadToken: wrong}, fx.commitment, fx.ciphertext); res.Status != http.StatusForbidden || res.str("error") != "bad_token" {
		t.Fatalf("wrong upload token: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(dropSlot{ID: d.ID, UploadToken: d.FetchToken}, fx.commitment, fx.ciphertext); res.Status != http.StatusForbidden {
		t.Fatal("fetch token accepted for upload")
	}
	ts.upload(d, fx.commitment, fx.ciphertext)
	if res := ts.fetch(dropSlot{ID: d.ID, FetchToken: wrong}); res.Status != http.StatusForbidden {
		t.Fatalf("wrong fetch token: %d", res.Status)
	}
	if res := ts.fetch(dropSlot{ID: d.ID, FetchToken: d.UploadToken}); res.Status != http.StatusForbidden {
		t.Fatal("upload token accepted for fetch")
	}
	if res := ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": d.ID, "token": wrong}); res.Status != http.StatusForbidden {
		t.Fatalf("wrong revoke token: %d", res.Status)
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "uploaded" {
		t.Fatal("bad tokens must not change state")
	}
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	if res := ts.open(revealSlot{ID: r.ID, RevealToken: r.RevokeToken}); res.Status != http.StatusForbidden {
		t.Fatal("revoke token accepted for open")
	}
	if res := ts.open(revealSlot{ID: r.ID, RevealToken: wrong}); res.Status != http.StatusForbidden {
		t.Fatal("wrong reveal token accepted")
	}
	unknown, _ := crypto.RandomToken()
	if res := ts.status(KindDrop, unknown); res.Status != http.StatusNotFound {
		t.Fatalf("unknown id: %d", res.Status)
	}
}

func TestRevokeByEitherSide(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	// Human cancels with the upload token.
	d := ts.createDrop(fx.commitment, 0)
	if res := ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": d.ID, "token": d.UploadToken}); res.Status != 200 || res.str("state") != "revoked" {
		t.Fatalf("revoke by human: %d %s", res.Status, res.Raw)
	}
	if res := ts.upload(d, fx.commitment, fx.ciphertext); res.Status != http.StatusGone || res.str("state") != "revoked" {
		t.Fatalf("upload after revoke: %d %s", res.Status, res.Raw)
	}
	if res := ts.fetch(d); res.Status != http.StatusGone || res.str("state") != "revoked" {
		t.Fatalf("fetch after revoke: %d %s", res.Status, res.Raw)
	}
	// Agent cancels with the fetch token, even after upload.
	d2 := ts.createDrop(fx.commitment, 0)
	ts.upload(d2, fx.commitment, fx.ciphertext)
	if res := ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": d2.ID, "token": d2.FetchToken}); res.Status != 200 {
		t.Fatalf("revoke by agent: %d %s", res.Status, res.Raw)
	}
	if st := ts.store.Stats(); st.Bytes != 0 {
		t.Fatal("revoked ciphertext not released")
	}
	// Reveals: human with the reveal token, agent with the revoke token.
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	if res := ts.post("/api/v1/reveals/revoke", map[string]any{"drop_id": r.ID, "token": r.RevokeToken}); res.Status != 200 {
		t.Fatalf("agent revoke reveal: %d %s", res.Status, res.Raw)
	}
	if res := ts.open(r); res.Status != http.StatusGone || res.str("state") != "revoked" {
		t.Fatalf("open after revoke: %d %s", res.Status, res.Raw)
	}
	r2 := ts.createReveal(ct, 0)
	if res := ts.post("/api/v1/reveals/revoke", map[string]any{"drop_id": r2.ID, "token": r2.RevealToken}); res.Status != 200 {
		t.Fatalf("human revoke reveal: %d %s", res.Status, res.Raw)
	}
	// Wrong kind on the revoke endpoint is a 404.
	if res := ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": r2.ID, "token": r2.RevealToken}); res.Status != http.StatusNotFound {
		t.Fatalf("reveal on drops endpoint: %d", res.Status)
	}
}

func TestExpiry(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 60)
	ts.upload(d, fx.commitment, fx.ciphertext)
	ts.clock.Advance(59 * time.Second)
	if st := ts.status(KindDrop, d.ID); st.str("state") != "uploaded" {
		t.Fatal("expired too early")
	}
	ts.clock.Advance(1 * time.Second)
	if st := ts.status(KindDrop, d.ID); st.str("state") != "expired" {
		t.Fatalf("status at expiry: %s", st.Raw)
	}
	if res := ts.fetch(d); res.Status != http.StatusGone || res.str("state") != "expired" {
		t.Fatalf("fetch after expiry: %d %s", res.Status, res.Raw)
	}
	if st := ts.store.Stats(); st.Bytes != 0 || st.Live != 0 {
		t.Fatalf("expired ciphertext still held: %+v", st)
	}
	// Tombstone stays visible through the grace period, then disappears.
	ts.clock.Advance(23 * time.Hour)
	ts.store.Sweep()
	if st := ts.status(KindDrop, d.ID); st.str("state") != "expired" {
		t.Fatal("tombstone removed too early")
	}
	ts.clock.Advance(2 * time.Hour)
	if n := ts.store.Sweep(); n != 1 {
		t.Fatalf("sweep removed %d", n)
	}
	if st := ts.status(KindDrop, d.ID); st.Status != http.StatusNotFound {
		t.Fatalf("tombstone still present: %d", st.Status)
	}
	// A reveal that expires unopened.
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 60)
	ts.clock.Advance(61 * time.Second)
	if res := ts.open(r); res.Status != http.StatusGone || res.str("state") != "expired" {
		t.Fatalf("open after expiry: %d %s", res.Status, res.Raw)
	}
}

func TestTTLClamp(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.DefaultTTL = 30 * time.Minute; c.MaxTTL = 2 * time.Hour })
	fx := newSealedFixture(t, "s")
	now := ts.clock.Now()
	cases := map[int64]time.Duration{0: 30 * time.Minute, -5: 30 * time.Minute, 10: MinTTL, 3600: time.Hour, 99999999: 2 * time.Hour}
	for ttl, want := range cases {
		d := ts.createDrop(fx.commitment, ttl)
		if d.ExpiresAt != now.Add(want).Format(time.RFC3339) {
			t.Fatalf("ttl %d: got %s want %s", ttl, d.ExpiresAt, now.Add(want).Format(time.RFC3339))
		}
	}
}

func TestAgentAuth(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	body := map[string]any{"commitment": fx.commitment}
	if res := ts.post("/api/v1/drops", body); res.Status != http.StatusUnauthorized || res.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no bearer: %d", res.Status)
	}
	if res := ts.post("/api/v1/drops", body, withAgent("wrong-key-wrong-key-wrong")); res.Status != http.StatusUnauthorized {
		t.Fatalf("wrong bearer: %d", res.Status)
	}
	if res := ts.post("/api/v1/drops", body, withHeader("Authorization", "Basic abc")); res.Status != http.StatusUnauthorized {
		t.Fatalf("basic auth: %d", res.Status)
	}
	if res := ts.post("/api/v1/drops", body, withHeader("Authorization", "bearer "+ts.agentKey)); res.Status != http.StatusCreated {
		t.Fatalf("case-insensitive scheme: %d %s", res.Status, res.Raw)
	}
	d := ts.createDrop(fx.commitment, 0)
	ts.upload(d, fx.commitment, fx.ciphertext)
	if res := ts.post("/api/v1/drops/fetch", map[string]any{"drop_id": d.ID, "fetch_token": d.FetchToken}); res.Status != http.StatusUnauthorized {
		t.Fatalf("fetch without bearer: %d", res.Status)
	}
	_, ct := revealFixture(t, "v")
	if res := ts.post("/api/v1/reveals", map[string]any{"ciphertext": crypto.Encoding.EncodeToString(ct)}); res.Status != http.StatusUnauthorized {
		t.Fatalf("reveal without bearer: %d", res.Status)
	}
	// With auth off, anonymous creation works and a bearer is still accepted.
	open := newTestServer(t, func(c *Config) { c.AgentAuth = "off"; c.AgentKeys = nil })
	if res := open.post("/api/v1/drops", body); res.Status != http.StatusCreated {
		t.Fatalf("auth off: %d %s", res.Status, res.Raw)
	}
}

func TestRequestValidation(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	good := map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": crypto.Encoding.EncodeToString(fx.ciphertext)}
	cases := []struct {
		name   string
		body   any
		opts   []reqOption
		status int
		code   string
	}{
		{"missing client header", good, []reqOption{withoutHeader(ClientHeader)}, 400, "missing_client_header"},
		{"wrong content type", good, []reqOption{withHeader("Content-Type", "text/plain")}, 415, "unsupported_media_type"},
		{"form content type", good, []reqOption{withHeader("Content-Type", "application/x-www-form-urlencoded")}, 415, "unsupported_media_type"},
		{"malformed json", `{"drop_id": `, nil, 400, "bad_request"},
		{"empty body", "", nil, 400, "bad_request"},
		{"unknown field", `{"drop_id":"` + d.ID + `","upload_token":"` + d.UploadToken + `","commitment":"` + fx.commitment + `","ciphertext":"AAAA","evil":1}`, nil, 400, "bad_request"},
		{"trailing data", `{"drop_id":"x"} {}`, nil, 400, "bad_request"},
		{"wrong type", `{"drop_id": 5}`, nil, 400, "bad_request"},
		{"short id", map[string]any{"drop_id": "abc", "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": "AAAA"}, nil, 400, "bad_request"},
		{"bad commitment", map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": "nope", "ciphertext": "AAAA"}, nil, 400, "bad_request"},
		{"empty ciphertext", map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": ""}, nil, 400, "bad_request"},
		{"ciphertext not base64url", map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": "+++/=="}, nil, 400, "bad_request"},
		{"ciphertext too short", map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": "AAAA"}, nil, 400, "bad_request"},
		{"ciphertext too large", map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": strings.Repeat("A", ts.cfg.MaxCiphertextBytes*4/3+100)}, nil, 413, "too_large"},
	}
	for _, c := range cases {
		res := ts.post("/api/v1/drops/upload", c.body, c.opts...)
		if res.Status != c.status || res.str("error") != c.code {
			t.Fatalf("%s: got %d %s, want %d %s", c.name, res.Status, res.Raw, c.status, c.code)
		}
		if bytes.Contains(res.Raw, []byte(d.UploadToken)) || bytes.Contains(res.Raw, []byte(d.ID)) {
			t.Fatalf("%s: error response echoes request values", c.name)
		}
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "created" {
		t.Fatal("invalid requests must not change state")
	}
	if res := ts.post("/api/v1/drops", map[string]any{"commitment": "short"}, ts.agent()); res.Status != 400 {
		t.Fatalf("create with bad commitment: %d", res.Status)
	}
	if res := ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID, "wait_seconds": 31}); res.Status != 400 {
		t.Fatalf("wait too long: %d", res.Status)
	}
	if res := ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID, "wait_seconds": -1}); res.Status != 400 {
		t.Fatalf("negative wait: %d", res.Status)
	}
	// Oversized raw body is rejected before parsing.
	huge := `{"ciphertext":"` + strings.Repeat("A", int(AbsoluteMaxBody)) + `"}`
	if res := ts.post("/api/v1/reveals", huge, ts.agent()); res.Status != 413 {
		t.Fatalf("huge body: %d", res.Status)
	}
}

func TestWrongKind(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	if res := ts.open(revealSlot{ID: d.ID, RevealToken: d.UploadToken}); res.Status != http.StatusNotFound {
		t.Fatalf("drop id on open: %d", res.Status)
	}
	if res := ts.upload(dropSlot{ID: r.ID, UploadToken: r.RevealToken}, fx.commitment, fx.ciphertext); res.Status != http.StatusNotFound {
		t.Fatalf("reveal id on upload: %d", res.Status)
	}
	if res := ts.status(KindReveal, d.ID); res.Status != http.StatusNotFound {
		t.Fatalf("drop id on reveal status: %d", res.Status)
	}
	if res := ts.status(KindDrop, r.ID); res.Status != http.StatusNotFound {
		t.Fatalf("reveal id on drop status: %d", res.Status)
	}
}

func TestLongPoll(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.MaxWaiters = 2 })
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	// Waiting for a state the slot is no longer in returns at once.
	start := time.Now()
	if res := ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID, "wait_seconds": 5, "wait_while": "uploaded"}); res.str("state") != "created" || time.Since(start) > time.Second {
		t.Fatalf("wait_while mismatch should return immediately: %s", res.Raw)
	}
	// A real wait wakes up when the upload arrives.
	var wg sync.WaitGroup
	wg.Add(1)
	var res response
	go func() {
		defer wg.Done()
		res = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID, "wait_seconds": 10, "wait_while": "created"})
	}()
	time.Sleep(150 * time.Millisecond)
	ts.upload(d, fx.commitment, fx.ciphertext)
	wg.Wait()
	if res.Status != 200 || res.str("state") != "uploaded" || time.Since(start) > 5*time.Second {
		t.Fatalf("long poll: %d %s after %s", res.Status, res.Raw, time.Since(start))
	}
	// The agent waits for the fetch; the page waits for delivery.
	wg.Add(1)
	go func() {
		defer wg.Done()
		res = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID, "wait_seconds": 10})
	}()
	time.Sleep(100 * time.Millisecond)
	ts.fetch(d)
	wg.Wait()
	if res.str("state") != "fetched" {
		t.Fatalf("page did not see delivery: %s", res.Raw)
	}
	// Timeout returns the unchanged state.
	d2 := ts.createDrop(fx.commitment, 0)
	start = time.Now()
	if res := ts.post("/api/v1/drops/status", map[string]any{"drop_id": d2.ID, "wait_seconds": 1}); res.str("state") != "created" || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("timeout: %s after %s", res.Raw, time.Since(start))
	}
	// Waiter cap: two waiters fill it, the third is turned away at once.
	var waiters sync.WaitGroup
	for i := 0; i < 2; i++ {
		waiters.Add(1)
		go func() {
			defer waiters.Done()
			ts.post("/api/v1/drops/status", map[string]any{"drop_id": d2.ID, "wait_seconds": 2})
		}()
	}
	time.Sleep(200 * time.Millisecond)
	if res := ts.post("/api/v1/drops/status", map[string]any{"drop_id": d2.ID, "wait_seconds": 3}); res.Status != http.StatusServiceUnavailable || res.str("error") != "too_many_waiters" {
		t.Fatalf("waiter cap: %d %s", res.Status, res.Raw)
	}
	waiters.Wait()
	// Terminal states never wait.
	start = time.Now()
	if res := ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID, "wait_seconds": 5}); res.str("state") != "fetched" || time.Since(start) > time.Second {
		t.Fatal("terminal state should not wait")
	}
}

func TestStoreFull(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.MaxLiveDrops = 1 })
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	if res := ts.post("/api/v1/drops", map[string]any{"commitment": fx.commitment}, ts.agent()); res.Status != http.StatusServiceUnavailable || res.str("error") != "store_full" || res.Header.Get("Retry-After") == "" {
		t.Fatalf("second create: %d %s", res.Status, res.Raw)
	}
	ts.post("/api/v1/drops/revoke", map[string]any{"drop_id": d.ID, "token": d.UploadToken})
	if res := ts.post("/api/v1/drops", map[string]any{"commitment": fx.commitment}, ts.agent()); res.Status != http.StatusCreated {
		t.Fatalf("create after revoke: %d", res.Status)
	}
	// Byte cap: MaxTotalBytes must hold at least one ciphertext but not two.
	tsb := newTestServer(t, func(c *Config) { c.MaxTotalBytes = int64(c.MaxCiphertextBytes) })
	big := bytes.Repeat([]byte{1}, tsb.cfg.MaxCiphertextBytes)
	tsb.createReveal(big, 0)
	if res := tsb.post("/api/v1/reveals", map[string]any{"ciphertext": crypto.Encoding.EncodeToString(big)}, tsb.agent()); res.Status != http.StatusServiceUnavailable {
		t.Fatalf("byte cap: %d %s", res.Status, res.Raw)
	}
}

func TestRateLimits(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.RatePagePerMin = 3; c.RateAgentPerMin = 3 })
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	// Page limit: burst is RatePagePerMin/3+1 = 2 requests, then 429 (the clock is frozen).
	var last response
	limited := false
	for i := 0; i < 5; i++ {
		last = ts.status(KindDrop, d.ID)
		if last.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited || last.str("error") != "rate_limited" || last.Header.Get("Retry-After") == "" {
		t.Fatalf("page rate limit not enforced: %d %s", last.Status, last.Raw)
	}
	ts.clock.Advance(time.Minute)
	if res := ts.status(KindDrop, d.ID); res.Status != 200 {
		t.Fatalf("limit did not recover: %d", res.Status)
	}
	limited = false
	for i := 0; i < 5; i++ {
		if res := ts.post("/api/v1/drops", map[string]any{"commitment": fx.commitment}, ts.agent()); res.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("agent rate limit not enforced")
	}
	// Global limit.
	tg := newTestServer(t, func(c *Config) { c.RateGlobalPerSec = 1 })
	limited = false
	for i := 0; i < 5; i++ {
		if res := tg.do(http.MethodGet, "/healthz", nil); res.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("global rate limit not enforced")
	}
}

func TestCORS(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.PageOrigins = []string{"https://page.example.org", testOrigin} })
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	res := ts.do(http.MethodOptions, "/api/v1/drops/status", nil, withOrigin("https://page.example.org"), withHeader("Access-Control-Request-Method", "POST"))
	if res.Status != http.StatusNoContent || res.Header.Get("Access-Control-Allow-Origin") != "https://page.example.org" || !strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), ClientHeader) {
		t.Fatalf("preflight allowed origin: %d %v", res.Status, res.Header)
	}
	res = ts.do(http.MethodOptions, "/api/v1/drops/status", nil, withOrigin("https://evil.example"), withHeader("Access-Control-Request-Method", "POST"))
	if res.Status != http.StatusForbidden || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("preflight evil origin: %d %v", res.Status, res.Header)
	}
	res = ts.status(KindDrop, d.ID)
	if res.Status != 200 || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no Origin header must mean no CORS headers and normal processing")
	}
	res = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID}, withOrigin(testOrigin))
	if res.Status != 200 || res.Header.Get("Access-Control-Allow-Origin") != testOrigin || !strings.Contains(res.Header.Get("Vary"), "Origin") {
		t.Fatalf("allowed origin post: %d %v", res.Status, res.Header)
	}
	res = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID}, withOrigin("https://evil.example"))
	if res.Status != http.StatusForbidden || res.str("error") != "origin_not_allowed" {
		t.Fatalf("evil origin post: %d %s", res.Status, res.Raw)
	}
	// The bundled page of the browser extension runs on an extension origin
	// that cannot be listed in advance; it is admitted and echoed back.
	for _, ext := range []string{"chrome-extension://abcdefghijklmnopabcdefghijklmnop", "moz-extension://0f4a7b3c-2d9e-4f1a-8b6c-5d2e3f4a5b6c"} {
		res = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID}, withOrigin(ext))
		if res.Status != 200 || res.Header.Get("Access-Control-Allow-Origin") != ext {
			t.Fatalf("extension origin %s: %d %v", ext, res.Status, res.Header)
		}
		res = ts.do(http.MethodOptions, "/api/v1/drops/status", nil, withOrigin(ext), withHeader("Access-Control-Request-Method", "POST"))
		if res.Status != http.StatusNoContent || res.Header.Get("Access-Control-Allow-Origin") != ext {
			t.Fatalf("extension preflight %s: %d %v", ext, res.Status, res.Header)
		}
	}
	for _, bad := range []string{"chrome-extension://", "chrome-extension://abc/def", "chrome-extension://ABC DEF", "moz-extension://" + strings.Repeat("a", 65), "https://chrome-extension.example", "chrome-extension:abc"} {
		res = ts.post("/api/v1/drops/status", map[string]any{"drop_id": d.ID}, withOrigin(bad))
		if res.Status != http.StatusForbidden {
			t.Fatalf("malformed extension origin %q accepted: %d", bad, res.Status)
		}
	}
}

func TestSecurityHeadersAndPage(t *testing.T) {
	ts := newTestServer(t, nil)
	for _, path := range []string{"/", "/drop", "/reveal"} {
		res := ts.do(http.MethodGet, path, nil)
		if res.Status != 200 || !bytes.Contains(res.Raw, []byte("drop page")) {
			t.Fatalf("%s: %d", path, res.Status)
		}
		csp := res.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'sha256-scriptdigest' 'wasm-unsafe-eval'", "style-src 'sha256-styledigest'", "connect-src 'self'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Fatalf("%s: CSP missing %q: %s", path, want, csp)
			}
		}
		h := res.Header
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" ||
			h.Get("X-Frame-Options") != "DENY" || h.Get("Cross-Origin-Opener-Policy") != "same-origin" || h.Get("X-Drop-Page-Version") != "0.0.0-test" || h.Get("X-Request-Id") == "" {
			t.Fatalf("%s: headers %v", path, h)
		}
		if h.Get("Strict-Transport-Security") != "" {
			t.Fatal("HSTS must not be set on plain http")
		}
	}
	res := ts.do(http.MethodGet, "/drop", nil, withHeader("X-Forwarded-Proto", "https"))
	if !strings.HasPrefix(res.Header.Get("Strict-Transport-Security"), "max-age=31536000") {
		t.Fatal("HSTS missing behind an https proxy")
	}
	res = ts.do(http.MethodHead, "/reveal", nil)
	if res.Status != 200 || len(res.Raw) != 0 {
		t.Fatalf("HEAD page: %d %d bytes", res.Status, len(res.Raw))
	}
	res = ts.do(http.MethodGet, "/api/v1/info", nil)
	if res.Status != 200 || res.str("page_sha256") != "0000" || res.str("agent_auth") != "required" || res.Body["long_poll_max_seconds"].(float64) != 30 {
		t.Fatalf("info: %d %s", res.Status, res.Raw)
	}
	if res := ts.do(http.MethodGet, "/healthz", nil); res.Status != 200 || string(res.Raw) != "ok\n" {
		t.Fatalf("healthz: %d %q", res.Status, res.Raw)
	}
	if res := ts.do(http.MethodGet, "/nope", nil); res.Status != http.StatusNotFound {
		t.Fatalf("unknown route: %d", res.Status)
	}
	noPage := newTestServer(t, func(c *Config) { c.ServePage = false })
	if res := noPage.do(http.MethodGet, "/drop", nil); res.Status != http.StatusNotFound {
		t.Fatalf("page disabled: %d", res.Status)
	}
	// Page enabled but not built: a clear 503, never a broken page.
	cfg := DefaultConfig()
	cfg.PublicOrigin = testOrigin
	cfg.AgentAuth = "off"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, NewMemory(StoreOptions{}), Options{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/drop", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not built") {
		t.Fatalf("unbuilt page: %d %s", rec.Code, rec.Body.String())
	}
}

// panicStore makes every call panic so the recovery middleware can be tested.
type panicStore struct{ Store }

func (panicStore) Status(_ context.Context, _ string) (Status, error) { panic("boom") }

func TestPanicRecovery(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.srv.store = panicStore{ts.store}
	id, _ := crypto.RandomToken()
	res := ts.status(KindDrop, id)
	if res.Status != http.StatusInternalServerError || res.str("error") != "internal_error" {
		t.Fatalf("panic: %d %s", res.Status, res.Raw)
	}
	if !strings.Contains(ts.logText(), `"panic":"boom"`) {
		t.Fatal("panic not logged")
	}
}

func TestAnonymousAgentsAreMeteredPerAddress(t *testing.T) {
	ts := newTestServer(t, func(c *Config) {
		c.AgentAuth = "off"
		c.AgentKeys = nil
		c.RateAgentPerMin = 3
		c.TrustedProxies = mustCIDRs("127.0.0.1/32", "::1/128")
	})
	fx := newSealedFixture(t, "s")
	body := map[string]any{"commitment": fx.commitment}
	from := func(addr string) reqOption { return withHeader("X-Forwarded-For", addr) }
	limited := false
	for i := 0; i < 5; i++ {
		if res := ts.post("/api/v1/drops", body, from("198.51.100.7")); res.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("anonymous agent calls are not rate limited")
	}
	// Another address has its own bucket: one open relay client cannot lock
	// out the others.
	if res := ts.post("/api/v1/drops", body, from("198.51.100.8")); res.Status != http.StatusCreated {
		t.Fatalf("a different address shares the anonymous bucket: %d %s", res.Status, res.Raw)
	}
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	nets, err := parseCIDRs(strings.Join(cidrs, ","))
	if err != nil {
		panic(err)
	}
	return nets
}
