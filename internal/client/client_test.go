package client

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/internal/relay"
)

const testKey = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func newRelay(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	cfg := relay.DefaultConfig()
	cfg.PublicOrigin = "http://127.0.0.1"
	cfg.AgentKeys = []relay.AgentKey{{ID: "test", Hash: crypto.HashToken(testKey)}}
	cfg.RateAgentPerMin = 10000
	cfg.RatePagePerMin = 10000
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := relay.NewStore(cfg, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.New(cfg, store, relay.Options{Version: "test"}).Handler())
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testKey, "burndrop-test/1")
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestNew(t *testing.T) {
	for _, bad := range []string{"", "ftp://x", "http://example.com", "relay.example", "https://relay.example/path"} {
		if _, err := New(bad, "", ""); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	c, err := New("HTTPS://Relay.Example:443/", "", "")
	if err != nil || c.Origin != "https://relay.example" || c.Name != "burndrop-go" {
		t.Fatalf("normalize: %v %+v", err, c)
	}
}

func TestDropFlow(t *testing.T) {
	ctx := context.Background()
	_, c := newRelay(t)
	info, err := c.Info(ctx)
	if err != nil || info.API != "v1" || info.Version != "test" || info.AgentAuth != "required" {
		t.Fatalf("info: %v %+v", err, info)
	}
	pub, priv, err := crypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	commitment := crypto.Commitment(pub[:])
	d, err := c.CreateDrop(ctx, commitment, 2*time.Minute)
	if err != nil || len(d.ID) != 22 || len(d.UploadToken) != 22 || len(d.FetchToken) != 22 || d.ExpiresAt.IsZero() {
		t.Fatalf("create: %v %+v", err, d)
	}
	st, err := c.DropStatus(ctx, d.ID, 0, "")
	if err != nil || st.State != StateCreated || st.Kind != "drop" || st.Terminal() {
		t.Fatalf("status: %v %+v", err, st)
	}
	// Fetch before upload.
	if _, _, err := c.Fetch(ctx, d.ID, d.FetchToken); !IsCode(err, CodeNotUploaded) {
		t.Fatalf("early fetch: %v", err)
	}
	// Long poll returns as soon as the upload lands.
	var wg sync.WaitGroup
	wg.Add(1)
	var waited Status
	var waitErr error
	go func() {
		defer wg.Done()
		waited, waitErr = c.WaitForUpload(ctx, d.ID, time.Now().Add(20*time.Second))
	}()
	env := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: "api-key", Purpose: "test", Storage: "memory", Retention: "session", Fingerprint: crypto.Fingerprint(pub[:]), Format: crypto.FormatText, Secret: "hunter2"}
	sealed, err := crypto.SealEnvelope(pub, env, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := c.Upload(ctx, d.ID, d.UploadToken, commitment, sealed); err != nil {
		t.Fatalf("upload: %v", err)
	}
	wg.Wait()
	if waitErr != nil || waited.State != StateUploaded || waited.UploadedAt.IsZero() {
		t.Fatalf("wait: %v %+v", waitErr, waited)
	}
	if err := c.Upload(ctx, d.ID, d.UploadToken, commitment, sealed); !IsCode(err, CodeAlreadyUploaded) {
		t.Fatalf("second upload: %v", err)
	}
	ct, uploadedAt, err := c.Fetch(ctx, d.ID, d.FetchToken)
	if err != nil || uploadedAt.IsZero() {
		t.Fatalf("fetch: %v", err)
	}
	got, err := crypto.OpenEnvelope(pub, priv, ct)
	if err != nil || got.Secret != "hunter2" {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := c.Fetch(ctx, d.ID, d.FetchToken); !IsCode(err, CodeGone) {
		t.Fatalf("second fetch: %v", err)
	}
	var relayErr *Error
	err = c.RevokeDrop(ctx, d.ID, d.FetchToken)
	if !errors.As(err, &relayErr) || relayErr.State != StateFetched || relayErr.At.IsZero() || relayErr.Status != http.StatusGone {
		t.Fatalf("revoke after fetch: %v", err)
	}
	if relayErr.Error() == "" {
		t.Fatal("error text")
	}
	// Revoke a fresh drop with the upload token.
	d2, _ := c.CreateDrop(ctx, commitment, 0)
	if err := c.RevokeDrop(ctx, d2.ID, d2.UploadToken); err != nil {
		t.Fatal(err)
	}
	if st, err := c.DropStatus(ctx, d2.ID, 0, ""); err != nil || st.State != StateRevoked || !st.Terminal() {
		t.Fatalf("revoked status: %v %+v", err, st)
	}
	// Wait on a terminal drop returns at once.
	if st, err := c.WaitForUpload(ctx, d2.ID, time.Now().Add(5*time.Second)); err != nil || st.State != StateRevoked {
		t.Fatalf("wait terminal: %v %+v", err, st)
	}
	// Deadline passes with no change.
	d3, _ := c.CreateDrop(ctx, commitment, 0)
	if _, err := c.WaitForUpload(ctx, d3.ID, time.Now().Add(1100*time.Millisecond)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	// Unknown ids and bad tokens.
	if _, err := c.DropStatus(ctx, "MTIzNDU2Nzg5MGFiY2RlZg", 0, ""); !IsCode(err, CodeNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, _, err := c.Fetch(ctx, d3.ID, d3.UploadToken); !IsCode(err, CodeBadToken) {
		t.Fatalf("bad token: %v", err)
	}
	// Unauthenticated agent calls.
	anon, _ := New(c.Origin, "", "")
	if _, err := anon.CreateDrop(ctx, commitment, 0); !IsCode(err, CodeUnauthorized) {
		t.Fatalf("no key: %v", err)
	}
}

func TestRevealFlow(t *testing.T) {
	ctx := context.Background()
	_, c := newRelay(t)
	key, _ := crypto.NewSymmetricKey(rand.Reader)
	aad := crypto.RevealAAD("db-password", false)
	env := crypto.Envelope{V: 1, Type: crypto.TypeReveal, Name: "db-password", Format: crypto.FormatText, Secret: "s3cret"}
	ct, err := crypto.EncryptEnvelope(key, env, aad, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.CreateReveal(ctx, ct, time.Hour)
	if err != nil || len(r.ID) != 22 || len(r.RevealToken) != 22 || len(r.RevokeToken) != 22 {
		t.Fatalf("create reveal: %v %+v", err, r)
	}
	if st, err := c.RevealStatus(ctx, r.ID, 0, ""); err != nil || st.State != StateCreated || st.Kind != "reveal" {
		t.Fatalf("status: %v %+v", err, st)
	}
	done := make(chan Status, 1)
	go func() {
		st, _ := c.WaitForOpen(ctx, r.ID, time.Now().Add(20*time.Second))
		done <- st
	}()
	time.Sleep(200 * time.Millisecond)
	got, createdAt, err := c.Open(ctx, r.ID, r.RevealToken)
	if err != nil || createdAt.IsZero() {
		t.Fatalf("open: %v", err)
	}
	if opened, err := crypto.DecryptEnvelope(key, got, aad); err != nil || opened.Secret != "s3cret" {
		t.Fatalf("decrypt: %v", err)
	}
	select {
	case st := <-done:
		if st.State != StateOpened || st.OpenedAt.IsZero() {
			t.Fatalf("wait for open: %+v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait for open did not return")
	}
	if _, _, err := c.Open(ctx, r.ID, r.RevealToken); !IsCode(err, CodeGone) {
		t.Fatalf("second open: %v", err)
	}
	r2, _ := c.CreateReveal(ctx, ct, 0)
	if err := c.RevokeReveal(ctx, r2.ID, r2.RevokeToken); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Open(ctx, r2.ID, r2.RevealToken); !IsCode(err, CodeGone) {
		t.Fatalf("open revoked: %v", err)
	}
}

func TestPageHashAndErrors(t *testing.T) {
	ctx := context.Background()
	_, c := newRelay(t)
	// No page is embedded in tests, so the relay answers 503.
	if _, err := c.PageHash(ctx); err == nil {
		t.Fatal("expected page unavailable")
	}
	// A non-JSON error body still yields a usable error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	defer bad.Close()
	bc, _ := New(bad.URL, "", "")
	if _, err := bc.Info(ctx); !IsCode(err, "http_502") {
		t.Fatalf("non-json error: %v", err)
	}
	// Malformed success bodies are reported.
	weird := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/drops/fetch" {
			_, _ = w.Write([]byte(`{"ciphertext":"***","uploaded_at":"x"}`))
			return
		}
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer weird.Close()
	wc, _ := New(weird.URL, "k", "")
	if _, err := wc.Info(ctx); err == nil {
		t.Fatal("malformed body accepted")
	}
	if _, _, err := wc.Fetch(ctx, "MTIzNDU2Nzg5MGFiY2RlZg", "MTIzNDU2Nzg5MGFiY2RlZg"); err == nil {
		t.Fatal("malformed ciphertext accepted")
	}
	if _, _, err := wc.Open(ctx, "MTIzNDU2Nzg5MGFiY2RlZg", "MTIzNDU2Nzg5MGFiY2RlZg"); err == nil {
		t.Fatal("malformed open accepted")
	}
	// Connection failures wrap the transport error.
	down, _ := New("http://127.0.0.1:1", "", "")
	down.HTTP = &http.Client{Timeout: time.Second}
	if _, err := down.Info(ctx); err == nil {
		t.Fatal("expected a connection error")
	}
	// The wait loop tolerates transient server errors, then gives up.
	var calls int
	var mu sync.Mutex
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal_error"}`))
	}))
	defer flaky.Close()
	fc, _ := New(flaky.URL, "", "")
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := fc.WaitForUpload(cctx, "MTIzNDU2Nzg5MGFiY2RlZg", time.Now().Add(time.Minute))
	if err == nil || time.Since(start) < time.Second {
		t.Fatalf("flaky wait: %v after %s", err, time.Since(start))
	}
	mu.Lock()
	if calls < 2 {
		t.Fatalf("expected retries, got %d calls", calls)
	}
	mu.Unlock()
	// Wait over the relay maximum is clamped.
	_, c2 := newRelay(t)
	d, _ := c2.CreateDrop(ctx, crypto.Commitment(make([]byte, 32)), 0)
	if _, err := c2.DropStatus(ctx, d.ID, time.Hour, "uploaded"); err != nil {
		t.Fatalf("clamped wait: %v", err)
	}
}
