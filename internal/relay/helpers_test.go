package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/web"
)

// fakeClock lets tests move time forward deterministically.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testServer is a relay under test with an in-memory store, a fake clock, a
// captured log, and one configured agent key.
type testServer struct {
	t        *testing.T
	srv      *Server
	store    *Memory
	cfg      Config
	clock    *fakeClock
	logs     *bytes.Buffer
	logsMu   *sync.Mutex
	agentKey string
	http     *httptest.Server
}

type syncWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (s syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

const testOrigin = "https://drop.example.com"

func testPage() *web.Page {
	html := []byte("<!doctype html><html><head><title>burndrop</title></head><body><main>drop page</main></body></html>")
	return &web.Page{HTML: html, Meta: web.Meta{Version: "0.0.0-test", SHA256: "0000", ScriptSHA256: "scriptdigest", StyleSHA256: "styledigest", NeedsWasm: true}}
}

func newTestServer(t *testing.T, mutate func(*Config)) *testServer {
	t.Helper()
	key, err := crypto.RandomAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.PublicOrigin = testOrigin
	cfg.AgentKeys, _ = ParseAgentKeys(FormatAgentKey("test", key))
	// Generous limits by default so functional tests never trip them.
	cfg.RatePagePerMin, cfg.RateAgentPerMin, cfg.RateGlobalPerSec = 1e6, 1e6, 1e6
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)}
	logs := &bytes.Buffer{}
	mu := &sync.Mutex{}
	logger := slog.New(slog.NewJSONHandler(syncWriter{mu: mu, w: logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := NewMemory(StoreOptions{MaxLive: cfg.MaxLiveDrops, MaxBytes: cfg.MaxTotalBytes, Now: clock.Now})
	srv := New(cfg, store, Options{Page: testPage(), Version: "test", Now: clock.Now, Logger: logger})
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &testServer{t: t, srv: srv, store: store, cfg: cfg, clock: clock, logs: logs, logsMu: mu, agentKey: key, http: hs}
}

func (ts *testServer) logText() string {
	ts.logsMu.Lock()
	defer ts.logsMu.Unlock()
	return ts.logs.String()
}

type response struct {
	Status int
	Body   map[string]any
	Raw    []byte
	Header http.Header
}

func (r response) str(key string) string {
	v, _ := r.Body[key].(string)
	return v
}

type reqOption func(*http.Request)

func withAgent(key string) reqOption {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+key) }
}

func withOrigin(origin string) reqOption {
	return func(r *http.Request) { r.Header.Set("Origin", origin) }
}

func withHeader(k, v string) reqOption {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func withoutHeader(k string) reqOption {
	return func(r *http.Request) { r.Header.Del(k) }
}

// do sends a request with the standard API headers and decodes the response.
func (ts *testServer) do(method, path string, body any, opts ...reqOption) response {
	ts.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			ts.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, ts.http.URL+path, rd)
	if err != nil {
		ts.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(ClientHeader, "test/1")
	for _, o := range opts {
		o(req)
	}
	res, err := ts.http.Client().Do(req)
	if err != nil {
		ts.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := response{Status: res.StatusCode, Raw: raw, Header: res.Header}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(raw, &out.Body)
	}
	return out
}

func (ts *testServer) post(path string, body any, opts ...reqOption) response {
	ts.t.Helper()
	return ts.do(http.MethodPost, path, body, opts...)
}

func (ts *testServer) agent() reqOption { return withAgent(ts.agentKey) }

// dropSlot is a created drop with its tokens.
type dropSlot struct {
	ID, UploadToken, FetchToken, ExpiresAt string
}

func (ts *testServer) createDrop(commitment string, ttl int64) dropSlot {
	ts.t.Helper()
	res := ts.post("/api/v1/drops", map[string]any{"ttl_seconds": ttl, "commitment": commitment}, ts.agent())
	if res.Status != http.StatusCreated {
		ts.t.Fatalf("create drop: %d %s", res.Status, res.Raw)
	}
	return dropSlot{ID: res.str("drop_id"), UploadToken: res.str("upload_token"), FetchToken: res.str("fetch_token"), ExpiresAt: res.str("expires_at")}
}

type revealSlot struct {
	ID, RevealToken, RevokeToken, ExpiresAt string
}

func (ts *testServer) createReveal(ciphertext []byte, ttl int64) revealSlot {
	ts.t.Helper()
	res := ts.post("/api/v1/reveals", map[string]any{"ttl_seconds": ttl, "ciphertext": crypto.Encoding.EncodeToString(ciphertext)}, ts.agent())
	if res.Status != http.StatusCreated {
		ts.t.Fatalf("create reveal: %d %s", res.Status, res.Raw)
	}
	return revealSlot{ID: res.str("drop_id"), RevealToken: res.str("reveal_token"), RevokeToken: res.str("revoke_token"), ExpiresAt: res.str("expires_at")}
}

func (ts *testServer) upload(d dropSlot, commitment string, ciphertext []byte) response {
	ts.t.Helper()
	return ts.post("/api/v1/drops/upload", map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": commitment, "ciphertext": crypto.Encoding.EncodeToString(ciphertext)})
}

func (ts *testServer) fetch(d dropSlot) response {
	ts.t.Helper()
	return ts.post("/api/v1/drops/fetch", map[string]any{"drop_id": d.ID, "fetch_token": d.FetchToken}, ts.agent())
}

func (ts *testServer) open(r revealSlot) response {
	ts.t.Helper()
	return ts.post("/api/v1/reveals/open", map[string]any{"drop_id": r.ID, "reveal_token": r.RevealToken})
}

func (ts *testServer) status(kind Kind, id string) response {
	ts.t.Helper()
	return ts.post("/api/v1/"+string(kind)+"s/status", map[string]any{"drop_id": id})
}

// sealedFixture produces a realistic drop: an agent keypair, a sealed envelope,
// and the commitment the page would send.
type sealedFixture struct {
	pub, priv  *[32]byte
	commitment string
	envelope   crypto.Envelope
	ciphertext []byte
}

func newSealedFixture(t *testing.T, secret string) sealedFixture {
	t.Helper()
	pub, priv, err := crypto.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: "openai-api-key", Purpose: "Call the OpenAI API", Storage: "macOS Keychain", Retention: "until-revoked", Fingerprint: crypto.Fingerprint(pub[:]), Format: crypto.FormatText, Secret: secret}
	ct, err := crypto.SealEnvelope(pub, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sealedFixture{pub: pub, priv: priv, commitment: crypto.Commitment(pub[:]), envelope: env, ciphertext: ct}
}

func revealFixture(t *testing.T, secret string) (key *[32]byte, ct []byte) {
	t.Helper()
	key, err := crypto.NewSymmetricKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.Envelope{V: 1, Type: crypto.TypeReveal, Name: "staging-db-url", Format: crypto.FormatText, Secret: secret}
	ct, err = crypto.EncryptEnvelope(key, env, crypto.RevealAAD("MTIzNDU2Nzg5MGFiY2RlZg", "staging-db-url", false), nil)
	if err != nil {
		t.Fatal(err)
	}
	return key, ct
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := crypto.Encoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64url: %v", err)
	}
	return b
}
