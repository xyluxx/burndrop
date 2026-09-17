package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xyluxx/burndrop/internal/client"
	"github.com/xyluxx/burndrop/internal/crypto"
	"github.com/xyluxx/burndrop/internal/link"
	"github.com/xyluxx/burndrop/internal/relay"
	"github.com/xyluxx/burndrop/internal/storage"
)

const testKey = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

type harness struct {
	agent   *Agent
	relay   *client.Client
	backend *storage.Memory
	audit   *Audit
	clock   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg := relay.DefaultConfig()
	cfg.PublicOrigin = "http://127.0.0.1"
	cfg.AgentKeys = []relay.AgentKey{{ID: "test", Hash: crypto.HashToken(testKey)}}
	cfg.RateAgentPerMin = 10000
	cfg.RatePagePerMin = 10000
	cfg.DefaultTTL = time.Hour
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := relay.NewStore(cfg, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.New(cfg, store, relay.Options{Version: "test"}).Handler())
	t.Cleanup(srv.Close)
	rc, err := client.New(srv.URL, testKey, "burndrop-test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	idx, err := storage.OpenIndex(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := storage.NewMemory()
	h := &harness{relay: rc, backend: backend, clock: time.Now()}
	manager := storage.NewManager(backend, idx, func() time.Time { return h.clock })
	audit, err := NewAudit(filepath.Join(dir, "audit.log"), func() time.Time { return h.clock })
	if err != nil {
		t.Fatal(err)
	}
	h.audit = audit
	acfg := Config{Relay: srv.URL, Storage: "memory"}
	if err := acfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.agent = New(acfg, rc, manager, audit)
	h.agent.Now = func() time.Time { return h.clock }
	return h
}

// submit plays the human: parse the link, seal the value, upload it.
func (h *harness) submit(t *testing.T, url, value string, mutate func(*crypto.Envelope)) link.Drop {
	t.Helper()
	d, origin, err := link.ParseDrop(url)
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	if origin != h.relay.Origin {
		t.Fatalf("page origin %q, want %q", origin, h.relay.Origin)
	}
	pub, err := crypto.KeyFromBytes(d.RecipientKey)
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: d.Name, Purpose: d.Purpose, Storage: d.Storage, Retention: d.Retention, Fingerprint: d.Fingerprint(), Format: crypto.FormatText, Secret: value}
	if mutate != nil {
		mutate(&env)
	}
	sealed, err := crypto.SealEnvelope(pub, env, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.relay.Upload(context.Background(), d.ID, d.UploadToken, crypto.Commitment(d.RecipientKey), sealed); err != nil {
		t.Fatalf("upload: %v", err)
	}
	return d
}

func (h *harness) events(t *testing.T) []Event {
	t.Helper()
	ev, err := h.audit.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestRequestFetchStore(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent

	// Validation.
	if _, err := a.Request(ctx, RequestInput{Name: "bad name", Purpose: "x"}); !errors.Is(err, storage.ErrInvalidName) {
		t.Fatalf("name: %v", err)
	}
	if _, err := a.Request(ctx, RequestInput{Name: "k", Purpose: "  "}); err == nil {
		t.Fatal("empty purpose accepted")
	}
	if _, err := a.Request(ctx, RequestInput{Name: "k", Purpose: "p", Retention: "forever"}); !errors.Is(err, storage.ErrRetention) {
		t.Fatalf("retention: %v", err)
	}
	if _, err := a.Request(ctx, RequestInput{Name: "k", Purpose: "p", TTL: "soon"}); err == nil {
		t.Fatal("bad ttl accepted")
	}

	out, err := a.Request(ctx, RequestInput{Name: "openai-api-key", Purpose: "Call the OpenAI API for the nightly report", TTL: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestID == "" || !strings.HasPrefix(out.Link, h.relay.Origin+"/drop#") || out.Storage != "memory" || out.Retention != storage.RetentionUntilRevoked {
		t.Fatalf("request output: %+v", out)
	}
	if !strings.Contains(out.Message, out.Link) || !strings.Contains(out.Message, out.Fingerprint) || !strings.Contains(out.Message, "opens once") && !strings.Contains(out.Message, "works once") {
		t.Fatalf("message lacks disclosures: %s", out.Message)
	}
	if time.Until(out.ExpiresAt) > 31*time.Minute || time.Until(out.ExpiresAt) < 25*time.Minute {
		t.Fatalf("ttl not applied: %s", out.ExpiresAt)
	}
	pending, err := a.Pending(ctx)
	if err != nil || len(pending) != 1 || pending[0].RequestID != out.RequestID || pending[0].Fingerprint != out.Fingerprint {
		t.Fatalf("pending: %v %+v", err, pending)
	}
	// Pending records are hidden from the secret list.
	if list, _ := a.List(ctx); len(list) != 0 {
		t.Fatalf("pending leaked into list: %+v", list)
	}

	// Nothing submitted yet: waiting.
	f, err := a.Fetch(ctx, FetchInput{RequestID: out.RequestID, WaitSeconds: 1})
	if err != nil || f.Status != StatusWaiting || f.Name != "openai-api-key" {
		t.Fatalf("waiting: %v %+v", err, f)
	}
	// With one pending request the id may be omitted.
	f, err = a.Fetch(ctx, FetchInput{WaitSeconds: 1})
	if err != nil || f.Status != StatusWaiting {
		t.Fatalf("implicit id: %v %+v", err, f)
	}

	// The human submits.
	h.submit(t, out.Link, "sk-live-secret-value-123", nil)
	f, err = a.Fetch(ctx, FetchInput{RequestID: out.RequestID})
	if err != nil || f.Status != StatusStored || f.Storage != "memory" || f.SizeBytes != len("sk-live-secret-value-123") || f.Fingerprint != out.Fingerprint {
		t.Fatalf("stored: %v %+v", err, f)
	}
	if strings.Contains(f.Message, "sk-live") {
		t.Fatal("value in message")
	}
	value, meta, err := h.backend.Get(ctx, "openai-api-key")
	if err != nil || string(value) != "sk-live-secret-value-123" || meta.Source != storage.SourceDrop || meta.Sendable || meta.Purpose == "" {
		t.Fatalf("backend: %v %q %+v", err, value, meta)
	}
	if p, _ := a.Pending(ctx); len(p) != 0 {
		t.Fatal("pending not cleared")
	}
	// The redactor learned the value.
	if got := a.Redactor.Redact("token=sk-live-secret-value-123"); got != "token=[redacted:openai-api-key]" {
		t.Fatalf("redact: %q", got)
	}
	// Fetching again reports no pending request.
	if _, err := a.Fetch(ctx, FetchInput{RequestID: out.RequestID}); !errors.Is(err, ErrNoPending) {
		t.Fatalf("second fetch: %v", err)
	}
	list, err := a.List(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "openai-api-key" {
		t.Fatalf("list: %v %+v", err, list)
	}
	// Audit has names and ids, never the value.
	raw, _ := os.ReadFile(h.audit.Path())
	if strings.Contains(string(raw), "sk-live") || !strings.Contains(string(raw), "openai-api-key") || !strings.Contains(string(raw), out.RequestID) {
		t.Fatalf("audit content: %s", raw)
	}
	events := h.events(t)
	if events[len(events)-1].Event != "fetch_secret" || events[len(events)-1].Result != StatusStored {
		t.Fatalf("audit events: %+v", events)
	}
}

func TestFetchOutcomes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent

	// Unknown, malformed, and ambiguous ids.
	if _, err := a.Fetch(ctx, FetchInput{RequestID: "nope"}); !errors.Is(err, ErrNoPending) {
		t.Fatalf("malformed id: %v", err)
	}
	if _, err := a.Fetch(ctx, FetchInput{}); !errors.Is(err, ErrNoPending) {
		t.Fatalf("no pending: %v", err)
	}
	r1, _ := a.Request(ctx, RequestInput{Name: "one", Purpose: "p"})
	r2, _ := a.Request(ctx, RequestInput{Name: "two", Purpose: "p"})
	if _, err := a.Fetch(ctx, FetchInput{}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous: %v", err)
	}

	// Revoked by the agent.
	state, err := a.Revoke(ctx, r1.RequestID)
	if err != nil || state != client.StateRevoked {
		t.Fatalf("revoke: %v %s", err, state)
	}
	if _, err := a.Revoke(ctx, r1.RequestID); !errors.Is(err, ErrNoPending) {
		t.Fatalf("revoke twice: %v", err)
	}
	// Revoked on the relay by the human side (upload token), seen by fetch.
	d2, _, _ := link.ParseDrop(r2.Link)
	if err := h.relay.RevokeDrop(ctx, d2.ID, d2.UploadToken); err != nil {
		t.Fatal(err)
	}
	f, err := a.Fetch(ctx, FetchInput{RequestID: r2.RequestID})
	if err != nil || f.Status != StatusRevoked {
		t.Fatalf("revoked: %v %+v", err, f)
	}
	if p, _ := a.Pending(ctx); len(p) != 0 {
		t.Fatalf("pending after revoke: %+v", p)
	}

	// Tampered link: the human used a link with a different name.
	r3, _ := a.Request(ctx, RequestInput{Name: "three", Purpose: "p"})
	h.submit(t, r3.Link, "v3", func(e *crypto.Envelope) { e.Name = "evil" })
	f, err = a.Fetch(ctx, FetchInput{RequestID: r3.RequestID})
	if err != nil || f.Status != StatusRejected || !strings.Contains(f.Message, "name") {
		t.Fatalf("tampered name: %v %+v", err, f)
	}
	if _, _, err := h.backend.Get(ctx, "three"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("rejected value stored")
	}
	// Tampered retention.
	r4, _ := a.Request(ctx, RequestInput{Name: "four", Purpose: "p", Retention: storage.RetentionSession})
	h.submit(t, r4.Link, "v4", func(e *crypto.Envelope) { e.Retention = storage.RetentionUntilRevoked })
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r4.RequestID}); f.Status != StatusRejected {
		t.Fatalf("tampered retention: %+v", f)
	}
	// Wrong fingerprint.
	r5, _ := a.Request(ctx, RequestInput{Name: "five", Purpose: "p"})
	h.submit(t, r5.Link, "v5", func(e *crypto.Envelope) { e.Fingerprint = "0000-0000-0000-0000" })
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r5.RequestID}); f.Status != StatusRejected {
		t.Fatalf("tampered fingerprint: %+v", f)
	}
	// Wrong purpose and wrong storage description: the human was shown text
	// this agent never produced.
	r5b, _ := a.Request(ctx, RequestInput{Name: "five-b", Purpose: "p"})
	h.submit(t, r5b.Link, "v5b", func(e *crypto.Envelope) { e.Purpose = "a purpose the agent never stated" })
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r5b.RequestID}); f.Status != StatusRejected || !strings.Contains(f.Message, "purpose shown") {
		t.Fatalf("tampered purpose: %+v", f)
	}
	r5c, _ := a.Request(ctx, RequestInput{Name: "five-c", Purpose: "p"})
	h.submit(t, r5c.Link, "v5c", func(e *crypto.Envelope) { e.Storage = "somewhere else" })
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r5c.RequestID}); f.Status != StatusRejected || !strings.Contains(f.Message, "storage description shown") {
		t.Fatalf("tampered storage: %+v", f)
	}
	// Wrong type.
	r6, _ := a.Request(ctx, RequestInput{Name: "six", Purpose: "p"})
	h.submit(t, r6.Link, "v6", func(e *crypto.Envelope) {
		e.Type = crypto.TypeReveal
		e.Purpose = ""
		e.Storage = ""
		e.Retention = ""
		e.Fingerprint = ""
	})
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r6.RequestID}); f.Status != StatusRejected {
		t.Fatalf("wrong type: %+v", f)
	}

	// Session retention lands in memory and shadows nothing persistent.
	r7, _ := a.Request(ctx, RequestInput{Name: "seven", Purpose: "p", Retention: storage.RetentionSession, Sendable: true})
	if !strings.Contains(r7.Message, "process memory") {
		t.Fatalf("session storage description: %s", r7.Message)
	}
	h.submit(t, r7.Link, "v7", nil)
	f, err = a.Fetch(ctx, FetchInput{RequestID: r7.RequestID})
	if err != nil || f.Status != StatusStored || f.Storage != "memory" {
		t.Fatalf("session stored: %v %+v", err, f)
	}
	if _, _, err := h.backend.Get(ctx, "seven"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("session secret reached the persistent backend")
	}
	if list, _ := a.List(ctx); len(list) != 1 || list[0].Name != "seven" || !list[0].Sendable {
		t.Fatalf("list: %+v", list)
	}

	// Someone else fetched first (simulated with the fetch token).
	r8, _ := a.Request(ctx, RequestInput{Name: "eight", Purpose: "p"})
	d8, _, _ := link.ParseDrop(r8.Link)
	h.submit(t, r8.Link, "v8", nil)
	rec, _ := a.loadPending(ctx, d8.ID)
	if _, _, err := h.relay.Fetch(ctx, d8.ID, rec.FetchToken); err != nil {
		t.Fatal(err)
	}
	f, err = a.Fetch(ctx, FetchInput{RequestID: r8.RequestID})
	if err != nil || f.Status != StatusGone || !strings.Contains(f.Message, "rotate") {
		t.Fatalf("gone: %v %+v", err, f)
	}

	// Expired on the relay: the agent's clock and the relay's clock differ
	// here, so simulate by revoking with the fetch token and deleting.
	r9, _ := a.Request(ctx, RequestInput{Name: "nine", Purpose: "p", TTL: "1m"})
	d9, _, _ := link.ParseDrop(r9.Link)
	_ = h.relay.RevokeDrop(ctx, d9.ID, d9.UploadToken)
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r9.RequestID}); f.Status != StatusRevoked {
		t.Fatalf("nine: %+v", f)
	}
	// Delete and revoke bookkeeping.
	if err := a.Delete(ctx, "seven"); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(ctx, "seven"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	if err := a.Delete(ctx, "pending.x"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("pending names must not be deletable as secrets")
	}
	if got := a.Redactor.Redact("v7"); got != "v7" {
		t.Fatal("short values are never redacted")
	}
}

func TestSendWithPassword(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent
	if _, err := a.Store.Put(ctx, "generated", []byte("generated-value"), storage.Metadata{Retention: storage.RetentionUntilRevoked, Source: storage.SourceCapture, Sendable: true}); err != nil {
		t.Fatal(err)
	}
	a.Config.RevealPasswordRequired = true
	if _, err := a.Send(ctx, SendInput{Name: "generated"}); !errors.Is(err, ErrNoRevealPassword) {
		t.Fatalf("no password source: %v", err)
	}
	a.PasswordSource = func() ([]byte, error) { return []byte(""), nil }
	if _, err := a.Send(ctx, SendInput{Name: "generated"}); !errors.Is(err, ErrNoRevealPassword) {
		t.Fatalf("empty password: %v", err)
	}
	a.PasswordSource = func() ([]byte, error) { return []byte("correct horse battery staple"), nil }
	out, err := a.Send(ctx, SendInput{Name: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.PasswordProtected || !strings.Contains(out.Message, "reveal password") || !strings.Contains(out.Link, "&s=") {
		t.Fatalf("send output: %+v", out)
	}
	rv, _, err := link.ParseReveal(out.Link)
	if err != nil || !rv.PasswordProtected() || len(rv.Salt) != crypto.SaltSize {
		t.Fatalf("reveal link: %v %+v", err, rv)
	}
	ct, _, err := h.relay.Open(ctx, rv.ID, rv.RevealToken)
	if err != nil {
		t.Fatal(err)
	}
	linkKey, _ := crypto.KeyFromBytes(rv.Key)
	if _, err := crypto.DecryptEnvelope(linkKey, ct, rv.AAD()); err == nil {
		t.Fatal("the link key alone opened a password-protected reveal")
	}
	wrong, _ := crypto.RevealKeyWithPassword(linkKey, []byte("wrong password"), rv.Salt)
	if _, err := crypto.DecryptEnvelope(wrong, ct, rv.AAD()); err == nil {
		t.Fatal("a wrong password opened the reveal")
	}
	right, _ := crypto.RevealKeyWithPassword(linkKey, []byte("correct horse battery staple"), rv.Salt)
	env, err := crypto.DecryptEnvelope(right, ct, rv.AAD())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := env.SecretBytes(); string(got) != "generated-value" {
		t.Fatalf("opened: %+v", env)
	}
	// Off again: plain links, no salt.
	a.Config.RevealPasswordRequired = false
	out, err = a.Send(ctx, SendInput{Name: "generated"})
	if err != nil || out.PasswordProtected || strings.Contains(out.Link, "&s=") || strings.Contains(out.Message, "reveal password") {
		t.Fatalf("plain send: %v %+v", err, out)
	}
}

func TestSend(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent
	if _, err := a.Send(ctx, SendInput{Name: "missing"}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// A received secret is not sendable by default.
	r, _ := a.Request(ctx, RequestInput{Name: "received", Purpose: "p"})
	h.submit(t, r.Link, "received-value-1", nil)
	if f, _ := a.Fetch(ctx, FetchInput{RequestID: r.RequestID}); f.Status != StatusStored {
		t.Fatal("store")
	}
	if _, err := a.Send(ctx, SendInput{Name: "received"}); !errors.Is(err, ErrNotSendable) {
		t.Fatalf("not sendable: %v", err)
	}
	if err := a.CanSend(ctx, "received"); !errors.Is(err, ErrNotSendable) {
		t.Fatalf("can send: %v", err)
	}
	if err := a.CanSend(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("can send missing: %v", err)
	}
	if err := a.CanSend(ctx, "bad name"); !errors.Is(err, storage.ErrInvalidName) {
		t.Fatal("can send name")
	}
	if err := a.CanSend(ctx, "pending."+r.RequestID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("can send pending: %v", err)
	}
	// A captured secret is sendable.
	if _, err := a.Store.Put(ctx, "generated", []byte("generated-value-\x00\x01"), storage.Metadata{Retention: storage.RetentionUntilRevoked, Source: storage.SourceCapture, Sendable: true}); err != nil {
		t.Fatal(err)
	}
	out, err := a.Send(ctx, SendInput{Name: "generated", TTL: "45m"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.Link, h.relay.Origin+"/reveal#") || !out.KeepsCopy || !strings.Contains(out.Message, out.Link) || strings.Contains(out.Message, "generated-value") {
		t.Fatalf("send output: %+v", out)
	}
	// The human opens it.
	rv, origin, err := link.ParseReveal(out.Link)
	if err != nil || origin != h.relay.Origin || rv.Name != "generated" || !rv.KeepsCopy {
		t.Fatalf("reveal link: %v %+v", err, rv)
	}
	ct, _, err := h.relay.Open(ctx, rv.ID, rv.RevealToken)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.KeyFromBytes(rv.Key)
	env, err := crypto.DecryptEnvelope(key, ct, rv.AAD())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := env.SecretBytes()
	if string(got) != "generated-value-\x00\x01" || env.Format != crypto.FormatBase64 || env.Purpose != "" {
		t.Fatalf("opened: %+v", env)
	}
	// A link whose keeps_copy flag was flipped fails to decrypt.
	if _, err := crypto.DecryptEnvelope(key, ct, crypto.RevealAAD("generated", false)); err == nil {
		t.Fatal("altered aad accepted")
	}
	// delete_after removes the agent's copy and says so.
	out2, err := a.Send(ctx, SendInput{Name: "generated", DeleteAfter: true})
	if err != nil || out2.KeepsCopy || !strings.Contains(out2.Message, "deleted my copy") {
		t.Fatalf("delete after: %v %+v", err, out2)
	}
	if _, _, err := a.Store.Get(ctx, "generated"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("copy kept")
	}
	// Bad inputs.
	if _, err := a.Send(ctx, SendInput{Name: "generated", TTL: "x"}); err == nil {
		t.Fatal("bad ttl")
	}
	if _, err := a.Send(ctx, SendInput{Name: "pending.abc"}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("pending name: %v", err)
	}
	raw, _ := os.ReadFile(h.audit.Path())
	if strings.Contains(string(raw), "generated-value") || !strings.Contains(string(raw), "refused_not_sendable") {
		t.Fatalf("audit: %s", raw)
	}
}

func TestRelayFailures(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent
	bad, _ := client.New("http://127.0.0.1:1", "k", "")
	a.Relay = bad
	if _, err := a.Request(ctx, RequestInput{Name: "n", Purpose: "p"}); err == nil {
		t.Fatal("request must fail when the relay is down")
	}
	_, _ = a.Store.Put(ctx, "s", []byte("sendable-value"), storage.Metadata{Retention: storage.RetentionSession, Sendable: true})
	if _, err := a.Send(ctx, SendInput{Name: "s"}); err == nil {
		t.Fatal("send must fail when the relay is down")
	}
	events := h.events(t)
	if len(events) < 2 || events[0].Result != "relay_error" || events[1].Result != "relay_error" {
		t.Fatalf("audit: %+v", events)
	}
	// The agent key was not written to the audit log.
	raw, _ := os.ReadFile(h.audit.Path())
	if strings.Contains(string(raw), "sendable-value") {
		t.Fatal("value in audit")
	}
}

func TestSplitOriginLinks(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	a := h.agent
	a.PageOrigin = "https://drop.example"
	r, err := a.Request(ctx, RequestInput{Name: "n", Purpose: "p"})
	if err != nil {
		t.Fatal(err)
	}
	d, origin, err := link.ParseDrop(r.Link)
	if err != nil || origin != "https://drop.example" || d.Relay != h.relay.Origin {
		t.Fatalf("split origin: %v %q %+v", err, origin, d)
	}
	_, _ = a.Store.Put(ctx, "s", []byte("sendable-value"), storage.Metadata{Retention: storage.RetentionSession, Sendable: true})
	s, err := a.Send(ctx, SendInput{Name: "s"})
	if err != nil {
		t.Fatal(err)
	}
	rv, origin, err := link.ParseReveal(s.Link)
	if err != nil || origin != "https://drop.example" || rv.Relay != h.relay.Origin {
		t.Fatalf("split origin reveal: %v %q %+v", err, origin, rv)
	}
}
